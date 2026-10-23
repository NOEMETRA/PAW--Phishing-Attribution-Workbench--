"""Analysis-source and resource admission; fixtures are not accuracy labels."""
from contextlib import ExitStack
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from paw.__main__ import trace_sources
from paw.core.batch import select_inputs
from paw.core.dkim_keys import load_key_file
from paw.core.mime_analysis import MimeLimits, MimeLimitExceeded
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import load_mail, parse_message_bytes
from paw.core.runtime import RunLimits


UNC_PATHS=(r'\\fixture.invalid\share\input.eml','//fixture.invalid/share/input.eml',
    r'\/fixture.invalid\share\input.eml',r'/\fixture.invalid/share/input.eml',
    r'\\?\UNC\fixture.invalid\share\input.eml','//?/UNC/fixture.invalid/share/input.eml')


class InputAdmissionTests(unittest.TestCase):
    def guarded_refusal(self, paths):
        operations=(select_inputs,load_mail,load_key_file,
            lambda path:trace_sources(path,'en',True,True,False,True))
        before=len(violations())
        with offline_policy(),ExitStack() as stack:
            for target in ('pathlib.Path.stat','pathlib.Path.resolve','pathlib.Path.mkdir',
                           'builtins.open','os.open','os.scandir'):
                stack.enter_context(patch(target,side_effect=AssertionError('Filesystem reached before admission')))
            for operation in operations:
                for path in paths:
                    with self.subTest(operation=operation,path=path):
                        with self.assertRaises(ValueError): operation(path)
        self.assertEqual(len(violations()),before)

    def test_unc_spellings_refuse_before_filesystem_or_worker_access(self):
        self.guarded_refusal(UNC_PATHS)

    def test_blank_and_nul_sources_refuse_before_filesystem_or_worker_access(self):
        self.guarded_refusal(('', '   ', 'bad\x00.eml'))

    def test_regular_original_bytes_and_uppercase_extensions_remain_supported(self):
        raw=b'From: sender@example.invalid\r\nSubject: supplied\r\n\r\nOriginal \xff\x00 bytes\r\n'
        with tempfile.TemporaryDirectory() as temporary,offline_policy():
            path=Path(temporary)/'literal # %.EML';path.write_bytes(raw)
            self.assertEqual(select_inputs(path),[path])
            headers,message,original=load_mail(path)
            self.assertEqual(original,raw);self.assertEqual(message._paw_source_bytes,raw)
            self.assertEqual(str(headers['subject']),'supplied')
            self.assertEqual(path.read_bytes(),raw)

    def test_input_byte_budget_checks_original_bytes_without_publishing_a_case(self):
        raw=b'From: sender@example.invalid\r\n\r\nbody'
        with tempfile.TemporaryDirectory() as temporary,offline_policy():
            path=Path(temporary)/'input.eml';path.write_bytes(raw)
            self.assertEqual(load_mail(path,replace(MimeLimits(),max_input_bytes=len(raw)))[2],raw)
            with self.assertRaises(MimeLimitExceeded):
                load_mail(path,replace(MimeLimits(),max_input_bytes=len(raw)-1))
            self.assertEqual(list(Path(temporary).iterdir()),[path])

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO source-kind contract')
    def test_direct_mail_reader_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'input.eml';os.mkfifo(path)
            code='''import sys
from paw.core.network_policy import offline_policy
from paw.core.parser_mail import load_mail
with offline_policy():
    try: load_mail(sys.argv[1])
    except ValueError: pass
    else: raise AssertionError('FIFO admitted')
'''
            env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]),PYTHONDONTWRITEBYTECODE='1')
            result=subprocess.run([sys.executable,'-B','-c',code,str(path)],env=env,capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_integer_runtime_budgets_reject_coercions_fractions_and_os_overflow(self):
        for field in ('memory_bytes','artifact_bytes','artifact_files','log_bytes'):
            for value in (True,False,0,-1,1.5,'2',None,{},2**63):
                with self.subTest(field=field,value=value):
                    with self.assertRaises(ValueError): RunLimits(**{field:value})
            self.assertEqual(getattr(RunLimits(**{field:1}),field),1)

    def test_runtime_durations_require_positive_finite_native_numbers(self):
        for field in ('wall_seconds','stage_seconds'):
            for value in (True,False,0,-1,float('nan'),float('inf'),'2',None,{},2**10000):
                with self.subTest(field=field,value=type(value).__name__):
                    with self.assertRaises(ValueError): RunLimits(**{field:value})
            self.assertEqual(getattr(RunLimits(**{field:.01}),field),.01)
            self.assertEqual(getattr(RunLimits(**{field:1}),field),1)

    def test_nonempty_malformed_wire_remains_observable_with_original_and_defects(self):
        for raw in (b'not a transport header\r\nraw body',
                    b'From: sender@example.invalid\r\nbroken separator\r\nbody',
                    b'Content-Type: multipart/mixed; boundary="absent"\r\n\r\nraw body'):
            with self.subTest(raw=raw):
                message=parse_message_bytes(raw)
                self.assertTrue(message.defects)
                self.assertEqual(message._paw_source_bytes,raw)


if __name__=='__main__':unittest.main()
