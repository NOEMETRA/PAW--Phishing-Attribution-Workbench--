"""Regression checks for defects found by actual offline engine workloads."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import time
import unittest
import zipfile

from paw.core.batch import select_inputs
from paw.core.evidence import seal_case
from paw.core.exporter import export_case
from paw.core.runtime import atomic_json
from paw.core.scoring import score_case, finalize_score
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.file_monitor import FileMonitor
from paw.core.abuse import generate_abuse_package, generate_arf_package, generate_xarf_package
from paw.core.stix import make_stix
from email.parser import BytesParser
from email import policy


class EngineContracts(unittest.TestCase):
    def test_input_selection_includes_uppercase_and_msg_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('a.eml','b.EML','c.EmL','d.MSG','notes.txt'):
                (root/name).write_bytes(b'fixture')
            self.assertEqual([path.name for path in select_inputs(root)], ['a.eml','b.EML','c.EmL','d.MSG'])

    def test_empty_directory_and_unsupported_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): select_inputs(directory)
            other=Path(directory)/'file.txt'
            other.write_bytes(b'fixture')
            with self.assertRaises(ValueError): select_inputs(other)

    def test_nonfinite_and_out_of_range_weights_cannot_create_verdicts(self):
        for value in (float('nan'),float('inf'),-float('inf'),-.01,1.01,True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                score_case({}, {}, {'domain':'example.org'},deobfuscation_weight=value)
        for value in (float('nan'),float('inf')):
            with self.assertRaises(ValueError): finalize_score({'score':value})
            with self.assertRaises(ValueError): finalize_score({'score':0},additional=value)

    def test_nonfinite_json_preserves_previous_control_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'progress.json'
            atomic_json(path,{'value':1})
            with self.assertRaises(ValueError): atomic_json(path,{'value':float('nan')})
            self.assertEqual(json.loads(path.read_text()),{'value':1})
            self.assertEqual(list(Path(directory).glob('*.tmp')),[])

    def test_actual_cli_rejects_nan_before_creating_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'input.eml'
            source.write_bytes(b'From: sender@example.org\r\n\r\nOriginal')
            environment=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]))
            process=subprocess.run([sys.executable,'-m','paw','trace','--src',str(source),
                '--no-egress','--deob-weight=nan'],cwd=root,env=environment,capture_output=True,timeout=10)
            self.assertEqual(process.returncode,2)
            self.assertFalse((root/'.paw-jobs').exists())
            self.assertFalse((root/'jobs').exists())

    @unittest.skipUnless(os.name=='nt','Windows handle sharing regression')
    def test_real_windows_reader_does_not_break_progress_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'progress.json'
            atomic_json(path,{'value':1})
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,
                                        wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
            kernel.CreateFileW.restype=wintypes.HANDLE
            kernel.CloseHandle.argtypes=[wintypes.HANDLE]
            handle=kernel.CreateFileW(str(path),0x80000000,3,None,3,0,None) # no FILE_SHARE_DELETE
            if handle==ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
            errors=[]
            def writer():
                try: atomic_json(path,{'value':2})
                except Exception as exc: errors.append(exc)
            thread=threading.Thread(target=writer)
            try:
                thread.start()
                time.sleep(.08)
                self.assertTrue(thread.is_alive())
            finally:
                kernel.CloseHandle(handle)
                thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])
            self.assertEqual(json.loads(path.read_text()),{'value':2})
            self.assertEqual(list(Path(directory).glob('*.tmp')),[])

    def test_export_rejects_nonexistent_empty_and_unsupported_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaises(FileNotFoundError): export_case(root/'missing','zip')
            with self.assertRaises(ValueError): export_case(root,'zip')
            with self.assertRaises(ValueError): export_case(root,'stix')
            self.assertFalse((root/'missing.zip').exists())

    def test_export_preserves_real_original_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            case=Path(directory)/'case-real'
            case.mkdir()
            raw=b'From: sender@example.org\r\n\r\nOriginal bytes'
            (case/'input.eml').write_bytes(raw)
            seal_case(case)
            with zipfile.ZipFile(export_case(case,'zip')) as archive:
                self.assertEqual(archive.read('case-real/input.eml'),raw)
                self.assertIn('case-real/evidence/merkle_index.json',archive.namelist())

    def test_monitor_matches_case_verifier_and_missing_seal_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            database=CampaignDatabase(str(root/'monitor.db'))
            cases=root/'cases'
            cases.mkdir()
            monitor=FileMonitor(cases,database)
            for name in ('case-sealed','case-unsealed'):
                case=cases/name
                case.mkdir()
                (case/'input.eml').write_bytes(b'Original bytes')
            seal_case(cases/'case-sealed')
            report=monitor.generate_integrity_report()
            self.assertEqual(report['integrity_summary'],{'ok':1,'compromised':0,'unknown':1})
            (cases/'case-sealed'/'input.eml').write_bytes(b'Tampered bytes')
            self.assertFalse(monitor.verify_merkle_integrity('case-sealed')[0])
            self.assertEqual(monitor.check_file_changes('case-unsealed')['integrity_status'],'unknown')

    def test_monitor_baselines_do_not_report_other_cases_as_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            monitor=FileMonitor(root,CampaignDatabase(str(root/'monitor.db')))
            for name in ('case-a','case-b'):
                case=root/name
                case.mkdir()
                (case/'input.eml').write_bytes(b'Original bytes')
                seal_case(case)
                self.assertEqual(monitor.check_file_changes(name)['deleted_files'],[])
            self.assertEqual(monitor.check_file_changes('case-a')['deleted_files'],[])

    def test_abuse_drafts_do_not_invent_dkim_or_compromise_and_keep_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'report').mkdir()
            raw=b'From: sender@example.org\r\n\r\nOriginal bytes'
            (root/'input.eml').write_bytes(raw)
            values={'headers.json':{'from':'sender@example.org','auth_results':{'dkim':[{'d':None,'result':'pass'}]}},
                    'auth.json':{'dkim':{'verification':{'status':'not_evaluated','result':None}}},
                    'origin.json':{'ip':'','verified':False},'domains.json':{},'manifest.json':{'inputs':[]}}
            for name,value in values.items(): (root/name).write_text(json.dumps(value),encoding='utf-8')
            for decision in ('Inconclusive','Likely malicious infrastructure'):
                (root/'report'/'score.json').write_text(json.dumps({'score':.2,'decision':decision}),encoding='utf-8')
                for language in ('it','en'):
                    text=Path(generate_abuse_package(root,language)).read_text(encoding='utf-8')
                    self.assertNotIn('DKIM: pass',text)
                    self.assertNotIn('likely compromised mailbox',text)
                    self.assertIn('not_evaluated',text)
            original_draft=BytesParser(policy=policy.default).parsebytes(Path(generate_arf_package(root)).read_bytes())
            self.assertIsNone(original_draft['From'])
            self.assertIsNone(original_draft['To'])
            self.assertEqual([part.get_payload(decode=True) for part in original_draft.iter_attachments()
                              if part.get_filename()=='input.eml'],[raw])
            structured=json.loads(Path(generate_xarf_package(root)).read_text())
            self.assertIsNone(structured['reporter'])
            self.assertEqual(structured['format_compliance']['xarf'],'not_validated')

    def test_stix_gap_does_not_emit_empty_or_misclassified_ip_objects(self):
        for ip in ('','2001:db8::1','192.0.2.1'):
            result=make_stix('case',ip,'','')
            self.assertEqual(result['status'],'unavailable')
            self.assertFalse(result['bundle_generated'])
            self.assertNotIn('objects',result)


if __name__=='__main__': unittest.main()
