"""Actual standalone workers/deadlines; no substituted decoder or result."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from paw.core.runtime import atomic_json, RunLimits, supervise
from paw.standalone import analyze_supervised, run_deobfuscation, StandaloneFailure, restrict_control_access
from paw.deobfuscate.input import validate_input_source, MAX_INPUT_BYTES

REPO = Path(__file__).resolve().parents[1]


class StandaloneAdmissionContracts(unittest.TestCase):
    def test_literal_byte_and_encoding_rejection_precedes_asyncio_bootstrap(self):
        for kind in ('text', 'url'):
            for value, error in (('é'*(MAX_INPUT_BYTES//2+1), '1 MiB'),
                                 ('€'*(MAX_INPUT_BYTES//3+1), '1 MiB'),
                                 ('😀'*(MAX_INPUT_BYTES//4+1), '1 MiB'),
                                 ('\ud800', 'valid UTF-8')):
                with self.subTest(kind=kind, error=error), \
                     patch('paw.standalone.run_deobfuscation', new=Mock(side_effect=AssertionError('Worker bootstrap attempted'))) as worker, \
                     patch('paw.standalone.asyncio.run', side_effect=AssertionError('Asyncio bootstrap attempted')) as loop:
                    with self.assertRaisesRegex(ValueError, error):
                        analyze_supervised(**{kind:value})
                    worker.assert_not_called()
                    loop.assert_not_called()

    def test_multibyte_literal_boundary_is_admitted_losslessly(self):
        for kind in ('text', 'url'):
            for value in ('é'*(MAX_INPUT_BYTES//2), '€'*(MAX_INPUT_BYTES//3)+'a',
                          '😀'*(MAX_INPUT_BYTES//4)):
                with self.subTest(kind=kind):
                    self.assertEqual(len(value.encode('utf-8')), MAX_INPUT_BYTES)
                    self.assertEqual(validate_input_source(**{kind:value}), (kind,value))


class StandaloneRuntimeContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous_cwd = Path.cwd()
        self.control_root = Path(tempfile.gettempdir())
        self.before_controls = set(self.control_root.glob('paw-standalone-*'))
        os.chdir(self.root)

    async def asyncTearDown(self):
        os.chdir(self.previous_cwd)
        self.assertEqual(set(self.control_root.glob('paw-standalone-*')),self.before_controls)
        self.temporary.cleanup()

    async def test_real_worker_preserves_input_and_reports_confirmed_shutdown(self):
        raw = '\ufeffCaffè\r\nрayраl\r\n'.encode('utf-8')
        path = self.root/'text.txt'; path.write_bytes(raw)
        result = await run_deobfuscation(file=path,deadline=15,memory_mib=256)
        self.assertEqual(result['input_observation']['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['deobfuscated_artifacts']['text']['original_text'].encode('utf-8'),raw)
        self.assertEqual(path.read_bytes(),raw)
        execution = result['standalone_execution']
        self.assertEqual(execution['status'],'completed')
        self.assertTrue(execution['tree_stopped'])
        self.assertEqual(execution['limits']['wall_seconds'],15)
        self.assertEqual(execution['limits']['memory_bytes'],256*1024**2)
        self.assertEqual(execution['containment'],'windows_job' if os.name=='nt' else 'posix_process_group')
        self.assertIsNone(result['suspicion_score'])
        self.assertEqual({path.name for path in self.root.iterdir()},{'text.txt'})

    async def test_real_worker_ignores_cwd_package_and_dependency_shadows(self):
        # Benign import-boundary fixtures only write a marker and fail; they
        # never perform network/process activity or supply analysis results.
        for shadow in ('paw', 'psutil'):
            directory = self.root/shadow; directory.mkdir()
            marker = directory/'shadow-imported.txt'
            if shadow == 'paw':
                package = directory/'paw'; package.mkdir()
                module = package/'__init__.py'
            else:
                module = directory/'psutil.py'
            module.write_text("from pathlib import Path\nPath("+repr(str(marker))+
                ").write_text('Unexpected cwd import')\nraise RuntimeError('Cwd shadow imported')\n", encoding='utf-8')
            os.chdir(directory)
            try:
                try:
                    result = await run_deobfuscation(text='Original é\r\n',deadline=15)
                except StandaloneFailure:
                    self.assertFalse(marker.exists(), 'Worker imported code from analysis cwd')
                    raise
                self.assertFalse(marker.exists())
                self.assertEqual(result['deobfuscated_artifacts']['text']['original_text'], 'Original é\r\n')
                self.assertEqual(result['input_observation']['sha256'],hashlib.sha256('Original é\r\n'.encode()).hexdigest())
                self.assertTrue(result['standalone_execution']['tree_stopped'])
            finally:
                os.chdir(self.root)

    async def test_invalid_literals_precede_transport_creation_in_async_adapter(self):
        for options in ({'text':'é'*(MAX_INPUT_BYTES//2+1)},
                        {'url':'😀'*(MAX_INPUT_BYTES//4+1)}, {'text':'\ud800'}):
            with patch('paw.standalone.tempfile.mkdtemp',
                       side_effect=AssertionError('Transport creation attempted')) as transport:
                with self.assertRaises(ValueError):
                    await run_deobfuscation(**options)
                transport.assert_not_called()

    async def test_transport_permissions_protect_directory_and_inherited_files(self):
        directory = self.root/'protected'; directory.mkdir()
        restrict_control_access(directory)
        child = directory/'request.json'; child.write_text('Local transport fixture',encoding='utf-8')
        if os.name != 'nt':
            self.assertEqual(directory.stat().st_mode & 0o777,0o700)
            return
        # Independent native ACL inspection, including inherited file rights;
        # no credentials/network or alternate-user impersonation is required.
        command = '''$ErrorActionPreference='Stop'; $pawItems = @($env:PAW_ACL_DIRECTORY, $env:PAW_ACL_FILE); foreach ($pawItem in $pawItems) {
            $pawAcl = Get-Acl -LiteralPath $pawItem
            [pscustomobject]@{ Protected=$pawAcl.AreAccessRulesProtected; Sids=@(
              $pawAcl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            ) } | ConvertTo-Json -Compress
        }'''
        # A parent PowerShell 7 session may export its incompatible module path
        # to Windows PowerShell; let the inspector discover its own built-ins.
        environment = {key:value for key,value in os.environ.items() if key.upper()!='PSMODULEPATH'}
        environment.update(PAW_ACL_DIRECTORY=str(directory),PAW_ACL_FILE=str(child))
        inspected = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
            command],env=environment,
            capture_output=True,text=True,timeout=15)
        self.assertEqual(inspected.returncode,0,inspected.stderr)
        records = [json.loads(line) for line in inspected.stdout.splitlines() if line.strip()]
        self.assertEqual(len(records),2,inspected.stdout)
        self.assertTrue(records[0]['Protected'])
        for record in records:
            self.assertEqual(set(record['Sids']),{'S-1-3-4','S-1-5-18'})

    async def test_actual_execution_deadline_stops_worker_without_results(self):
        with self.assertRaises(StandaloneFailure) as failure:
            await run_deobfuscation(text='р'*524288,deadline=.001)
        outcome = failure.exception.outcome
        self.assertEqual(outcome['status'],'timed_out')
        self.assertTrue(outcome['tree_stopped'])
        self.assertLess(outcome['elapsed_seconds'],10)
        self.assertEqual(list(self.root.iterdir()),[])

    async def test_invalid_source_and_limits_create_no_worker_controls(self):
        for options in ({}, {'text':'','url':'x'}, {'file':'//invalid-host/share/text.txt'},
                        {'text':'x','deadline':0}, {'text':'x','deadline':float('nan')},
                        {'text':'x','memory_mib':0}, {'text':'x','memory_mib':63},
                        {'text':'x','memory_mib':4097}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                await run_deobfuscation(**options)
        self.assertEqual(set(self.control_root.glob('paw-standalone-*')),self.before_controls)

    async def test_worker_input_rejection_preserves_source_and_cleans_controls(self):
        path = self.root/'bad.txt'; path.write_bytes(b'pa\xffypal')
        with self.assertRaisesRegex(ValueError,'not valid UTF-8'):
            await run_deobfuscation(file=path)
        self.assertEqual(path.read_bytes(),b'pa\xffypal')
        self.assertEqual({path.name for path in self.root.iterdir()},{'bad.txt'})

    async def test_instrumented_actual_worker_opens_source_under_guard_after_gate(self):
        path = self.root/'source.txt'; path.write_bytes(b'Original\r\n')
        control = self.root/'audit'; control.mkdir()
        request = control/'request.json'; atomic_json(request,{'file':str(path)})
        # Only observe real worker events; run its unchanged module after the
        # shared start gate. The hook never supplies analysis output.
        script = '''import sys,runpy
from paw.core.runtime import wait_for_gate
wait_for_gate()
from paw.core.network_policy import network_allowed
opens=[]; attempts=[]
source=sys.argv[2]
def observe(event,args):
    if event=='open' and args[0]==source: opens.append(not network_allowed())
    if (event.startswith('socket.') and event!='socket.gethostname') or event in {'subprocess.Popen','os.system','os.posix_spawn','os.spawn','os.fork','os.exec','os.startfile','os.startfile/2','_winapi.CreateProcess'}: attempts.append(event)
sys.addaudithook(observe)
sys.argv=["paw.standalone_worker",sys.argv[1]]
runpy.run_module('paw.standalone_worker',run_name='__main__')
assert opens==[True], opens
assert not attempts, attempts
'''
        outcome = await supervise([sys.executable,'-X','utf8','-c',script,str(request),str(path)],
            cwd=self.root,control=control,limits=RunLimits(wall_seconds=15),
            env={'PYTHONPATH':str(REPO)})
        self.assertEqual(outcome['status'],'exited')
        self.assertEqual(outcome['returncode'],0,(control/'worker.log').read_text())
        self.assertTrue(outcome['tree_stopped'])
        response = json.loads((control/'result.json').read_text())
        self.assertEqual(response['status'],'completed')
        self.assertEqual(response['result']['deobfuscated_artifacts']['text']['original_text'],'Original\r\n')


if __name__=='__main__': unittest.main()
