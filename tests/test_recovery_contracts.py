"""Real launch attempts and crash recovery; no email targets or mocked workers."""
import asyncio
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

import psutil
from fastapi import HTTPException
from paw.core.runtime import atomic_json, read_progress, preserve_interrupted
from paw.core.process_recovery import process_identity, recover_worker, group_writers
from paw.core.verify import verify_case
from paw.web import api

REPO = Path(__file__).resolve().parents[1]


class LaunchContracts(unittest.TestCase):
    def attempt(self, operation):
        # exec/fork failures are isolated from the unittest process itself.
        source = '''import os, sys, json
from paw.core.network_policy import offline_policy, EgressDenied, violations
with offline_policy():
    try:
        OPERATION
    except EgressDenied:
        print(json.dumps({'blocked':True,'events':violations()}))
    else:
        print(json.dumps({'blocked':False}))
'''.replace('OPERATION', operation)
        result = subprocess.run([sys.executable,'-c',source],cwd=REPO,
            capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value['blocked'], operation)
        self.assertTrue(value['events'])

    def test_spawnv_and_spawnve_cannot_escape_hook(self):
        self.attempt("os.spawnv(os.P_WAIT,sys.executable,[sys.executable,'-c','pass'])")
        self.attempt("os.spawnve(os.P_WAIT,sys.executable,[sys.executable,'-c','pass'],dict(os.environ))")

    def test_exec_cannot_replace_the_guarded_interpreter(self):
        self.attempt("os.execv(sys.executable,[sys.executable,'-c','pass'])")
        self.attempt("os.execve(sys.executable,[sys.executable,'-c','pass'],dict(os.environ))")

    @unittest.skipUnless(hasattr(os,'startfile'),'Windows shell launch only')
    def test_windows_shell_launch_is_blocked_before_file_resolution(self):
        self.attempt("os.startfile('paw-review-nonexistent.noextension')")

    @unittest.skipUnless(os.name=='nt','Windows native process API only')
    def test_windows_createprocess_cannot_bypass_subprocess_wrapper(self):
        self.attempt("import _winapi, subprocess; _winapi.CreateProcess(sys.executable,'\\\"'+sys.executable+'\\\" -c pass',None,None,False,0x08000000,None,None,subprocess.STARTUPINFO())")

    @unittest.skipUnless(hasattr(os,'fork'),'POSIX fork only')
    def test_fork_cannot_create_a_child(self):
        self.attempt("pid=os.fork(); os._exit(0) if pid==0 else os.waitpid(pid,0)")

    @unittest.skipUnless(hasattr(os,'forkpty'),'POSIX forkpty only')
    def test_forkpty_cannot_create_a_child(self):
        self.attempt("pid,fd=os.forkpty(); os._exit(0) if pid==0 else os.waitpid(pid,0)")

    @unittest.skipUnless(hasattr(os,'posix_spawn'),'POSIX spawn only')
    def test_posix_spawn_cannot_create_a_child(self):
        self.attempt("pid=os.posix_spawn(sys.executable,[sys.executable,'-c','pass'],dict(os.environ)); os.waitpid(pid,0)")


class RecoveryContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.previous = (api.DATA_DIR,api.CASES_DIR,api.JOBS_DIR,api.EXPORT_DIR,
                         api.analysis_queue,api._recovery_locks)
        api.DATA_DIR,api.CASES_DIR = self.root,self.root/'cases'
        api.JOBS_DIR,api.EXPORT_DIR = self.root/'jobs',self.root/'exports'
        api.JOBS_DIR.mkdir(); api.EXPORT_DIR.mkdir()
        api.analysis_queue,api._recovery_locks = {},{}
        self.identifier = 'analysis_crash'
        self.control = api.JOBS_DIR/self.identifier
        self.case = api.CASES_DIR/'case-crash'
        self.case.mkdir(parents=True)
        self.control.mkdir()
        atomic_json(self.case/'manifest.json',{'analysis_job':self.identifier})
        (self.case/'input.eml').write_bytes(b'Original test bytes')
        atomic_json(api.JOBS_DIR/(self.identifier+'.json'),{'status':'running'})
        atomic_json(self.control/'progress.json',{'case_ids':[self.case.name]})

    async def asyncTearDown(self):
        (api.DATA_DIR,api.CASES_DIR,api.JOBS_DIR,api.EXPORT_DIR,
         api.analysis_queue,api._recovery_locks) = self.previous
        self.temp.cleanup()

    async def test_unknown_writer_blocks_detail_verify_export_and_sealing(self):
        result = await api.get_analysis_status(self.identifier)
        self.assertEqual(result['status'],'recovery_blocked')
        self.assertFalse(result['supervisor']['tree_stopped'])
        for operation in (api.get_case_detail,api.verify_evidence,api.export_case):
            with self.assertRaises(HTTPException) as caught:
                await operation(self.case.name)
            self.assertEqual(caught.exception.status_code,409)
        self.assertEqual(preserve_interrupted(self.root,self.control,'interrupted','unknown'),[])
        self.assertFalse((self.case/'execution.json').exists())
        self.assertEqual(list(api.EXPORT_DIR.iterdir()),[])
        # A corrupt manifest also cannot hide the progress record's ownership.
        (self.case/'manifest.json').write_text('{')
        with self.assertRaises(HTTPException): await api.get_case_detail(self.case.name)
        listing = await api.list_cases()
        self.assertEqual(listing['cases'][0]['status'],'recovery_blocked')
        self.assertNotIn('subject',listing['cases'][0])

    async def test_queued_restart_does_not_claim_an_active_worker(self):
        atomic_json(api.JOBS_DIR/(self.identifier+'.json'),{'status':'queued'})
        job = await api.get_analysis_status(self.identifier)
        self.assertEqual(job['status'],'interrupted')
        self.assertTrue(read_progress(self.control/'supervisor.json')['tree_stopped'])

    @unittest.skipIf(os.name=='nt','Real POSIX process groups run in Linux CI')
    async def test_killed_supervisor_orphans_are_stopped_before_api_publishes(self):
        heartbeat = "import time; from pathlib import Path\np=Path('cases/case-crash/child-heartbeat')\nwhile True: p.write_text(str(time.time())); time.sleep(.02)"
        worker = ('from paw.core.runtime import wait_for_gate,mark_stage\nwait_for_gate()\n'
                  'import subprocess,sys,time\nfrom pathlib import Path\n'
                  'subprocess.Popen([sys.executable,"-c",'+repr(heartbeat)+'])\n'
                  'mark_stage("writes","case-crash")\n'
                  'p=Path("cases/case-crash/parent-heartbeat")\n'
                  'while True: p.write_text(str(time.time())); time.sleep(.02)')
        source = ('import asyncio,sys\nfrom pathlib import Path\n'
                  'from paw.core.runtime import supervise\n'
                  'asyncio.run(supervise([sys.executable,"-c",'+repr(worker)+'],cwd=Path.cwd(),'
                  'control=Path("jobs/analysis_crash")))')
        parent = subprocess.Popen([sys.executable,'-c',source],cwd=self.root,
            env=dict(os.environ,PYTHONPATH=str(REPO)),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        pid = None
        try:
            for _ in range(300):
                record = read_progress(self.control/'process.json')
                if record and (self.case/'child-heartbeat').exists():
                    pid = record['pid']; break
                if parent.poll() is not None: self.fail('Supervisor unexpectedly exited')
                await asyncio.sleep(.02)
            self.assertIsNotNone(pid)
            # An ungraceful API/supervisor death bypasses its finally cleanup.
            parent.kill(); await asyncio.to_thread(parent.wait,timeout=5)
            self.assertTrue(group_writers(pid))
            before = (self.case/'child-heartbeat').read_bytes()
            await asyncio.sleep(.08)
            self.assertNotEqual((self.case/'child-heartbeat').read_bytes(),before)
            # The API's startup hook must recover before yielding to requests.
            async with api.lifespan(api.app):
                job = await api.get_analysis_status(self.identifier)
            self.assertEqual(job['status'],'interrupted')
            self.assertTrue(job['supervisor']['tree_stopped'])
            self.assertEqual(group_writers(pid),[])
            content = {p.name:p.read_bytes() for p in self.case.glob('*heartbeat')}
            await asyncio.sleep(.1)
            self.assertEqual({p.name:p.read_bytes() for p in self.case.glob('*heartbeat')},content)
            self.assertTrue(verify_case(self.case))
            detail = await api.get_case_detail(self.case.name)
            self.assertEqual(detail['status'],'interrupted')
            archive = await api.export_case(self.case.name)
            self.assertTrue(Path(archive.path).is_file())
        finally:
            if parent.poll() is None: parent.kill()
            await asyncio.to_thread(parent.wait,timeout=5)
            if pid is not None:
                try: os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError: pass

    @unittest.skipIf(os.name=='nt','POSIX identity and process group only')
    async def test_mismatching_start_time_does_not_kill_unrelated_group(self):
        process = subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True)
        try:
            identity = process_identity(process.pid)
            identity['created_at'] -= 1
            atomic_json(self.control/'process.json',identity)
            result = await recover_worker(self.control)
            self.assertFalse(result['tree_stopped'])
            self.assertIsNone(process.poll())
            self.assertEqual(preserve_interrupted(self.root,self.control,'interrupted','mismatch'),[])
        finally:
            os.killpg(process.pid,signal.SIGKILL)
            await asyncio.to_thread(process.wait,timeout=5)


if __name__=='__main__': unittest.main()
