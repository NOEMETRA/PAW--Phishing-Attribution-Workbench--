"""Real source CLI ownership, seal guards and process interruption on owned input."""
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import time
import unittest

import psutil

from paw.core.job_registry import case_owner, job_state, require_stopped_case
from paw.core.verify import verify_case


class SourceJobBridge(unittest.TestCase):
    def run_cli(self, folder):
        source = folder/'owned.HTML'; raw = b'\x00\xffinert bytes\r\n'
        source.write_bytes(raw); source.chmod(0o400)
        workspace = folder/'workspace'
        result = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', 'inspect-source', str(source), '--workdir', str(workspace)],
                                capture_output=True, text=True, timeout=40, cwd=folder, env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])))
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        value = json.loads(result.stdout); case = workspace/'cases'/value['worker']['case_id']
        self.assertEqual((case/'source.bin').read_bytes(), raw)
        self.assertEqual(source.read_bytes(), raw)
        self.assertTrue(value['supervisor']['tree_stopped']); self.assertTrue(verify_case(case))
        return workspace, case, value

    def test_completed_source_cli_is_registered_for_existing_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, case, result = self.run_cli(Path(temporary))
            identifier = case_owner(case, workspace, workspace/'jobs')
            self.assertIsNotNone(identifier, 'Source case lacks modern analysis ownership')
            self.assertRegex(identifier, r'^analysis_[0-9a-f]{32}$')
            job = job_state(workspace, workspace/'jobs', identifier)
            self.assertEqual(job['origin'], 'cli'); self.assertEqual(job['status'], 'completed')
            self.assertEqual(job['case_ids'], [case.name]); self.assertEqual(job['kind'], 'source_byte_observation')
            self.assertEqual(job['supervisor']['tree_stopped'], True)
            require_stopped_case(case)

    def test_valid_seal_does_not_override_unconfirmed_worker_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, case, result = self.run_cli(Path(temporary))
            identifier = case_owner(case, workspace, workspace/'jobs')
            self.assertIsNotNone(identifier, 'Source case lacks modern analysis ownership')
            state_path = workspace/'jobs'/(identifier+'.json')
            job = json.loads(state_path.read_bytes()); job['status'] = 'running'
            state_path.write_text(json.dumps(job))
            supervisor = Path(result['control'])/'supervisor.json'
            outcome = json.loads(supervisor.read_bytes()); outcome['tree_stopped'] = False
            supervisor.write_text(json.dumps(outcome))
            self.assertTrue(verify_case(case))
            with self.assertRaisesRegex(RuntimeError, 'shutdown not confirmed'): require_stopped_case(case)

    @unittest.skipUnless(os.name == 'posix', 'POSIX owned process suspension')
    def test_actual_cli_cancel_guards_sealed_case_until_worker_tree_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary); source = folder/'owned-cancel.bin'
            source.write_bytes(os.urandom(8*1024**2)); source.chmod(0o400)
            original = source.read_bytes(); workspace = folder/'workspace'
            client = subprocess.Popen([sys.executable, '-P', '-B', '-m', 'paw', 'inspect-source', str(source), '--workdir', str(workspace)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, cwd=folder, env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])))
            worker_pid = worker_start = None
            try:
                end = time.monotonic()+12; control = None
                while time.monotonic() < end:
                    self.assertIsNone(client.poll(), 'worker finished before owned interruption fixture')
                    directories = list((workspace/'jobs').glob('analysis_*'))
                    directories = [path for path in directories if path.is_dir()]
                    if directories:
                        candidate = directories[0]
                        try: progress = json.loads((candidate/'progress.json').read_bytes())
                        except (OSError, ValueError): progress = {}
                        if progress.get('stage') == 'source_zip_export':
                            identity = json.loads((candidate/'process.json').read_bytes())
                            worker_pid = identity['pid']; process = psutil.Process(worker_pid)
                            self.assertEqual(process.ppid(), client.pid); self.assertEqual(os.getpgid(worker_pid), worker_pid)
                            worker_start = process.create_time(); os.kill(worker_pid, signal.SIGSTOP)
                            control = candidate; break
                    time.sleep(.002)
                self.assertIsNotNone(control, 'owned export stage was not reached')
                case = workspace/'cases'/progress['case_ids'][0]
                self.assertTrue(verify_case(case))
                with self.assertRaisesRegex(RuntimeError, 'shutdown not confirmed'): require_stopped_case(case)
                client.send_signal(signal.SIGINT); stdout, stderr = client.communicate(timeout=10)
                self.assertEqual(client.returncode, 130, stdout+stderr)
                result = json.loads(stdout); self.assertTrue(result['supervisor']['tree_stopped'])
                self.assertEqual(result['worker']['status'], 'cancelled')
                job = job_state(workspace, workspace/'jobs', result['analysis_id'])
                self.assertEqual(job['status'], 'cancelled')
                self.assertTrue(job['supervisor']['tree_stopped'])
                self.assertEqual(job['partial_cases'], [{'case_id': case.name, 'status': 'completed', 'integrity': 'verified'}])
                self.assertEqual(source.read_bytes(), original); self.assertTrue(verify_case(case))
                self.assertFalse(psutil.pid_exists(worker_pid)); require_stopped_case(case)
            finally:
                if client.poll() is None:
                    client.send_signal(signal.SIGINT)
                    try: client.communicate(timeout=8)
                    except subprocess.TimeoutExpired: client.kill(); client.communicate(timeout=5)
                if worker_pid and worker_start:
                    try:
                        process = psutil.Process(worker_pid)
                        if process.create_time() == worker_start and process.uids().real == os.getuid():
                            os.killpg(worker_pid, signal.SIGKILL)
                    except (psutil.NoSuchProcess, ProcessLookupError): pass


if __name__ == '__main__': unittest.main()
