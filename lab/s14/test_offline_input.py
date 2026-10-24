"""Inert real CLI/local API admission; never starts guests or executes input."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import tempfile
import unittest

from offline_input import MAX_FRAME, admit, decode
from offline_input_matrix import authorize, job, run_job


class Admission(unittest.TestCase):
    def test_cli_and_local_api_agree_without_executing_input(self):
        value = job('success'); expected = admit(value)
        result = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('offline_input.py')), '--validate-stdin'],
                                input=json.dumps(value).encode(), capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['job_sha256'], expected['job_sha256'])
        value['source_hex'] = b'changed after admission'.hex()
        self.assertNotEqual(expected['job']['source_hex'], value['source_hex'])

    def test_schema_hash_authorization_clock_and_size_fail_closed(self):
        for key, changed in [('source_sha256', '0' * 64), ('profile', 'browser'), ('job_id', '../escape'),
                             ('operator_authorization', 'all-samples'), ('created_at', True),
                             ('expires_at', int(time.time()) - 1), ('source_hex', '00' * 16385)]:
            value = job('success'); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): admit(value)
        value = job('success'); value['mount'] = '/home'
        with self.assertRaisesRegex(ValueError, 'job_shape'): admit(value)

    def test_duplicate_keys_frame_size_and_unknown_source_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate_key'): decode(b'{"job_id":1,"job_id":2}')
        with self.assertRaisesRegex(ValueError, 'frame_budget'): decode(b' ' * (MAX_FRAME + 1))
        value = job('success'); source = b"print('another harmless source')\n"
        value.update(source_hex=source.hex(), source_sha256=hashlib.sha256(source).hexdigest())
        self.assertEqual(admit(value)['source'], source)
        with self.assertRaisesRegex(ValueError, 'synthetic_catalog_only'): authorize(value)

    def test_api_stops_partial_startup_before_propagating_failure(self):
        class Gate:
            def __init__(self, root): self.output = root; self.active_vm = None; self.stopped = []
            def start(self, label):
                self.active_vm = {'label': label}; raise TimeoutError('owned readiness timeout')
            def stop(self, vm): self.stopped.append(vm); self.active_vm = None
        with tempfile.TemporaryDirectory() as directory:
            gate = Gate(Path(directory))
            with self.assertRaisesRegex(TimeoutError, 'readiness'): run_job(gate, job('success'))
            self.assertIsNone(gate.active_vm)
            self.assertEqual(len(gate.stopped), 1)
            self.assertEqual(gate.stopped[0]['label'], 'owned-success')

    def test_busy_gate_keeps_prior_job_and_does_not_consume_admission(self):
        class Gate:
            def __init__(self, root): self.output = root; self.active_vm = {'label': 'prior-job'}
            def start(self, label): raise AssertionError('busy admission must not start')
            def stop(self, vm): raise AssertionError('busy admission must not stop the prior job')
        with tempfile.TemporaryDirectory() as directory:
            gate = Gate(Path(directory)); prior = gate.active_vm
            with self.assertRaisesRegex(ValueError, 'gate_busy'): run_job(gate, job('success'))
            self.assertIs(gate.active_vm, prior)
            self.assertFalse((gate.output / 'admissions').exists())

    def test_startup_before_vm_registration_keeps_original_error(self):
        class Gate:
            def __init__(self, root): self.output = root
            def start(self, label): raise TimeoutError('owned failure before registration')
            def stop(self, vm): raise AssertionError('no owned VM to stop')
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(TimeoutError, 'before registration'):
                run_job(Gate(Path(directory)), job('success'))


if __name__ == '__main__': unittest.main()
