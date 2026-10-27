"""Finite recipe ordering/rollback with explicit authority/systemd/VM doubles.

These tests prove orchestration and durable failure handling, not Root or I08
acceptance. The serialized authority/VM custody and client phase suites exercise
their real boundaries separately. No service or VM starts here.
"""
from contextlib import contextmanager, ExitStack, redirect_stdout
import json
import io
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14')]
import representation_producer as p
import vm_runtime_revalidation as runtime


class Recipe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.job = 'a'*32; self.release = 'f'*40; self.state = self.root/'state'
        (self.state/'jobs'/self.job).mkdir(parents=True); self.control = self.root/'control'; self.control.mkdir(mode=0o700)
        self.store = self.root/'authority'; self.store.mkdir(mode=0o700)
        self.contexts = {key: {'profile': p.auth.contract.PROFILES[key][0], 'owned': 'inert context'} for key in ['python', 'html']}
        self.ready = b'{"owned":"inert readiness only"}\n'; self.requests = {}; self.events = []

    def tearDown(self): self.tmp.cleanup()

    def run_recipe(self, fault=None, python_done=False, all_done=False):
        @contextmanager
        def anchor(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        @contextmanager
        def authority():
            with anchor(self.store) as fd: yield fd
        def capture(engine): return next(v for v in self.contexts.values() if v['profile'] == engine)
        def accepted(key, context): return all_done or python_done and key == 'python'
        def request(job, nonce, profile, mode, slot):
            rid = f'{len(self.requests)+1:032x}'
            raw = p.auth.canonical({'candidate': {'request_id': rid, 'slot': slot,
                'created_at': int(time.time()), 'expires_at': int(time.time())+900,
                'selection_binding_sha256': '1'*64, 'source': {'sha256': '2'*64}}})
            self.requests[mode, slot] = raw
            return raw, self.root/'unchanged-parent', {'fixed': 'same parent bytes'}
        def execute(raw, policy, **kwargs):
            slot = p.auth.decode(raw)['candidate']['slot']; self.events.append('execute:'+slot)
            witness = kwargs.get('_witness')
            if kwargs.get('_owned_probe'): witness['live_busy_lock_refused'] = True
            if slot in p.FAULTS: return {'result': 'FAIL', 'runs': []}, self.root/'inert-audit'
            if fault == 'validation' and slot == 'qp' or fault == 'smoke' and slot == 'smoke' and self.events.count('execute:smoke') == 2:
                return {'result': 'FAIL', 'error': 'owned injected failure'}, self.root/'inert-audit'
            selected = 'html' if python_done else 'python'
            blob = b'OWNED-REPRESENTATION-0000000000000000\n' if selected == 'python' else p.auth.canonical({'title': 'OWNED-REPRESENTATION-0000000000000000'[:32]})
            return {'result': 'PASS', 'runs': [{'outcome': {'status': 'completed', 'returncode': 0,
                'records': [{'bytes_hex': blob.hex()}]}}]}, self.root/'inert-audit'
        def client(job, nonce, profile, mode, phase, context, **kwargs):
            self.events.append('client:'+phase+':'+mode)
            if phase == 'import':
                spec = p.client_command(job, nonce, profile, mode, phase, slot=kwargs['slot'])
                target = spec['workspace']/'sidecar-smoke/result'; target.mkdir(parents=True)
                (target/'request.json').write_bytes(self.requests[mode, 'smoke'])
                (target/'receipt.json').write_bytes(b'{"owned":"receipt"}\n')
            return {'result': 'PASS', 'writers_stopped': True, 'mode': mode}
        def install(raw, context):
            self.events.append('install-readiness')
            with authority() as fd: p.auth.fs.exclusive(fd, 'readiness-'+p.auth.digest(raw)+'.json', raw)
        def exported(raw):
            return {'request_id': p.auth.decode(raw)['candidate']['request_id'], 'receipt_sha256': p.auth.digest(b'{"owned":"receipt"}\n')}
        execution_patch = mock.patch.object(p, 'execute', side_effect=execute)
        installed_patch = mock.patch.object(p.auth, 'install_readiness', side_effect=install)
        patches = [mock.patch.object(p, 'root_only'), mock.patch.object(p, 'snapshot_proof', side_effect=ValueError('operator_release_history') if fault == 'proof' else None), mock.patch.object(p, 'STATE', self.state), mock.patch.object(p, 'CONTROL', self.control),
             mock.patch.object(p, 'CLIENTS', self.root/'clients'), mock.patch.object(p, 'READERS', self.root/'readers'), 
             mock.patch.object(p, 'RELEASES', self.root/'releases'), mock.patch.object(p.auth, 'HERE', self.root/'releases'/self.release/'lab/s14'), 
             mock.patch.object(p.auth.fs, 'root_directory', anchor), mock.patch.object(p.auth, 'store', authority), 
             mock.patch.object(p.uuid, 'uuid4', return_value=SimpleNamespace(hex='0'*32)), 
             mock.patch.object(runtime, 'revalidate', return_value={'result': 'PASS', 'vm_started': False}), 
             mock.patch.object(p.auth, 'initialize'), mock.patch.object(p.auth, 'capture', side_effect=capture), 
             mock.patch.object(p, 'accepted', side_effect=accepted), mock.patch.object(p, 'stage_client'), 
             mock.patch.object(p, 'run_client', side_effect=client), mock.patch.object(p, 'owned_request', side_effect=request), 
             mock.patch.object(p, 'case_inventory', return_value={'fixed': 'same parent bytes'}), 
             mock.patch.object(p.auth, 'make_policy', return_value=b'owned policy'), mock.patch.object(p.auth, 'install_policy'), 
             mock.patch.object(p.auth, 'issue'), mock.patch.object(p.auth, 'inspect', side_effect=ValueError('owned changed request refusal')), 
             mock.patch.object(p.auth, 'consume', side_effect=FileExistsError('owned replay refusal')), 
             execution_patch, 
             mock.patch.object(p, 'verify_single', return_value={'result': 'PASS'}), mock.patch.object(p, 'verify_fault', return_value={'result': 'PASS'}), 
             mock.patch.object(p, 'new_readiness', return_value=self.ready), installed_patch, 
             mock.patch.object(p, 'publish', side_effect=exported), mock.patch.object(p.auth.contract, 'validate_request', side_effect=lambda raw, now=None: p.auth.decode(raw)), 
             mock.patch.object(p.auth.contract, 'validate_receipt', return_value={'artifacts': []}), 
             mock.patch.object(p, 'publish_reader_tree')]
        self.output = io.StringIO()
        with ExitStack() as stack, redirect_stdout(self.output):
            handles = {id(patch): stack.enter_context(patch) for patch in patches}
            execution = handles[id(execution_patch)]; installed = handles[id(installed_patch)]
            try: p.run_owned(self.job, self.release)
            except ValueError as error: failure = error
            else: failure = None
        result = json.loads((self.state/'jobs'/self.job/'result.json').read_bytes())
        return result, failure, execution.call_count, installed.call_count

    def test_python_six_vectors_then_readiness_then_two_smokes(self):
        result, failure, executed, installed = self.run_recipe()
        self.assertIsNone(failure, repr(result)); self.assertEqual(result['result'], 'PASS'); self.assertEqual(result['profile'], 'python')
        self.assertEqual((executed, installed, result['cases']), (8, 1, 8))
        before = self.events[:self.events.index('install-readiness')]
        self.assertEqual(sum(v.startswith('execute:') for v in before), 6)
        self.assertEqual(self.events.count('client:import:source'), 1); self.assertEqual(self.events.count('client:import:installed'), 1)
        self.assertEqual(result['real_source_grants_issued'], 0)

    def test_next_bounded_call_selects_html_without_caller_profile_argument(self):
        result, failure, executed, installed = self.run_recipe(python_done=True)
        self.assertIsNone(failure, repr(result)); self.assertEqual(result['profile'], 'html'); self.assertEqual((executed, installed), (8, 1))

    def test_validation_failure_installs_no_readiness_or_acceptance(self):
        result, failure, _, installed = self.run_recipe('validation')
        self.assertIsNotNone(failure); self.assertEqual(result['result'], 'FAIL'); self.assertEqual(installed, 0)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_second_smoke_failure_revokes_only_new_readiness_and_does_not_accept(self):
        result, failure, executed, installed = self.run_recipe('smoke')
        self.assertIsNotNone(failure); self.assertEqual((executed, installed), (8, 1))
        self.assertEqual(result['result'], 'FAIL'); self.assertTrue(result['new_readiness_revoked'])
        self.assertEqual(list(self.store.iterdir()), [])

    def test_both_current_acceptances_start_no_new_guest(self):
        result, failure, executed, installed = self.run_recipe(all_done=True)
        self.assertIsNone(failure); self.assertEqual((executed, installed), (0, 0))
        self.assertTrue(result['already_accepted']); self.assertFalse(result['vm_started'])

    def test_invalid_release_proof_refuses_before_runtime_client_or_guest(self):
        result, failure, executed, installed = self.run_recipe('proof')
        self.assertIsNotNone(failure); self.assertEqual(result['result'], 'FAIL'); self.assertEqual((executed, installed), (0, 0))
        self.assertEqual(self.events, [])
        diagnostic = json.loads(self.output.getvalue())['diagnostic']
        self.assertEqual(diagnostic['error_code'], 'operator_release_history')
        self.assertEqual(diagnostic['error_type'], 'ValueError')



class Diagnostics(unittest.TestCase):
    def test_reason_codes_are_available_without_private_paths_or_raw_output(self):
        for error, code in [(ValueError('operator_release_history'), 'operator_release_history'),
                            (ValueError('owned_representation_execution_failed:positive:private opaque detail'), 'owned_representation_execution_failed'),
                            (PermissionError(13, 'permission denied', '/private/owned-probe'), 'non_code_failure'),
                            (ValueError('secret\nopaque untrusted bytes'), 'non_code_failure'),
                            (ValueError('secret_identifier'), 'non_code_failure'),
                            (ValueError('x'*200), 'non_code_failure')]:
            with self.subTest(code=code):
                value = p.failure_diagnostic(error)
                self.assertEqual(value['error_code'], code); self.assertLess(len(json.dumps(value)), 512)
                self.assertNotIn('private', json.dumps(value)); self.assertNotIn('secret', json.dumps(value))


if __name__ == '__main__': unittest.main()
