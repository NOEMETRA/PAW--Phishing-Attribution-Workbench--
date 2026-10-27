"""Adapters with inert VM channels and temporary opaque quarantine."""
import copy
from contextlib import contextmanager, nullcontext
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14'), str(REPO/'tests')]
import representation_adapter as adapter
from test_representation_bridge import forensic_case


class Adapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        case, graph = forensic_case(self.root)
        node = next(key for key, row in graph.nodes.items() if row['kind'] == 'partial_decoded_candidate')
        info = adapter.auth.contract.prepare(case, node, 'html', self.root/'request')
        self.request = adapter.auth.contract.validate_request(Path(info['request']).read_bytes())
        self.uid = str(uuid.uuid4())

    def tearDown(self): self.tmp.cleanup()

    def exercise(self, profile, fault=None, cancel=False):
        request = copy.deepcopy(self.request)
        if profile == adapter.PYTHON:
            request['candidate']['profile'] = profile; request['candidate']['source']['media_type'] = 'text/x-python'
        raw = adapter.auth.canonical(request); summary = adapter.auth.inspect(raw)
        source = bytes.fromhex(request['candidate']['source']['data_hex']); current = adapter.job(request)
        job_sha = adapter.auth.digest(adapter.auth.canonical(current)); rid = summary['request_id']
        context = {'profile': profile, 'backend': {'chrome_version': 'Google Chrome owned inert',
                   'chrome_binary_sha256': '1'*64}}
        ledger = {'request_id': rid}; output = self.root/('job-'+str(len(list(self.root.glob('job-*')))))
        output.mkdir(mode=0o700); media = output/'media'; media.write_bytes(b'owned inert media')
        gate = mock.Mock(spec=adapter.HashGate if profile == adapter.PYTHON else adapter.BrowserVM)
        gate.phase = 'job'; gate.output = output; gate.media = media; gate.active_vm = None; gate.report = {'vms': []}
        gate.connection = SimpleNamespace(listAllDomains=mock.Mock(return_value=['foreign'] if fault == 'busy' else []))
        gate.seed_config = {'source_sha256': summary['source_sha256'], 'source_bytes': len(source),
                            'job_sha256': job_sha, 'request_id': rid}
        if fault == 'seed': gate.seed_config['job_sha256'] = '0'*64
        data = b'{"owned":"opaque"}'
        records = [{'name': 'observations.json', 'bytes_hex': data.hex(), 'sha256': adapter.auth.digest(data),
                    'scope': 'opaque untrusted guest browser output'}] if profile == adapter.HTML else [
            {'name': name, 'bytes_hex': data.hex(), 'sha256': adapter.auth.digest(data), 'scope': 'opaque untrusted output'}
            for name in ['stdout.bin', 'stderr.bin']]
        outcome = {'done': True, 'status': 'cancelled' if cancel else 'completed', 'returncode': 0,
            'records': [] if cancel else records, 'writers_stopped': True,
            'events': {'memory.events': '', 'pids.events': '', 'pids.current': '0'}, 'output_truncated': False,
            'sandbox': {key: True for key in ['renderer_seen', 'renderer_nnp', 'renderer_seccomp', 'renderer_pid_namespace', 'all_uids_nonroot']}}
        def call(operation, **kwargs):
            if operation == 'inspect':
                return {'chrome_version': context['backend']['chrome_version'],
                        'chrome_binary_sha256': context['backend']['chrome_binary_sha256'],
                        'kernel_release': '6.8.0-147-generic', 'network_interfaces': ['lo'], 'prior_marker_absent': True}
            if operation == 'start':
                return {'started': True, 'prior_marker_absent': True, 'source_sha256': summary['source_sha256'],
                        'job_sha256': job_sha, 'job_limits': {'memory.max': str(adapter.JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(adapter.JOB_TASKS)}}
            if fault == 'protocol': raise ValueError('owned protocol failure')
            return outcome
        vm = {'node': {'uuid': self.uid}, 'channel': SimpleNamespace(call=call), 'stopped': False}
        def start(label): gate.active_vm = vm; return vm
        def stop(value):
            value.update(stopped=None if fault == 'stop' else True, stop_seconds=.01); gate.active_vm = None
            owner = {'reason': 'controller_lost' if fault == 'owner' else 'requested_stop', 'connection_closed': True}
            if profile == adapter.HTML: owner['vm_uuid'] = self.uid
            (output/(current['job_id']+'-owner-result.json')).write_text(json.dumps(owner))
            (output/(current['job_id']+'-owner-result.json')).chmod(0o400)
            (output/(current['job_id']+'-ready.json')).write_text(json.dumps({'uuid': 'wrong' if fault == 'identity' else self.uid}))
            (output/(current['job_id']+'-ready.json')).chmod(0o400)
            gate.report['vms'].append({'uuid': self.uid, 'label': current['job_id']})
        gate.start.side_effect = start; gate.stop.side_effect = stop
        @contextmanager
        def root_directory(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try: yield fd
            finally: os.close(fd)
        with mock.patch.object(adapter.auth.os, 'geteuid', return_value=0), \
             mock.patch.object(adapter.auth.fs, 'OWNER_UID', os.getuid()), \
             mock.patch.object(adapter.auth.fs, 'root_directory', root_directory), \
             mock.patch.object(adapter.auth.fs, 'execution_lock', nullcontext), \
             mock.patch.object(adapter.auth, 'capture', return_value=context), \
             mock.patch.object(adapter.auth, 'consume', return_value=(ledger, b'owned grant', summary, request, source)) as consume, \
             mock.patch.object(adapter.auth, 'load_bound', return_value=(b'owned grant', summary, request, source)), \
             mock.patch.object(adapter.auth, 'confirm_consumed'), \
             mock.patch.object(adapter, 'available_memory', return_value=3*1024**3), \
             mock.patch.object(adapter.shutil, 'disk_usage', return_value=SimpleNamespace(free=20*1024**3)):
            try:
                function = adapter.run_python if profile == adapter.PYTHON else adapter.run_html
                result = function(gate, raw, b'owned policy', cancel=cancel)
            except Exception as error: result = error
            consumed = consume.call_count
        return result, gate, output, consumed

    def test_python_and_html_bind_new_parent_and_authority_before_opaque_quarantine(self):
        for profile in [adapter.PYTHON, adapter.HTML]:
            value, gate, output, consumed = self.exercise(profile)
            self.assertIsInstance(value, dict, repr(value)); self.assertEqual(consumed, 1)
            self.assertTrue(value['writers_stopped']); self.assertIsNone(gate.active_vm)
            self.assertEqual(value['job']['parent_sha256'], self.request['candidate']['selection_binding_sha256'])
            self.assertEqual(value['job']['operator_authorization'], 'root-representation-grant-v1')
            self.assertTrue((output/(value['job']['job_id']+'-quarantine')).is_dir())

    def test_busy_host_refuses_before_consumption_or_guest_creation(self):
        for profile in [adapter.PYTHON, adapter.HTML]:
            value, gate, _, consumed = self.exercise(profile, 'busy')
            self.assertIsInstance(value, ValueError); self.assertEqual(consumed, 0); gate.start.assert_not_called()

    def test_changed_owner_blocks_quarantine_after_stop(self):
        for profile in [adapter.PYTHON, adapter.HTML]:
            value, gate, output, _ = self.exercise(profile, 'owner')
            self.assertIsInstance(value, ValueError); self.assertIsNone(gate.active_vm)
            self.assertEqual(list(output.glob('*-quarantine')), [])

    def test_unknown_stop_and_protocol_failure_never_publish(self):
        for profile in [adapter.PYTHON, adapter.HTML]:
            for fault in ['stop', 'protocol']:
                value, gate, output, _ = self.exercise(profile, fault)
                self.assertIsInstance(value, ValueError); self.assertIsNone(gate.active_vm)
                self.assertEqual(list(output.glob('*-quarantine')), [])

    def test_html_seed_mismatch_refuses_before_guest(self):
        value, gate, output, _ = self.exercise(adapter.HTML, 'seed')
        self.assertIsInstance(value, ValueError); gate.start.assert_not_called()
        self.assertEqual(list(output.glob('*-quarantine')), [])

    def test_python_ready_identity_binds_the_legacy_two_field_owner_protocol(self):
        value, gate, output, _ = self.exercise(adapter.PYTHON, 'identity')
        self.assertIsInstance(value, ValueError); self.assertEqual(list(output.glob('*-quarantine')), [])

    def test_cancelled_output_is_empty_and_externally_stopped(self):
        for profile in [adapter.PYTHON, adapter.HTML]:
            value, _, output, _ = self.exercise(profile, cancel=True)
            self.assertIsInstance(value, dict, repr(value)); self.assertEqual(value['outcome']['status'], 'cancelled')
            self.assertEqual(value['quarantine'], []); self.assertTrue(value['writers_stopped'])

    def test_unprivileged_call_refuses_before_lock_authority_or_guest(self):
        with mock.patch.object(adapter.os, 'geteuid', return_value=1000), \
             mock.patch.object(adapter.auth.fs, 'execution_lock') as lock, \
             mock.patch.object(adapter.auth, 'consume') as consume:
            for function in [adapter.run_python, adapter.run_html]:
                with self.assertRaisesRegex(ValueError, 'root_representation_adapter_required'):
                    function(None, b'', b'')
            lock.assert_not_called(); consume.assert_not_called()


if __name__ == '__main__': unittest.main()
