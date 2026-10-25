"""Inert lifecycle refusal tests; no libvirt, subprocess or browser is started."""
import contextlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_browser_contract as support
auth, contract, frame = support.auth, support.contract, support.frame
import browser_offline_adapter as adapter


@contextlib.contextmanager
def opened(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: yield fd
    finally: os.close(fd)


class FakeBrowser(adapter.BrowserVM):
    def __init__(self, output, context, value, *, fault=None, busy=False):
        self.output = output; output.mkdir(); self.phase = 'job'; self.active_vm = None
        self.starts = self.stops = 0; self.fault = fault; self.context = context
        self.connection = SimpleNamespace(listAllDomains=lambda flags: ['owned busy domain'] if busy else [])
        self.media = output/'input.iso'; self.media.write_bytes(b'owned inert media placeholder')
        self.seed_config = {'source_sha256': value['source']['sha256'], 'source_bytes': value['source']['bytes'],
                            'request_id': value['request_id'], 'job_sha256': auth.digest(auth.canonical(adapter.job(value)))}

    def start(self, label):
        self.starts += 1
        self.active_vm = {'node': {'uuid': '00000000-0000-0000-0000-000000000001'}, 'channel': self,
                          'owner_result_path': str(self.output/'owner-result.json')}
        if self.fault == 'startup': raise ValueError('owned_startup_failure')
        return self.active_vm

    def call(self, operation, seconds=8):
        if operation == 'inspect':
            return {'chrome_version': self.context['chrome_version'], 'chrome_binary_sha256': self.context['chrome_binary_sha256'],
                    'kernel_release': '6.8.0-147-generic', 'network_interfaces': ['lo'], 'prior_marker_absent': True}
        if operation == 'start':
            return {'started': True, 'prior_marker_absent': True, 'source_sha256': self.seed_config['source_sha256'],
                    'job_sha256': self.seed_config['job_sha256'],
                    'job_limits': {'memory.max': str(512*1024**2), 'memory.swap.max': '0', 'pids.max': '256'}}
        if self.fault == 'protocol': raise ValueError('guest_channel_failed:owned_fixture')
        value = support.Output().outcome()
        if self.fault == 'output': value['records'][0]['sha256'] = '0'*64
        return value

    def stop(self, vm):
        self.stops += 1
        if self.fault == 'unknown-stop': raise ValueError('unknown_stop_blocks_publication')
        vm.update(stopped=True, stop_seconds=.01)
        (self.output/'owner-result.json').write_bytes(auth.canonical({'reason': 'qemu_exited' if self.fault == 'owner' else 'requested_stop',
            'connection_closed': True, 'vm_uuid': vm['node']['uuid']}))
        (self.output/'owner-result.json').chmod(0o600)
        self.active_vm = None


@contextlib.contextmanager
def authority():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary); store = root/'authority'; store.mkdir(mode=0o700)
        ctx = support.Authority().context(); now = int(time.time()); value = frame(now=now); raw = contract.canonical(value)
        policy = support.Authority().policy(ctx); policy.update(created_at=now, expires_at=now+900); policy_raw = contract.canonical(policy)
        @contextlib.contextmanager
        def lock(): yield
        with patch.object(auth, 'store', lambda: opened(store)), patch.object(auth.fs, 'OWNER_UID', os.getuid()), \
                patch.object(auth.fs, 'root_directory', opened), patch.object(auth.fs, 'execution_lock', lock), \
                patch.object(auth.os, 'geteuid', return_value=0), patch.object(auth.platform, 'validate_context'), \
                patch.object(auth, 'capture', return_value=ctx), \
                patch.object(adapter, 'available_memory', return_value=4*1024**3), \
                patch.object(adapter.shutil, 'disk_usage', return_value=SimpleNamespace(free=20*1024**3)):
            with auth.store() as fd: auth.fs.exclusive(fd, 'policy-'+auth.digest(policy_raw)+'.json', policy_raw)
            auth.issue(raw, policy_raw, ctx)
            yield root, store, ctx, value, raw, policy_raw


class Lifecycle(unittest.TestCase):
    def test_busy_and_low_disk_refuse_before_global_consumption(self):
        for fault in ['busy', 'disk', 'memory']:
            with self.subTest(fault=fault), authority() as (root, store, ctx, value, raw, policy):
                gate = FakeBrowser(root/'output', ctx, value, busy=fault == 'busy')
                if fault == 'disk':
                    with patch.object(adapter.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)), self.assertRaises(ValueError):
                        adapter.run_browser_granted(gate, raw, policy)
                elif fault == 'memory':
                    with patch.object(adapter, 'available_memory', return_value=0), self.assertRaisesRegex(ValueError, 'browser_available_memory_admission'):
                        adapter.run_browser_granted(gate, raw, policy)
                else:
                    with self.assertRaises(ValueError): adapter.run_browser_granted(gate, raw, policy)
                self.assertEqual(gate.starts, 0); self.assertFalse((store/'consumed').exists())

    def test_known_stop_required_and_failed_attempts_remain_consumed(self):
        for fault in ['startup', 'protocol', 'owner', 'output', 'unknown-stop']:
            with self.subTest(fault=fault), authority() as (root, store, ctx, value, raw, policy):
                gate = FakeBrowser(root/'output', ctx, value, fault=fault)
                expected = {'startup':'owned_startup_failure','protocol':'guest_channel_failed','owner':'browser_unexpected_owner_exit','output':'record_digest','unknown-stop':'unknown_stop_blocks_publication'}[fault]
                with self.assertRaisesRegex(ValueError, expected): adapter.run_browser_granted(gate, raw, policy)
                self.assertEqual(gate.starts, 1); self.assertGreaterEqual(gate.stops, 1)
                self.assertFalse(list(gate.output.glob('*-quarantine')))
                with self.assertRaises(FileExistsError): auth.consume(raw, policy, ctx)

    def test_completed_opaque_output_publishes_only_after_stop_and_replay_cannot_start(self):
        with authority() as (root, store, ctx, value, raw, policy):
            gate = FakeBrowser(root/'output', ctx, value); result = adapter.run_browser_granted(gate, raw, policy)
            self.assertEqual(gate.stops, 1); self.assertTrue(result['writers_stopped'])
            self.assertEqual(result['outcome']['status'], 'completed')
            self.assertEqual((gate.output/('html-'+value['request_id']+'-quarantine')/'artifact-00.bin').read_bytes(), b'{"owned":true}\n')
            other = FakeBrowser(root/'other', ctx, value)
            with self.assertRaises(FileExistsError): adapter.run_browser_granted(other, raw, policy)
            self.assertEqual(other.starts, 0)

    def test_changed_context_after_boot_stops_without_output(self):
        with authority() as (root, store, ctx, value, raw, policy):
            gate = FakeBrowser(root/'output', ctx, value); changed = dict(ctx, image_sha256='e'*64)
            with patch.object(auth, 'capture', side_effect=[ctx, changed]), self.assertRaises(ValueError):
                adapter.run_browser_granted(gate, raw, policy)
            self.assertEqual(gate.stops, 1); self.assertFalse(list(gate.output.glob('*-quarantine')))


if __name__ == '__main__': unittest.main()
