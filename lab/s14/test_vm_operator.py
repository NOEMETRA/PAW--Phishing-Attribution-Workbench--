"""Root dispatch composition simulated with owned files; no polkit/VM changes."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import vm_operator_entry as entry
import vm_operator_host as host
import vm_release_archive as archive
import vm_release_storage as storage
from test_vm_release_contract import fixture


class InstalledOperator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.base = Path(self.tmp.name)
        self.state = self.base/'state'; self.state.mkdir(mode=0o700)
        self.releases = self.base/'releases'; self.releases.mkdir(mode=0o700)
        (self.state/'jobs').mkdir(mode=0o700)
        self.policy, self.proof = fixture(); now = int(time.time())
        self.policy.update(created_at=now-1, expires_at=now+3600)
        self.patchers = [patch.object(storage, 'ROOT_UID', os.getuid()), patch.object(host, 'ROOT_UID', os.getuid()),
                         patch.object(host, 'STATE', self.state), patch.object(host, 'RELEASES', self.releases),
                         patch.object(host.os, 'geteuid', return_value=0)]
        for item in self.patchers: item.start()
        fd = os.open(self.releases, os.O_RDONLY | os.O_DIRECTORY)
        try: digest = archive.stage(fd, self.proof, {host.WORKER: b'OWNED = 1\n'})
        finally: os.close(fd)
        self.current = {'schema': 'paw-vm-active-v1', 'release_sha': self.proof['merge_sha'],
                        'manifest_sha256': digest, 'pull_request': 111}
        for name, value in [('policy.json', self.policy), ('active.json', self.current)]:
            path = self.state/name; path.write_bytes(storage.canonical(value)); path.chmod(0o600)
        accepted = self.state/'enrollment-acceptance'; accepted.mkdir(mode=0o700)
        proof = {'schema': 'paw-vm-native-acceptance-v1', 'result': 'PASS', 'release_sha': self.policy['anchor_sha'],
                 'completed_phases': ['probe', 'run', 'revoke', 'restored'], 'cases': 9,
                 'real_samples_executed': 0, 'protected_job_sha256': 'f'*64}
        (accepted/'result.json').write_bytes(storage.canonical(proof)); (accepted/'result.json').chmod(0o600)
        @contextmanager
        def owned_directory(path):
            # Test-only fd fixture. Production walks and checks fixed root ancestors.
            self.assertTrue(path == self.state or path == self.releases or self.state in path.parents)
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: storage.directory(descriptor); yield descriptor
            finally: os.close(descriptor)
        item = patch.object(host, 'trusted_directory', owned_directory); item.start(); self.patchers.append(item)

    def tearDown(self):
        for item in reversed(self.patchers): item.stop()
        self.tmp.cleanup()

    def test_status_never_launches_and_wrong_caller_or_arguments_refuse(self):
        with patch.object(host.subprocess, 'run') as run:
            self.assertEqual(host.main(['status'], 1000)['status'], 'enrolled')
            with self.assertRaises(ValueError): host.main(['status'], 1001)
            with self.assertRaises(ValueError): host.main(['run', '/tmp/user.py'], 1000)
            run.assert_not_called()

    def test_revocation_survives_expired_lease_and_blocks_new_work(self):
        self.policy.update(created_at=1, expires_at=2)
        (self.state/'policy.json').write_bytes(storage.canonical(self.policy))
        self.assertFalse(host.main(['status'], 1000)['lease_valid'])
        self.assertEqual(host.main(['revoke'], 1000)['status'], 'revoked')
        self.assertEqual(host.main(['status'], 1000)['status'], 'revoked')
        with patch.object(host.subprocess, 'run') as run, self.assertRaises(ValueError): host.main(['run', 'browser-owned-v1'], 1000)
        run.assert_not_called()

    def test_missing_failed_or_foreign_acceptance_blocks_ordinary_run_and_promotion(self):
        receipt = self.state/'enrollment-acceptance'/'result.json'; saved = receipt.read_bytes()
        for condition in ['missing', 'failed', 'foreign', 'false_count']:
            if condition == 'missing': receipt.unlink()
            else:
                value = json.loads(saved)
                if condition == 'failed': value['result'] = 'FAIL'
                elif condition == 'foreign': value['release_sha'] = '0'*40
                else: value['real_samples_executed'] = False
                receipt.write_bytes(storage.canonical(value)); receipt.chmod(0o600)
            with self.subTest(condition=condition), patch.object(host, 'run_owned') as run, patch.object(host, 'promote') as promote:
                self.assertEqual(host.main(['status'], 1000)['status'], 'enrollment_incomplete')
                for argv in [['run', 'browser-owned-v1'], ['promote', '111']]:
                    with self.assertRaisesRegex(ValueError, 'enrollment_incomplete'): host.main(argv, 1000)
                run.assert_not_called(); promote.assert_not_called()

    def native_test(self):
        (self.state/'enrollment-acceptance'/'result.json').unlink()
        now = int(time.time()); token = b'a'*64
        value = {'schema': 'paw-vm-native-test-v1', 'release_sha': self.current['release_sha'],
                 'recipe': 'browser-owned-v1', 'token_sha256': __import__('hashlib').sha256(token).hexdigest(),
                 'owner_pid': os.getpid(), 'owner_start': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                 'created_at': now, 'expires_at': now+60}
        path = self.state/'enrollment-test.json'; path.write_bytes(storage.canonical(value)); path.chmod(0o600)
        return value, token, path

    def test_incomplete_native_test_requires_private_live_one_use_pipe_authority(self):
        _, token, _ = self.native_test()
        with patch.object(host.os, 'isatty', return_value=False), patch.object(host.select, 'select', return_value=([0], [], [])), \
             patch.object(host.os, 'read', return_value=token+b'\n'), patch.object(host, 'run_owned', return_value={'owned': True}) as run:
            self.assertEqual(host.main(['run', 'browser-owned-v1'], 1000), {'owned': True})
            with self.assertRaisesRegex(ValueError, 'native_test_consumed'): host.main(['run', 'browser-owned-v1'], 1000)
            run.assert_called_once()
        self.assertEqual(host.main(['status'], 1000)['status'], 'enrollment_incomplete')

    def test_dead_or_reused_native_owner_expired_grant_or_wrong_token_never_runs(self):
        value, token, path = self.native_test(); saved = dict(value)
        for mutation in ['owner_start', 'dead_owner', 'expired', 'wrong_token']:
            changed = dict(saved)
            if mutation == 'owner_start': changed['owner_start'] = '0'
            elif mutation == 'dead_owner': changed['owner_pid'] = 2147483647
            elif mutation == 'expired': changed.update(created_at=1, expires_at=2)
            path.write_bytes(storage.canonical(changed))
            with self.subTest(mutation=mutation), patch.object(host.os, 'isatty', return_value=False), \
                 patch.object(host.select, 'select', return_value=([0], [], [])), \
                 patch.object(host.os, 'read', return_value=b'b'*64+b'\n'), patch.object(host, 'run_owned') as run:
                with self.assertRaises(ValueError): host.main(['run', 'browser-owned-v1'], 1000)
                run.assert_not_called()
        self.assertFalse((self.state/'enrollment-test-consumed').exists())

    def test_native_owner_loss_during_capability_wait_refuses_before_consumption(self):
        value, token, path = self.native_test()
        owner = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(20)'])
        try:
            value.update(owner_pid=owner.pid, owner_start=Path('/proc', str(owner.pid), 'stat').read_text().rsplit(')', 1)[1].split()[19])
            path.write_bytes(storage.canonical(value))
            def loses_owner(*args):
                owner.terminate(); owner.wait(timeout=5); return ([0], [], [])
            with patch.object(host.os, 'isatty', return_value=False), patch.object(host.select, 'select', side_effect=loses_owner), \
                 patch.object(host.os, 'read', return_value=token+b'\n'), patch.object(host, 'run_owned') as run:
                with self.assertRaisesRegex(ValueError, 'native_test_owner_lost'): host.main(['run', 'browser-owned-v1'], 1000)
                run.assert_not_called()
            self.assertFalse((self.state/'enrollment-test-consumed').exists())
        finally:
            if owner.poll() is None: owner.terminate()
            owner.wait(timeout=5)

    def test_native_test_expiry_during_capability_wait_refuses_before_consumption(self):
        value, token, _ = self.native_test(); expired = False
        def clock(): return value['created_at']+(61 if expired else 1)
        def lease_expires(*args):
            nonlocal expired
            expired = True; return ([0], [], [])
        with patch.object(host.time, 'time', side_effect=clock), patch.object(host.os, 'isatty', return_value=False), \
             patch.object(host.select, 'select', side_effect=lease_expires), patch.object(host.os, 'read', return_value=token+b'\n'), \
             patch.object(host, 'run_owned') as run:
            with self.assertRaisesRegex(ValueError, 'native_test_identity_or_lease'): host.main(['run', 'browser-owned-v1'], 1000)
            run.assert_not_called()
        self.assertFalse((self.state/'enrollment-test-consumed').exists())

    def test_user_writable_state_and_lock_symlink_are_not_authority(self):
        (self.state/'active.json').chmod(0o666)
        with self.assertRaises(ValueError): host.main(['status'], 1000)
        (self.state/'active.json').chmod(0o600)
        (self.state/'operation.lock').symlink_to(self.state/'policy.json')
        fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(OSError):
                with host.operation_lock(fd): pass
        finally: os.close(fd)

    def test_operation_lock_is_exclusive_for_the_whole_request(self):
        fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with host.operation_lock(fd), self.assertRaises(BlockingIOError):
                with host.operation_lock(fd): pass
        finally: os.close(fd)

    def test_owned_worker_only_uses_fixed_unit_limits_and_verified_release(self):
        observed = []
        def systemd(argv, **kwargs):
            observed.append(argv); job = argv[-1]
            fd = os.open(self.state/'jobs'/job, os.O_RDONLY | os.O_DIRECTORY)
            try: host.write_state(fd, 'result.json', {'result': 'PASS', 'job': job, 'recipe': 'browser-owned-v1',
                    'release_sha': self.current['release_sha'], 'real_samples_executed': 0})
            finally: os.close(fd)
            return SimpleNamespace(returncode=0)
        with patch.object(host.subprocess, 'run', side_effect=systemd): result = host.main(['run', 'browser-owned-v1'], 1000)
        self.assertEqual(result['status'], 'completed'); self.assertEqual(len(observed), 1)
        argv = observed[0]
        self.assertIn('--property=MemoryMax=512M', argv); self.assertIn('--property=IPAddressDeny=any', argv)
        self.assertIn('--property=TasksMax=64', argv); self.assertIn('--property=MemorySwapMax=0', argv)
        self.assertIn('-I', argv); self.assertIn('-B', argv)
        self.assertIn(str(self.releases/self.current['release_sha']/host.WORKER), argv)

    def test_tampered_snapshot_stops_before_a_unit_is_created(self):
        worker = self.releases/self.current['release_sha']/host.WORKER
        worker.chmod(0o600); worker.write_bytes(b'CHANGED\n'); worker.chmod(0o444)
        with patch.object(host.subprocess, 'run') as run, self.assertRaises(ValueError): host.main(['run', 'browser-owned-v1'], 1000)
        run.assert_not_called(); self.assertEqual(list((self.state/'jobs').iterdir()), [])

    def test_failed_or_falsely_typed_worker_result_never_becomes_completed(self):
        for sample_count, returncode in [(False, 0), (1, 0), (0, 1)]:
            def systemd(argv, **kwargs):
                job = argv[-1]; fd = os.open(self.state/'jobs'/job, os.O_RDONLY | os.O_DIRECTORY)
                try: host.write_state(fd, 'result.json', {'result': 'PASS', 'job': job, 'recipe': 'browser-owned-v1',
                        'release_sha': self.current['release_sha'], 'real_samples_executed': sample_count})
                finally: os.close(fd)
                return SimpleNamespace(returncode=returncode)
            with self.subTest(sample_count=sample_count, returncode=returncode), \
                 patch.object(host.subprocess, 'run', side_effect=systemd), self.assertRaises(ValueError):
                host.main(['run', 'browser-owned-v1'], 1000)

    def test_read_credential_is_one_bounded_pipe_frame_not_a_filename_or_argument(self):
        with patch.object(host.os, 'isatty', return_value=True), patch.object(host.select, 'select') as ready:
            with self.assertRaises(ValueError): host.credential()
            ready.assert_not_called()
        for raw in [b'fixture_token_123456789\nextra', b'x'*258+b'\n', b'token-without-frame', b'\xff\n']:
            with patch.object(host.os, 'isatty', return_value=False), patch.object(host.select, 'select', return_value=([0], [], [])), \
                 patch.object(host.os, 'read', return_value=raw), self.assertRaises(ValueError): host.credential()

    def test_arbitrary_worker_paths_options_real_recipes_or_bad_ids_refuse(self):
        for release, recipe, job in [('../x', 'browser-owned-v1', 'a'*32), ('a'*40, '/bin/sh', 'a'*32),
                                     ('a'*40, 'real-source', 'a'*32), ('a'*40, [], 'a'*32),
                                     ('a'*40, 'browser-owned-v1', 'a'*31+';')]:
            with self.subTest(recipe=recipe), self.assertRaises(ValueError): host.worker_command(release, recipe, job)


class EntryBoundary(unittest.TestCase):
    def test_only_exact_root_bootstrap_module_set_and_full_digests_admit(self):
        value = {'schema': 'paw-vm-bootstrap-v1', 'owner_uid': 1000, 'entry_sha256': 'a'*64,
                 'modules': {name: 'b'*64 for name in entry.MODULES}}
        self.assertEqual(entry.bootstrap(json.dumps(value).encode()), value)
        for mutation in ['owner', 'module', 'digest', 'extra']:
            changed = copy.deepcopy(value)
            if mutation == 'owner': changed['owner_uid'] = True
            elif mutation == 'module': changed['modules']['../../user.py'] = 'a'*64
            elif mutation == 'digest': changed['entry_sha256'] = 'a'*10
            else: changed['command'] = '/bin/sh'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): entry.bootstrap(json.dumps(changed).encode())

    def test_workspace_entrypoint_is_not_a_root_authorization(self):
        with patch.object(entry.os, 'geteuid', return_value=0), patch.object(entry, 'read') as read:
            with self.assertRaises(ValueError): entry.main()
            read.assert_not_called()


if __name__ == '__main__': unittest.main()
