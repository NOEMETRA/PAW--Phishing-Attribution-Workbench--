"""Native enrollment data/layout tests on owned files; no root/polkit/network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import vm_operator_install as native
import vm_operator_host as host
import vm_release_archive as archive
import vm_release_storage as storage
from test_vm_release_contract import fixture


def approved():
    policy, proof = fixture()
    names = {native.ENTRY_SOURCE, native.WORKER_SOURCE, native.INSTALLER_SOURCE,
             *{'lab/s14/'+name for name in native.MODULES}}
    files = {name: b'# approved inert test bytes\n' for name in names}
    value = {'schema': 'paw-vm-native-bundle-v1', 'repository': native.REPOSITORY, 'owner_uid': 1000,
             'head_sha': proof['merge_sha'], 'pull_request': 111, 'created_at': 100, 'expires_at': 1000,
             'policy': policy, 'files': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                             'data_hex': raw.hex()} for name, raw in files.items()}}
    return value, files, proof


class NativeBundle(unittest.TestCase):
    def admit(self, value, now=200):
        raw = native.canonical(value); return native.bundle(raw, hashlib.sha256(raw).hexdigest(), now)

    def test_exact_digest_and_all_required_bootstrap_bytes(self):
        value, files, _ = approved(); meta, decoded = self.admit(value)
        self.assertEqual(decoded, files); self.assertNotIn('files', meta)
        raw = native.canonical(value)
        with self.assertRaises(ValueError): native.bundle(raw, '0'*64, 200)
        value['files'].pop(native.INSTALLER_SOURCE)
        with self.assertRaises(ValueError): self.admit(value)

    def test_expired_long_future_or_boolean_lease_refuses(self):
        for key, item in [('expires_at', 200), ('expires_at', 3701), ('created_at', 201), ('created_at', True)]:
            value, _, _ = approved(); value[key] = item
            with self.subTest(key=key, item=item), self.assertRaises(ValueError): self.admit(value)

    def test_paths_oversize_bytes_and_digest_changes_refuse(self):
        for mutation in ['path', 'length', 'size', 'digest', 'extra', 'owner']:
            value, _, _ = approved(); item = value['files'][native.ENTRY_SOURCE]
            if mutation == 'path': value['files']['lab/s14/../evil.py'] = dict(item)
            elif mutation == 'length': item['bytes'] = True
            elif mutation == 'size': item.update(bytes=1024**2+1, data_hex='00'*(1024**2+1))
            elif mutation == 'digest': item['sha256'] = '0'*64
            elif mutation == 'extra': item['command'] = '/bin/sh'
            else: value['owner_uid'] = 0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.admit(value)

    def test_noncanonical_duplicate_and_symlink_input_refuse(self):
        value, _, _ = approved()
        for raw in [json.dumps(value).encode(), native.canonical(value)[:-1]+b',"schema":"duplicate"}']:
            with self.assertRaises(ValueError): native.bundle(raw, hashlib.sha256(raw).hexdigest(), 200)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'link'; path.symlink_to(Path(folder)/'absent')
            with self.assertRaises(OSError): native.approved_file(path, '0'*64)

    def test_polkit_authorizes_only_fixed_program_enrolled_name_and_root(self):
        policy, rule = native.polkit_configuration('linux-dac', Path('/usr/local/libexec/paw-vm-operator'))
        self.assertIn(b'org.freedesktop.policykit.exec.path', policy)
        self.assertIn(b'action.id === "org.noemetra.paw.vm.operator"', rule)
        self.assertIn(b'action.lookup("program") === "/usr/local/libexec/paw-vm-operator"', rule)
        self.assertIn(b'action.lookup("user") === "root"', rule)
        self.assertIn(b'subject.user === "linux-dac"', rule)
        with self.assertRaises(ValueError): native.polkit_configuration('user";evil', Path('/usr/local/libexec/paw-vm-operator'))
        with self.assertRaises(ValueError): native.polkit_configuration('linux-dac', Path('/bin/sh'))


class NativeLayout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.host = SimpleNamespace(ENTRY=self.root/'libexec'/'entry', STATIC=self.root/'static',
                                    STATE=self.root/'state', RELEASES=self.root/'releases')
        @contextmanager
        def directory(path):
            self.assertTrue(path == self.root or self.root in path.parents)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: storage.directory(fd); yield fd
            finally: os.close(fd)
        self.host.trusted_directory = directory
        self.rule = self.root/'rules'/'rule'; self.policy = self.root/'policies'/'policy'
        self.exports = self.root/'exports'
        value, self.files, self.proof = approved()
        self.meta = {k: v for k, v in value.items() if k != 'files'}
        self.patchers = [patch.object(native.os, 'geteuid', return_value=0),
                         patch.object(storage, 'ROOT_UID', os.getuid()),
                         patch.object(native, 'RULE_FILE', self.rule), patch.object(native, 'POLICY_FILE', self.policy),
                         patch.object(native, 'EXPORTS', self.exports),
                         patch.object(native, 'polkit_configuration', return_value=(b'policy', b'rule'))]
        for p in self.patchers: p.start()

    def tearDown(self):
        for p in reversed(self.patchers): p.stop()
        self.tmp.cleanup()

    def test_policy_is_published_only_after_installed_status_check(self):
        def selfcheck(*args, **kwargs):
            self.assertFalse(self.rule.exists()); self.assertFalse(self.policy.exists())
            self.assertTrue((self.host.STATE/'bootstrap.json').exists())
            return SimpleNamespace(returncode=0, stdout='{"status":"enrollment_incomplete"}')
        with patch.object(native.subprocess, 'run', side_effect=selfcheck):
            result = native.install_layout(self.host, storage, archive, self.meta, self.files, self.proof)
        self.assertEqual(result['result'], 'INSTALLED_NOT_RUNTIME_ACCEPTED')
        self.assertEqual(stat.S_IMODE(self.host.ENTRY.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.host.STATE/'bootstrap.json').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.host.STATIC/'vm_release_contract.py').stat().st_mode), 0o444)
        self.assertEqual(self.rule.read_bytes(), b'rule')

    def test_failed_selfcheck_rolls_back_and_never_publishes_permission(self):
        with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), self.assertRaises(ValueError):
            native.install_layout(self.host, storage, archive, self.meta, self.files, self.proof)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_stage_failure_after_rename_does_not_leave_initial_snapshot(self):
        def fails_after_rename(*args):
            archive.stage(*args); raise ValueError('inert post-rename verification failure')
        proxy = SimpleNamespace(stage=fails_after_rename)
        with self.assertRaisesRegex(ValueError, 'post-rename'):
            native.install_layout(self.host, storage, proxy, self.meta, self.files, self.proof)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_operator_or_nonroot_installer_never_overwrites(self):
        self.host.STATIC.mkdir(); marker = self.host.STATIC/'keep'; marker.write_bytes(b'preserved')
        with patch.object(native.subprocess, 'run') as run, self.assertRaises(ValueError):
            native.install_layout(self.host, storage, archive, self.meta, self.files, self.proof)
        run.assert_not_called(); self.assertEqual(marker.read_bytes(), b'preserved')
        with patch.object(native.os, 'geteuid', return_value=1000), self.assertRaises(ValueError):
            native.install_layout(self.host, storage, archive, self.meta, self.files, self.proof)

    def test_preexisting_state_must_already_be_private_and_is_not_repaired_implicitly(self):
        self.host.STATE.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'existing_private_directory_mode'):
            native.install_layout(self.host, storage, archive, self.meta, self.files, self.proof)
        self.assertEqual(stat.S_IMODE(self.host.STATE.stat().st_mode), 0o755)
        self.assertFalse(self.rule.exists())


class NativeAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.state = self.root/'state'; self.state.mkdir(mode=0o700); (self.state/'jobs').mkdir(mode=0o700)
        (self.root/'releases').mkdir(mode=0o700)
        self.rules = self.root/'rules'; self.rules.mkdir(mode=0o700); self.rule = self.rules/'rule'; self.rule.write_bytes(b'owned')
        @contextmanager
        def directory(path):
            self.assertTrue(path == self.root or self.root in path.parents)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        self.patchers = [patch.object(native.os, 'geteuid', return_value=0), patch.object(host, 'ROOT_UID', os.getuid()),
                         patch.object(host, 'STATE', self.state), patch.object(host, 'RELEASES', self.root/'releases'),
                         patch.object(host, 'trusted_directory', directory), patch.object(native, 'RULE_FILE', self.rule),
                         patch.object(native, 'authorization_probe', return_value={'owned_test_probe': True}),
                         patch.object(storage, 'verify', return_value=({}, {}))]
        for p in self.patchers: p.start()
        self.head = 'c'*40; self.job = 'd'*32
        self.meta = {'head_sha': self.head, 'owner_uid': 1000}
        self.installed = {'release_sha': self.head, 'manifest_sha256': 'e'*64}
        self.outcome = {'result': 'PASS', 'job': self.job, 'recipe': 'browser-owned-v1', 'release_sha': self.head,
                        'real_samples_executed': 0, 'cases': 9}

    def tearDown(self):
        for p in reversed(self.patchers): p.stop()
        self.tmp.cleanup()

    def phase(self, _, meta, folder, phase, nonce=None):
        if phase == 'run':
            marker = self.state/'enrollment-test-consumed'; marker.write_bytes(b'owned consumed'); marker.chmod(0o600)
            path = self.state/'jobs'/self.job; path.mkdir(mode=0o700)
            with host.trusted_directory(path) as fd: host.write_state(fd, 'result.json', self.outcome)
        elif phase == 'revoke':
            with host.trusted_directory(self.state) as fd: host.revoke(fd)
        elif phase == 'restored': self.assertFalse((self.state/'revoked').exists())

    def record(self): return json.loads((self.state/'enrollment-acceptance'/'result.json').read_bytes())

    def test_complete_native_acceptance_checks_protected_job_revoke_and_restore(self):
        with patch.object(native, 'acceptance_phase', side_effect=self.phase):
            result = native.accept_installation(host, storage, self.meta, self.installed)
        self.assertEqual(result['result'], 'PASS'); self.assertEqual(result['cases'], 9)
        self.assertEqual(result['completed_phases'], ['probe', 'run', 'revoke', 'restored'])
        self.assertEqual(self.record(), result); self.assertTrue(self.rule.exists())
        self.assertFalse((self.state/'revoked').exists())

    def test_failed_job_retains_result_and_revokes_rule_without_deleting_sources(self):
        self.outcome['real_samples_executed'] = False
        with patch.object(native, 'acceptance_phase', side_effect=self.phase), self.assertRaises(ValueError):
            native.accept_installation(host, storage, self.meta, self.installed)
        self.assertEqual(self.record()['result'], 'FAIL'); self.assertFalse(self.rule.exists())
        self.assertTrue((self.state/'revoked').exists()); self.assertTrue((self.state/'jobs'/self.job/'result.json').exists())

    def test_phase_failure_after_native_restore_reinstates_revocation(self):
        def failed(*args):
            self.phase(*args)
            if args[3] == 'restored': raise ValueError('owned post-restore failure')
        with patch.object(native, 'acceptance_phase', side_effect=failed), self.assertRaises(ValueError):
            native.accept_installation(host, storage, self.meta, self.installed)
        self.assertTrue((self.state/'revoked').exists()); self.assertFalse(self.rule.exists())
        self.assertEqual(self.record()['result'], 'FAIL')

    def test_revoked_attempt_must_not_create_another_job(self):
        def bad(*args):
            self.phase(*args)
            if args[3] == 'revoke': (self.state/'jobs'/('f'*32)).mkdir(mode=0o700)
        with patch.object(native, 'acceptance_phase', side_effect=bad), self.assertRaises(ValueError):
            native.accept_installation(host, storage, self.meta, self.installed)
        self.assertTrue((self.state/'revoked').exists()); self.assertFalse(self.rule.exists())

    def test_failure_before_acceptance_log_creation_still_removes_rule_and_revokes(self):
        folder = self.state/'enrollment-acceptance'; folder.mkdir(mode=0o700)
        (folder/'result.json').write_bytes(b'prior owned record')
        with self.assertRaises(FileExistsError): native.accept_installation(host, storage, self.meta, self.installed)
        self.assertFalse(self.rule.exists()); self.assertTrue((self.state/'revoked').exists())
        self.assertEqual((folder/'result.json').read_bytes(), b'prior owned record')

    def test_failure_persisting_final_acceptance_proof_revokes_permission(self):
        original = host.write_state
        def fail_final(fd, name, value):
            if value.get('schema') == 'paw-vm-native-acceptance-v1' and value.get('result') == 'PASS':
                raise OSError('owned final proof storage failure')
            return original(fd, name, value)
        with patch.object(native, 'acceptance_phase', side_effect=self.phase), \
             patch.object(host, 'write_state', side_effect=fail_final), self.assertRaises(OSError):
            native.accept_installation(host, storage, self.meta, self.installed)
        self.assertFalse(self.rule.exists()); self.assertTrue((self.state/'revoked').exists())

    @unittest.skipUnless(hasattr(os, 'fork'), 'POSIX process-loss contract')
    def test_sigkill_before_acceptance_leaves_no_ordinary_delegated_authority(self):
        policy, _ = fixture(); now = int(time.time()); policy.update(created_at=now, expires_at=now+3600, anchor_sha=self.head)
        current = {'schema': 'paw-vm-active-v1', 'release_sha': self.head, 'manifest_sha256': 'e'*64, 'pull_request': 111}
        for name, value in [('policy.json', policy), ('active.json', current)]:
            path = self.state/name; path.write_bytes(storage.canonical(value)); path.chmod(0o600)
        read, write = os.pipe(); pid = os.fork()
        if pid == 0:
            os.close(read)
            def held(*args):
                os.write(write, b'R'); signal.pause()
            try:
                with patch.object(native, 'authorization_probe', side_effect=held):
                    native.accept_installation(host, storage, self.meta, self.installed)
            except BaseException: os._exit(2)
            os._exit(3)
        os.close(write); reaped = False
        try:
            self.assertTrue(select.select([read], [], [], 5)[0]); self.assertEqual(os.read(read, 1), b'R')
            os.kill(pid, signal.SIGKILL); _, status = os.waitpid(pid, 0); reaped = True
            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
            self.assertTrue(self.rule.exists())  # No exception cleanup ran.
            self.assertFalse((self.state/'enrollment-acceptance'/'result.json').exists())
            with patch.object(host, 'run_owned') as run:
                with self.assertRaisesRegex(ValueError, 'enrollment_incomplete'): host.main(['run', 'browser-owned-v1'], 1000)
                run.assert_not_called()
            self.assertEqual(host.main(['status'], 1000)['status'], 'enrollment_incomplete')
        finally:
            os.close(read)
            if not reaped:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(pid, 0)


class NativePolkitProbe(unittest.TestCase):
    def setUp(self):
        self.child = Mock(pid=os.getpid()); self.child.poll.return_value = None
        self.host = SimpleNamespace(ENTRY=Path('/usr/local/libexec/paw-vm-operator'))

    def test_fixed_details_describe_live_enrolled_subject_and_never_allow_interaction(self):
        responses = [SimpleNamespace(returncode=n, stdout=b'', stderr=b'') for n in [0, 1, 2]]
        with (patch.object(native.os, 'geteuid', return_value=0),
              patch.object(native.subprocess, 'Popen', return_value=self.child) as child,
              patch.object(native.subprocess, 'run', side_effect=responses) as checks):
            result = native.authorization_probe(self.host, {'owner_uid': os.getuid()})
        self.assertTrue(result['custom_authorized']); self.assertTrue(result['noninteractive'])
        self.assertEqual(child.call_args.kwargs['user'], os.getuid())
        for call in checks.call_args_list:
            argv = call.args[0]; self.assertNotIn('--allow-user-interaction', argv)
            subject = argv[argv.index('--process')+1].split(',')
            self.assertEqual(subject[0], str(os.getpid())); self.assertEqual(subject[2], str(os.getuid()))
            self.assertTrue(subject[1].isdigit()); self.assertIn('--detail', argv)
        self.child.terminate.assert_called_once(); self.child.wait.assert_called_once()

    def test_generic_allow_or_check_error_is_not_counted_as_denial(self):
        for code in [0, 127]:
            responses = [SimpleNamespace(returncode=n, stdout=b'', stderr=b'') for n in [0, code, 1]]
            with self.subTest(code=code), patch.object(native.os, 'geteuid', return_value=0), \
                 patch.object(native.subprocess, 'Popen', return_value=self.child), \
                 patch.object(native.subprocess, 'run', side_effect=responses), self.assertRaises(ValueError):
                native.authorization_probe(self.host, {'owner_uid': os.getuid()})


if __name__ == '__main__': unittest.main()
