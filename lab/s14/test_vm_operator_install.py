"""Native enrollment data/layout tests on owned files; no root/polkit/network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vm_operator_install as native
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
            return SimpleNamespace(returncode=0, stdout='{"status":"enrolled"}')
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


if __name__ == '__main__': unittest.main()
