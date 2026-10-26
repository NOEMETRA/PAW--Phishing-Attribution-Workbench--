"""Committed-byte native bootstrap fixtures; never install or authenticate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vm_operator_setup as setup
import vm_operator_install as native


class SetupBundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.repo = Path(self.tmp.name)
        self.git('init', '-q'); self.git('config', 'user.name', 'Owned Test'); self.git('config', 'user.email', 'owned@example.invalid')
        names = {native.ENTRY_SOURCE, native.WORKER_SOURCE, native.INSTALLER_SOURCE,
                 *{'lab/s14/'+name for name in native.MODULES}}
        for name in names:
            path = self.repo/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'# inert committed fixture\n')
        (self.repo/native.INSTALLER_SOURCE).write_bytes(b'print("INERT_APPROVED_INSTALLER_RAN")\n')
        self.git('add', '.'); self.git('commit', '-qm', 'owned sources')
        self.head = self.git('rev-parse', 'HEAD').decode().strip()

    def git(self, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(self.repo), *args], stderr=subprocess.STDOUT)

    def tearDown(self): self.tmp.cleanup()

    def test_bundle_uses_committed_blobs_not_changed_workspace_or_untracked_files(self):
        (self.repo/native.ENTRY_SOURCE).write_bytes(b'# changed uncommitted\n')
        (self.repo/'lab/s14/untracked.py').write_bytes(b'# not committed\n')
        raw, digest = setup.build(self.repo, self.head, 111, now=100)
        meta, files = native.bundle(raw, digest, now=101)
        self.assertEqual(files[native.ENTRY_SOURCE], b'# inert committed fixture\n')
        self.assertNotIn('lab/s14/untracked.py', files)
        self.assertEqual(meta['head_sha'], self.head); self.assertEqual(meta['policy']['anchor_sha'], self.head)
        self.assertEqual(meta['expires_at'], 3700)

    def test_committed_symlink_and_short_commit_cannot_enter_bundle(self):
        path = self.repo/'lab/s14/link.py'; path.symlink_to('vm_operator_entry.py')
        self.git('add', '.'); self.git('commit', '-qm', 'owned linked fixture')
        with self.assertRaises(ValueError): setup.build(self.repo, self.git('rev-parse', 'HEAD').decode().strip(), 111, 100)
        with self.assertRaises(ValueError): setup.build(self.repo, self.head[:10], 111, 100)

    def test_literal_loader_checks_whole_bundle_then_installer_before_execution(self):
        raw, digest = setup.build(self.repo, self.head, 111, 100)
        path = self.repo/'approval.json'; path.write_bytes(raw)
        # Mock only UID for this unprivileged subprocess; the installer is a
        # benign print fixture, with no filesystem/polkit/VM operations.
        code = 'import os; os.geteuid=lambda:0\n'+setup.LOADER
        def run(expected):
            return subprocess.run([sys.executable, '-I', '-B', '-c', code, str(path), expected],
                                  capture_output=True, text=True, timeout=10)
        good = run(digest); self.assertEqual(good.returncode, 0); self.assertIn('INERT_APPROVED_INSTALLER_RAN', good.stdout)
        changed = json.loads(raw); changed['files'][native.INSTALLER_SOURCE]['sha256'] = '0'*64
        broken = native.canonical(changed); path.write_bytes(broken)
        bad_whole = run(digest); self.assertNotEqual(bad_whole.returncode, 0); self.assertFalse(bad_whole.stdout)
        bad_installer = run(hashlib.sha256(broken).hexdigest()); self.assertNotEqual(bad_installer.returncode, 0)
        self.assertFalse(bad_installer.stdout); self.assertIn('native_bootstrap_installer_digest', bad_installer.stderr)

    def test_native_command_is_finite_resource_bounded_and_has_no_credential(self):
        argv = setup.command(Path('/owned/approval.json'), 'a'*64, self.head)
        self.assertEqual(argv[:3], ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/systemd-run'])
        self.assertIn('--property=MemorySwapMax=0', argv); self.assertIn('--property=LimitCORE=0', argv)
        self.assertIn('--property=RuntimeMaxSec=2100', argv); self.assertIn('--property=TasksMax=64', argv)
        self.assertEqual(argv[-3:], [setup.LOADER, '/owned/approval.json', 'a'*64])
        self.assertFalse(any('token' in arg.lower() or 'password' in arg.lower() for arg in argv))

    def test_repair_request_is_digest_bound_data_not_a_root_path_or_command(self):
        previous = {'release_sha': 'a'*40, 'manifest_sha256': 'b'*64}
        raw, digest = setup.build(self.repo, self.head, 111, 100, repair_from=previous)
        meta, _ = native.bundle(raw, digest, 100)
        self.assertEqual(meta['schema'], 'paw-vm-native-bundle-v2'); self.assertEqual(meta['repair_from'], previous)
        self.assertEqual(meta['policy']['anchor_sha'], self.head)


if __name__ == '__main__': unittest.main()
