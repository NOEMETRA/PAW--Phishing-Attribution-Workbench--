"""Snapshot byte/permission/containment checks using private owned files only."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vm_release_contract as contract
import vm_release_storage as storage
from test_vm_release_contract import fixture


class SnapshotStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.parent = Path(self.tmp.name)
        self.policy, self.proof = fixture(); self.release = self.proof['merge_sha']
        self.root = self.parent/self.release; self.root.mkdir(mode=0o700)
        self.source = self.root/'paw/core/owned.py'; self.source.parent.mkdir(parents=True)
        for directory in [self.root/'paw', self.source.parent]: directory.chmod(0o700)
        data = b'VALUE = 1\n'; self.source.write_bytes(data); self.source.chmod(0o444)
        proof_raw = storage.canonical(self.proof)
        self.value = {'schema': 'paw-vm-root-snapshot-v1', 'repository': contract.REPOSITORY,
                      'release_sha': self.release, 'head_sha': self.proof['head_sha'],
                      'proof_sha256': hashlib.sha256(proof_raw).hexdigest(),
                      'files': {'paw/core/owned.py': {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}}}
        self.raw = storage.canonical(self.value); self.digest = hashlib.sha256(self.raw).hexdigest()
        for name, raw in [('release.json', self.raw), ('proof.json', proof_raw)]:
            (self.root/name).write_bytes(raw); (self.root/name).chmod(0o444)
        self.fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        # Production always requires UID0. The inert fixture owns no root paths.
        self.owner = patch.object(storage, 'ROOT_UID', os.getuid()); self.owner.start()

    def tearDown(self):
        self.owner.stop(); os.close(self.fd); self.tmp.cleanup()

    def verify(self): return storage.verify(self.fd, self.release, self.digest)

    def replace(self, path, raw): path.chmod(0o600); path.write_bytes(raw); path.chmod(0o444)

    def test_exact_readonly_snapshot_returns_proof_without_executing_source(self):
        value, proof = self.verify(); self.assertEqual(value, self.value)
        self.assertEqual(proof, self.proof)
        self.assertEqual(contract.release(proof, self.policy, 1000, now=200)['release_sha'], self.release)
        self.assertEqual(self.source.read_bytes(), b'VALUE = 1\n')

    def test_user_writable_code_or_group_writable_directory_refuses(self):
        for path, mode in [(self.source, 0o644), (self.source.parent, 0o775)]:
            old = path.stat().st_mode & 0o777; path.chmod(mode)
            try:
                with self.subTest(path=path.name), self.assertRaises(ValueError): self.verify()
            finally: path.chmod(old)

    def test_foreign_owner_and_untrusted_parent_refuse(self):
        with patch.object(storage, 'ROOT_UID', os.getuid()+1), self.assertRaises(ValueError): self.verify()
        self.parent.chmod(0o777)
        with self.assertRaises(ValueError): self.verify()
        self.parent.chmod(0o700)

    def test_changed_manifest_proof_or_same_length_source_refuses(self):
        for path, raw in [(self.root/'release.json', self.raw+b' '),
                          (self.root/'proof.json', b'{}'), (self.source, b'VALUE = 2\n')]:
            original = path.read_bytes(); self.replace(path, raw)
            try:
                with self.subTest(name=path.name), self.assertRaises(ValueError): self.verify()
            finally: self.replace(path, original)

    def test_extra_file_empty_directory_or_missing_source_refuses(self):
        extra = self.root/'extra.py'; extra.write_bytes(b'opaque'); extra.chmod(0o444)
        with self.assertRaises(ValueError): self.verify()
        extra.unlink(); extra.mkdir()
        with self.assertRaises(ValueError): self.verify()
        extra.rmdir(); self.source.unlink()
        with self.assertRaises(ValueError): self.verify()

    def test_source_symlink_and_intermediate_symlink_refuse(self):
        self.source.unlink(); outside = self.parent/'outside.py'; outside.write_bytes(b'VALUE = 1\n'); outside.chmod(0o444)
        self.source.symlink_to(outside)
        with self.assertRaises((ValueError, OSError)): self.verify()
        self.source.unlink(); self.source.parent.rmdir(); self.source.parent.symlink_to(self.parent)
        with self.assertRaises((ValueError, OSError)): self.verify()

    def test_hardlink_and_fifo_cannot_enter_a_source_snapshot(self):
        outside = self.parent/'outside.py'; outside.write_bytes(self.source.read_bytes()); outside.chmod(0o444)
        self.source.unlink(); os.link(outside, self.source)
        with self.assertRaises(ValueError): self.verify()
        self.source.unlink(); os.mkfifo(self.source)
        with self.assertRaises(ValueError): self.verify()

    def test_release_selection_has_no_arbitrary_path_or_short_identifier(self):
        for name in ['../release', '/tmp/code', 'c'*10, 'c'*40+'/more', True]:
            with self.subTest(name=name), self.assertRaises(ValueError): storage.verify(self.fd, name, self.digest)

    def test_manifest_paths_types_expansion_and_duplicates_refuse(self):
        for path in ['../outside.py', '/root/file.py', 'paw/../file.py', 'paw//file.py',
                     'paw/core/file.py\0', 'paw\\core\\file.py', 'paw/core/payload.bin', 'lab/s14/a.py/../b.py']:
            changed = copy.deepcopy(self.value); changed['files'] = {path: next(iter(changed['files'].values()))}
            with self.subTest(path=path), self.assertRaises(ValueError): storage.manifest(storage.canonical(changed), self.release)
        for item in [{'bytes': True, 'sha256': 'a'*64}, {'bytes': storage.MAX_FILE+1, 'sha256': 'a'*64}]:
            changed = copy.deepcopy(self.value); changed['files']['paw/core/owned.py'] = item
            with self.assertRaises(ValueError): storage.manifest(storage.canonical(changed), self.release)
        with self.assertRaises(ValueError): storage.manifest(b'{"files":{},"files":{}}', self.release)

    def test_manifest_cannot_change_release_repository_or_add_execution_arguments(self):
        for key, value in [('repository', 'other/repo'), ('release_sha', 'e'*40), ('command', '/bin/sh')]:
            changed = copy.deepcopy(self.value); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): storage.manifest(storage.canonical(changed), self.release)


if __name__ == '__main__': unittest.main()
