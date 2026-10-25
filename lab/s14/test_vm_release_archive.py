"""Owned archive attack cases; no download, root installation or execution."""
import copy
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import vm_release_archive as archive
import vm_release_storage as storage
from test_vm_release_contract import fixture


def packed(entries=None, commit='c'*40):
    prefix = 'PAW--Phishing-Attribution-Workbench---'+commit
    entries = [('paw/core/owned.py', b'VALUE = 1\n', tarfile.REGTYPE)] if entries is None else entries
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT, pax_headers={'comment': commit}) as tar:
        root = tarfile.TarInfo(prefix); root.type = tarfile.DIRTYPE; tar.addfile(root)
        for name, data, kind in entries:
            item = tarfile.TarInfo(prefix+'/'+name); item.type = kind
            if kind == tarfile.REGTYPE: item.size = len(data)
            else: item.linkname = '../../outside'
            tar.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return gzip.compress(stream.getvalue())


class ArchiveBoundary(unittest.TestCase):
    def test_opaque_sources_selected_without_extracting_other_repository_files(self):
        raw = packed([('paw/core/owned.py', b'VALUE = 1\n', tarfile.REGTYPE),
                      ('README.md', b'not executable source', tarfile.REGTYPE)])
        self.assertEqual(archive.sources(raw, 'c'*40), {'paw/core/owned.py': b'VALUE = 1\n'})

    def test_traversal_backslash_absolute_alias_and_duplicates_refuse(self):
        for name in ['../escape.py', 'paw/../../escape.py', 'paw\\core\\owned.py', 'paw//core/owned.py']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive.sources(packed([(name, b'data', tarfile.REGTYPE)]), 'c'*40)
        with self.assertRaises(ValueError):
            archive.sources(packed([('README.md', b'a', tarfile.REGTYPE), ('README.md', b'b', tarfile.REGTYPE)]), 'c'*40)

    def test_links_and_special_files_refuse_even_when_not_selected_for_install(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                archive.sources(packed([('docs/ignored', b'', kind)]), 'c'*40)

    def test_commit_mismatch_no_sources_corrupt_and_expansion_budget_refuse(self):
        with self.assertRaises(ValueError): archive.sources(packed(), 'e'*40)
        with self.assertRaises(ValueError): archive.sources(packed([('README.md', b'x', tarfile.REGTYPE)]), 'c'*40)
        with self.assertRaises(ValueError): archive.sources(b'not gzip', 'c'*40)
        with patch.object(archive, 'MAX_EXPANDED', 1024), self.assertRaises(ValueError): archive.sources(packed(), 'c'*40)
        with patch.object(archive, 'MAX_COMPRESSED', 1), self.assertRaises(ValueError): archive.sources(packed(), 'c'*40)

    def test_selected_source_and_member_count_budgets_refuse(self):
        with patch.object(storage, 'MAX_FILE', 1), self.assertRaises(ValueError): archive.sources(packed(), 'c'*40)
        with patch.object(archive, 'MAX_MEMBERS', 1), self.assertRaises(ValueError): archive.sources(packed(), 'c'*40)

    def test_source_bytes_bind_to_independent_complete_commit_tree(self):
        _, proof = fixture(); data = b'VALUE = 1\n'; files = {'paw/core/owned.py': data}
        entry = {'path': 'paw/core/owned.py', 'type': 'blob', 'mode': '100644', 'size': len(data),
                 'sha': hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}
        commit = {'sha': proof['merge_sha'], 'tree': {'sha': 'e'*40}}
        tree = {'sha': 'e'*40, 'truncated': False, 'tree': [entry]}
        class Client:
            def get(self, path): return commit if '/git/commits/' in path else tree
        self.assertEqual(archive.verify_git_tree(Client(), proof, files), 'e'*40)
        for mutation in ['bytes', 'missing', 'truncated', 'mode', 'duplicate', 'tree']:
            changed = copy.deepcopy(tree); offered = dict(files)
            if mutation == 'bytes': offered['paw/core/owned.py'] = b'VALUE = 2\n'
            elif mutation == 'missing': offered.clear()
            elif mutation == 'truncated': changed['truncated'] = True
            elif mutation == 'mode': changed['tree'][0]['mode'] = '120000'
            elif mutation == 'duplicate': changed['tree'].append(dict(changed['tree'][0]))
            else: changed['sha'] = 'f'*40
            class BadClient:
                def get(self, path): return commit if '/git/commits/' in path else changed
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                archive.verify_git_tree(BadClient(), proof, offered)

    def test_root_stage_is_readonly_verified_and_never_activates_or_executes(self):
        policy, proof = fixture(); files = {'paw/core/owned.py': b'VALUE = 1\n'}
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                uid = os.getuid()
                with patch.object(storage, 'ROOT_UID', uid), patch.object(archive.os, 'geteuid', return_value=0):
                    digest = archive.stage(fd, proof, files)
                    value, stored_proof = storage.verify(fd, proof['merge_sha'], digest)
                    self.assertEqual(stored_proof, proof)
                    self.assertEqual(value['files']['paw/core/owned.py']['sha256'], hashlib.sha256(files['paw/core/owned.py']).hexdigest())
                    self.assertEqual(archive.stage(fd, proof, files), digest)
                    with self.assertRaises(ValueError): archive.stage(fd, proof, {'paw/core/owned.py': b'VALUE = 2\n'})
                self.assertEqual(sorted(os.listdir(fd)), [proof['merge_sha']])
                self.assertFalse((Path(folder)/'active.json').exists())
            finally: os.close(fd)

    def test_write_api_refuses_unprivileged_role_or_untrusted_sources(self):
        policy, proof = fixture()
        with patch.object(archive.os, 'geteuid', return_value=1000), self.assertRaises(ValueError):
            archive.stage(-1, proof, {'paw/core/owned.py': b'x'})

    def test_failed_stage_leaves_no_published_or_partial_release(self):
        policy, proof = fixture()
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(storage, 'ROOT_UID', os.getuid()), patch.object(archive.os, 'geteuid', return_value=0), \
                     patch.object(archive, '_write', side_effect=OSError('owned disk failure')):
                    with self.assertRaises(OSError): archive.stage(fd, proof, {'paw/core/owned.py': b'x'})
                self.assertEqual(os.listdir(fd), [])
            finally: os.close(fd)


if __name__ == '__main__': unittest.main()
