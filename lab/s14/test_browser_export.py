"""Owned descriptor/permission regression; no root, polkit, VM or network."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import reader_export as export


class ReaderExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.base = Path(self.tmp.name)
        self.tree = self.base/'export'; self.tree.mkdir(mode=0o700)
        (self.tree/'nested').mkdir(mode=0o700); (self.tree/'nested'/'audit').write_bytes(b'owned evidence')
        (self.tree/'nested'/'audit').chmod(0o600)
        self.outside = self.base/'canary'; self.outside.write_bytes(b'outside untouched')
        self.original_open = os.open
        def root(path, flags, *args, **kwargs):
            # Only filesystem root is virtualized into this owned private test tree.
            return self.original_open(self.base if path == '/' else path, flags, *args, **kwargs)
        self.patchers = [patch.object(export, 'ROOT_UID', os.getuid()), patch.object(export.os, 'open', root)]
        for p in self.patchers: p.start()

    def tearDown(self):
        for p in reversed(self.patchers): p.stop()
        self.tmp.cleanup()

    def test_tree_stays_private_until_last_operation_and_is_never_user_writable(self):
        operations = []; original = os.fchmod
        def observed(fd, mode):
            operations.append((os.fstat(fd).st_ino, mode))
            if len(operations) > 1: self.assertEqual(stat.S_IMODE(self.tree.stat().st_mode), 0o700)
            original(fd, mode)
        with patch.object(export.os, 'fchmod', observed), patch.object(export.os, 'chown') as path_chown:
            export.publish_reader_tree(Path('/export'), os.getgid())
        path_chown.assert_not_called()
        self.assertEqual(operations[-1], (self.tree.stat().st_ino, 0o750))
        self.assertEqual(stat.S_IMODE((self.tree/'nested'/'audit').stat().st_mode), 0o440)
        for path in [self.tree, *self.tree.rglob('*')]:
            self.assertEqual(path.stat().st_uid, os.getuid()); self.assertFalse(path.stat().st_mode & 0o022)
        self.assertEqual(self.outside.read_bytes(), b'outside untouched')

    def test_symlink_hardlink_fifo_and_writable_inode_refuse_without_publishing(self):
        for kind in ['symlink', 'hardlink', 'fifo', 'writable']:
            path = self.tree/'unexpected'
            if kind == 'symlink': path.symlink_to(self.outside)
            elif kind == 'hardlink': os.link(self.outside, path)
            elif kind == 'fifo': os.mkfifo(path)
            else: path.write_bytes(b'owned'); path.chmod(0o666)
            with self.subTest(kind=kind), self.assertRaises(ValueError): export.publish_reader_tree(Path('/export'), os.getgid())
            self.assertEqual(stat.S_IMODE(self.tree.stat().st_mode), 0o700)
            self.assertEqual(self.outside.read_bytes(), b'outside untouched'); path.unlink()

    def test_substituted_child_is_never_followed(self):
        original = export.os.stat; replaced = False
        def switch(name, *args, **kwargs):
            nonlocal replaced
            value = original(name, *args, **kwargs)
            if name == 'audit' and kwargs.get('dir_fd') is not None and not replaced:
                replaced = True; path = self.tree/'nested'/'audit'; path.unlink(); path.symlink_to(self.outside)
            return value
        with patch.object(export.os, 'stat', switch), self.assertRaises(OSError):
            export.publish_reader_tree(Path('/export'), os.getgid())
        self.assertTrue(replaced); self.assertEqual(stat.S_IMODE(self.tree.stat().st_mode), 0o700)
        self.assertEqual(self.outside.read_bytes(), b'outside untouched')

    def test_writable_parent_and_already_visible_export_refuse(self):
        self.base.chmod(0o777)
        with self.assertRaises(ValueError): export.publish_reader_tree(Path('/export'), os.getgid())
        self.base.chmod(0o700); self.tree.chmod(0o750)
        with self.assertRaises(ValueError): export.publish_reader_tree(Path('/export'), os.getgid())


if __name__ == '__main__': unittest.main()
