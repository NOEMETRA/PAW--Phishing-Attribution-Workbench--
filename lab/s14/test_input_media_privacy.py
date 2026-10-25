"""Real file mode regression with inert owner-role substitution; no root/VM."""
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from hash_offline_adapter import protect_input_folder


class InputPrivacy(unittest.TestCase):
    def test_only_qemu_group_can_read_seed_and_plain_source_is_root_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);overlay=root/'overlay.qcow2';overlay.write_bytes(b'inert');overlay.chmod(0o600)
            for name in ['seed.iso','user-data','meta-data','network-config']:(root/name).write_bytes(b'owned marker, not an ISO or source execution')
            calls=[]
            with patch('hash_offline_adapter.os.geteuid',return_value=0), \
                 patch('hash_offline_adapter.pwd.getpwnam',return_value=types.SimpleNamespace(pw_gid=64055)), \
                 patch('hash_offline_adapter.os.chown',side_effect=lambda path,uid,gid:calls.append((Path(path).name,uid,gid))):
                protect_input_folder({'folder':root,'overlay':overlay})
            self.assertEqual(root.stat().st_mode&0o777,0o750)
            self.assertEqual((root/'seed.iso').stat().st_mode&0o777,0o440)
            self.assertTrue(all((root/name).stat().st_mode&0o777==0o600 for name in ['user-data','meta-data','network-config']))
            self.assertIn(('seed.iso',0,64055),calls);self.assertIn(('user-data',0,0),calls)
            self.assertFalse(any(name=='overlay.qcow2' for name,_,_ in calls))
            self.assertEqual(overlay.stat().st_mode&0o777,0o600)

    def test_no_unprivileged_production_option_or_symlink_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);overlay=root/'overlay.qcow2';overlay.write_bytes(b'inert')
            with patch('hash_offline_adapter.os.geteuid',return_value=1000),self.assertRaises(ValueError):
                protect_input_folder({'folder':root,'overlay':overlay})
            (root/'seed.iso').symlink_to(overlay)
            with patch('hash_offline_adapter.os.geteuid',return_value=0), \
                 patch('hash_offline_adapter.pwd.getpwnam',return_value=types.SimpleNamespace(pw_gid=64055)), \
                 patch('hash_offline_adapter.os.chown'),self.assertRaises(ValueError):
                protect_input_folder({'folder':root,'overlay':overlay})


if __name__=='__main__':unittest.main()
