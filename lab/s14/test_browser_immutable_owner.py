"""Actual owner help imports on owned source copies; no libvirt or VM starts."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import browser_vm as browser


class ImmutableOwner(unittest.TestCase):
    def test_real_owner_child_leaves_exact_source_inventory_unchanged(self):
        original = Path(browser.__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for source in [*(original/'paw').rglob('*.py'), *(original/'lab/s14').glob('*.py')]:
                path = root/source.relative_to(original); path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.read_bytes()); path.chmod(0o444)
            def inventory():
                return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in root.rglob('*') if p.is_file()}
            before = inventory()
            with patch.object(browser, '__file__', str(root/'lab/s14/browser_vm.py')):
                argv = browser.owner_command(Path('/var/lib/paw-s14/control/owned/config.json'))
            self.assertEqual(argv[:3], ['/usr/bin/python3', '-I', '-B'])
            # Help takes the same real import path as the owner, without
            # invoking owner(), importing libvirt or opening a VM connection.
            child = subprocess.run([sys.executable, *argv[1:-2], '--help'], capture_output=True, text=True,
                                   env=dict(os.environ, PYTHONDONTWRITEBYTECODE='0'), timeout=15)
            self.assertEqual(child.returncode, 0, child.stderr)
            self.assertEqual(inventory(), before); self.assertEqual(list(root.rglob('__pycache__')), [])


if __name__ == '__main__': unittest.main()
