"""Actual harmless owner interpreter: snapshot inventory must not change."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lab/s14'))
import synthetic_gate as gate
import vm_release_storage as storage


@unittest.skipUnless(os.name == 'posix' and Path('/usr/bin/python3').exists(), 'Linux owner interpreter')
class OwnerSnapshot(unittest.TestCase):
    def exercise(self, old=False):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory); release='a'*40; root=parent/release
            lab=root/'lab/s14'; lab.mkdir(parents=True)
            script=lab/'owned_owner.py'
            script.write_text('import sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).parent))\nimport owned_dependency\n')
            (lab/'owned_dependency.py').write_text('VALUE=1\n')
            files={str(p.relative_to(root)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                   for p in lab.iterdir()}
            proof=storage.canonical({'repository':storage.REPOSITORY,'head_sha':'b'*40,'merge_sha':release})
            manifest=storage.canonical({'schema':'paw-vm-root-snapshot-v1','repository':storage.REPOSITORY,
                'head_sha':'b'*40,'release_sha':release,'proof_sha256':hashlib.sha256(proof).hexdigest(),'files':files})
            (root/'release.json').write_bytes(manifest); (root/'proof.json').write_bytes(proof)
            root.chmod(0o700)
            for p in root.rglob('*'): p.chmod(0o700 if p.is_dir() else 0o444)
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                with mock.patch.object(storage,'ROOT_UID',os.getuid()):
                    storage.verify(fd,release,hashlib.sha256(manifest).hexdigest())
                    with mock.patch.object(gate,'__file__',str(script)):
                        argv=gate.owner_command(lab/'unused.json')
                    if old: argv.remove('-B')
                    # Match the fixed Root service's0077 inheritance. Ordinary
                    # UID substitutes directory ownership, never VM or Root work.
                    result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,
                        preexec_fn=lambda:os.umask(0o077),timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr)
                    if old:
                        with self.assertRaisesRegex(ValueError,'snapshot_exact_inventory'):
                            storage.verify(fd,release,hashlib.sha256(manifest).hexdigest())
                        self.assertTrue(list(root.rglob('*.pyc')))
                    else:
                        checked,_=storage.verify(fd,release,hashlib.sha256(manifest).hexdigest())
                        self.assertEqual(checked['files'],files);self.assertFalse(list(root.rglob('__pycache__')))
                    for name,row in files.items():
                        self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),row['sha256'])
            finally:os.close(fd)

    def test_old_isolated_invocation_reproduces_exact_inventory_refusal(self):self.exercise(old=True)
    def test_fixed_owner_invocation_keeps_actual_snapshot_exact(self):self.exercise()


if __name__=='__main__':unittest.main()
