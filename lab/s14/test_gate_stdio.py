"""Actual benign child verifies the controller descriptor is not inherited."""
import json
import os
import sys
import tempfile
import unittest
from gate_guest import isolated_process


class DescriptorBoundary(unittest.TestCase):
    def test_child_cannot_read_owned_parent_control_canary(self):
        reader, writer = os.pipe(); saved = os.dup(0)
        try:
            os.write(writer, b'OWNED-CONTROL-CANARY'); os.close(writer)
            os.dup2(reader, 0); os.close(reader)
            code = 'import json,os;print(json.dumps({"stdin":os.readlink("/proc/self/fd/0"),"bytes":os.read(0,64).hex()}))'
            with tempfile.TemporaryDirectory() as directory:
                child = isolated_process([sys.executable, '-I', '-c', code], None, directory)
                stdout, stderr = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(json.loads(stdout), {'stdin': '/dev/null', 'bytes': ''})
        finally:
            os.dup2(saved, 0); os.close(saved)


if __name__ == '__main__': unittest.main()
