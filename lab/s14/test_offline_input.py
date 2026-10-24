"""Inert real CLI/local API admission; never starts guests or executes input."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

from offline_input import MAX_FRAME, admit, decode
from offline_input_matrix import authorize, job


class Admission(unittest.TestCase):
    def test_cli_and_local_api_agree_without_executing_input(self):
        value = job('success'); expected = admit(value)
        result = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('offline_input.py')), '--validate-stdin'],
                                input=json.dumps(value).encode(), capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['job_sha256'], expected['job_sha256'])
        value['source_hex'] = b'changed after admission'.hex()
        self.assertNotEqual(expected['job']['source_hex'], value['source_hex'])

    def test_schema_hash_authorization_clock_and_size_fail_closed(self):
        for key, changed in [('source_sha256', '0' * 64), ('profile', 'browser'), ('job_id', '../escape'),
                             ('operator_authorization', 'all-samples'), ('created_at', True),
                             ('expires_at', int(time.time()) - 1), ('source_hex', '00' * 16385)]:
            value = job('success'); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): admit(value)
        value = job('success'); value['mount'] = '/home'
        with self.assertRaisesRegex(ValueError, 'job_shape'): admit(value)

    def test_duplicate_keys_frame_size_and_unknown_source_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate_key'): decode(b'{"job_id":1,"job_id":2}')
        with self.assertRaisesRegex(ValueError, 'frame_budget'): decode(b' ' * (MAX_FRAME + 1))
        value = job('success'); source = b"print('another harmless source')\n"
        value.update(source_hex=source.hex(), source_sha256=hashlib.sha256(source).hexdigest())
        self.assertEqual(admit(value)['source'], source)
        with self.assertRaisesRegex(ValueError, 'synthetic_catalog_only'): authorize(value)


if __name__ == '__main__': unittest.main()
