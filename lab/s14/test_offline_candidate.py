"""Inert untrusted-input checks; no root, guest, networking or payload execution."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from offline_candidate import MAX_FRAME, MAX_SOURCE, canonical, inspect_candidate
from offline_input_matrix import authorize, job


def candidate(content=b"print('owned noncatalog review fixture')\n"):
    now = int(time.time())
    return {'schema': 'paw-s14-offline-candidate-v1', 'profile': 'linux-python-offline-v1',
            'request_id': 'a' * 32, 'case_reference_sha256': 'b' * 64,
            'source': {'media_type': 'text/x-python', 'encoding': 'utf-8',
                       'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'data_hex': content.hex()},
            'provenance': {'kind': 'operator-supplied', 'reference': 'Owned local inert review fixture'},
            'created_at': now, 'expires_at': now + 900, 'purpose': 'offline-single-job-review'}


class CandidateBoundary(unittest.TestCase):
    def test_real_cli_never_executes_source_or_authorizes_runtime(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / 'must-not-exist'
            content = ('from pathlib import Path\nPath(' + repr(str(marker)) + ").write_text('unexpected')\n").encode()
            raw = canonical(candidate(content))
            result = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('offline_candidate.py')), '--inspect-stdin'],
                                    input=raw, capture_output=True, timeout=4)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            self.assertFalse(value['execution_authorized']); self.assertEqual(value['runtime_adapter'], 'unavailable')
            self.assertEqual(value['source_sha256'], hashlib.sha256(content).hexdigest())
            self.assertEqual(value['frame_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertNotIn('source', value); self.assertFalse(marker.exists())

    def test_digest_binds_parent_source_provenance_and_exact_frame(self):
        value = candidate(); before = inspect_candidate(canonical(value))
        for key, changed in [('case_reference_sha256', 'c' * 64), ('request_id', 'd' * 32),
                             ('provenance', {'kind': 'operator-supplied', 'reference': 'Other claim'})]:
            other = copy.deepcopy(value); other[key] = changed
            self.assertNotEqual(inspect_candidate(canonical(other))['candidate_sha256'], before['candidate_sha256'])
        pretty = json.dumps(value, indent=2).encode(); after = inspect_candidate(pretty)
        self.assertEqual(before['candidate_sha256'], after['candidate_sha256'])
        self.assertNotEqual(before['frame_sha256'], after['frame_sha256'])

    def test_scope_extra_fields_ids_and_claims_refuse(self):
        for key, changed in [('profile', 'browser'), ('schema', 'paw-s14-synthetic-request-v1'),
                             ('request_id', '../job'), ('case_reference_sha256', 'a'),
                             ('purpose', 'execute-now'), ('execution_authorized', True),
                             ('provenance', {'kind': 'verified', 'reference': 'claim'}),
                             ('provenance', {'kind': 'operator-supplied', 'reference': '\nforged'}),
                             ('provenance', {'kind': 'operator-supplied', 'reference': 'x' * 257}),
                             ('provenance', {'kind': 'operator-supplied', 'reference': '   '})]:
            value = candidate(); value[key] = changed
            with self.subTest(key=key, changed=changed), self.assertRaises(ValueError): inspect_candidate(canonical(value))

    def test_lease_strict_types_future_expiry_and_boundaries(self):
        value = candidate(); now = value['created_at']
        self.assertEqual(inspect_candidate(canonical(value), now=now)['status'], 'valid-review-candidate')
        for key, changed in [('created_at', True), ('created_at', now + 1), ('expires_at', now),
                             ('expires_at', now + 901), ('expires_at', 1.0)]:
            other = copy.deepcopy(value); other[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): inspect_candidate(canonical(other), now=now)
        with self.assertRaisesRegex(ValueError, 'expired'): inspect_candidate(canonical(value), now=now + 900)

    def test_bytes_hash_utf8_nul_size_and_type_fail_closed(self):
        for key, changed in [('bytes', True), ('bytes', 0), ('bytes', MAX_SOURCE + 1),
                             ('data_hex', '00'), ('data_hex', 'AA'), ('sha256', '0' * 64),
                             ('encoding', 'latin-1'), ('media_type', 'application/x-executable'), ('path', '/tmp/file')]:
            value = candidate(); value['source'][key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): inspect_candidate(canonical(value))
        for content in [b'\xff', b'a\0b']:
            with self.subTest(content=content), self.assertRaises(ValueError): inspect_candidate(canonical(candidate(content)))
        self.assertEqual(inspect_candidate(canonical(candidate(b'#' * MAX_SOURCE)))['source_bytes'], MAX_SOURCE)

    def test_malformed_duplicate_nonfinite_oversized_and_deep_json_refuse(self):
        for raw in [b'{"source":1,"source":2}', b'{"x":NaN}', b'{"x":Infinity}', b'[]', b'{', b'\xff',
                    b' ' * (MAX_FRAME + 1), b'[' * 2000 + b']' * 2000]:
            with self.subTest(prefix=raw[:25]), self.assertRaises(ValueError): inspect_candidate(raw)

    def test_old_runtime_catalog_still_refuses_noncatalog_and_new_schema(self):
        value = candidate(); source = bytes.fromhex(value['source']['data_hex']); old = job('success')
        old.update(source_hex=source.hex(), source_sha256=hashlib.sha256(source).hexdigest())
        self.assertFalse(inspect_candidate(canonical(value))['execution_authorized'])
        with self.assertRaisesRegex(ValueError, 'synthetic_catalog_only'): authorize(old)
        with self.assertRaisesRegex(ValueError, 'job_shape'): authorize(value)

    def test_cli_refuses_invalid_frame_with_json_and_nonzero_exit(self):
        result = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('offline_candidate.py')), '--inspect-stdin'],
                                input=b'{"execution_authorized":true}', capture_output=True, timeout=4)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)['execution_authorized'])
        self.assertEqual(json.loads(result.stdout)['status'], 'refused')


if __name__ == '__main__':
    unittest.main()
