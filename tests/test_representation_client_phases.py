"""Actual owned PAW preparation/refresh plus inert trusted-reader collection."""
import importlib.util
from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(REPO), str(REPO/'tests')]
sys.path.insert(0, str(REPO/"lab/s14"))
import representation_owned_inputs as client
import representation_producer as producer
from paw.core import representation_bridge as bridge
from paw.core.verify import verify_case
from test_representation_bridge import receipt_for


class Phases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.workspace = self.root/'client'
        self.nonce = '1122334455667788'
        self.prepared = client.prepare(self.workspace, self.nonce, REPO, 'python')

    def tearDown(self): self.tmp.cleanup()

    def test_all_seven_slots_get_distinct_fresh_requests_and_preserve_originals(self):
        requests = []
        for slot in sorted(client.SLOTS):
            value = client.next_request(self.workspace, self.nonce, 'python', slot, REPO)
            self.assertEqual(value['result'], 'PASS'); self.assertTrue(value['original_case_unchanged'])
            raw = (self.workspace/'slots'/slot/'request.json').read_bytes(); request = bridge.validate_request(raw)
            requests.append(request['candidate']['request_id'])
        self.assertEqual(len(set(requests)), 7)
        self.assertEqual(len(self.prepared['cases']), 3)
        for row in self.prepared['cases']: self.assertEqual(client.inventory(Path(row['case'])), row['case_inventory'])

    def test_inert_root_reader_receipt_collects_into_a_separate_real_sealed_sidecar(self):
        client.next_request(self.workspace, self.nonce, 'python', 'smoke', REPO)
        request_path = self.workspace/'slots/smoke/request.json'; raw = request_path.read_bytes(); request = bridge.validate_request(raw)
        export = self.root/'inert-export'; export.mkdir(mode=0o700)
        receipt = receipt_for(request, raw)
        (export/'receipt.json').write_bytes(bridge.canonical(receipt)); (export/'request.json').write_bytes(raw)
        (export/'artifact-00.bin').write_bytes(b'out')
        @contextmanager
        def trusted(identifier):
            self.assertEqual(identifier, request['candidate']['request_id'])
            fd = os.open(export, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        # This explicitly substitutes Root provenance/reader ownership only;
        # it is a transport/seal test, never KVM or readiness acceptance.
        original = bridge.shared._read_regular
        def regular(*args, **kwargs):
            kwargs.pop('root_owned', None); return original(*args, **kwargs)
        with mock.patch.object(bridge, 'trusted_export', trusted), mock.patch.object(bridge.shared, '_read_regular', side_effect=regular):
            value = client.next_request(self.workspace, self.nonce, 'python', 'smoke', REPO, collect=True)
        self.assertEqual(value['phase'], 'import'); self.assertTrue(value['original_case_unchanged'])
        with redirect_stdout(io.StringIO()): self.assertTrue(verify_case(self.workspace/'sidecar-smoke/result'))
        for row in self.prepared['cases']: self.assertEqual(client.inventory(Path(row['case'])), row['case_inventory'])

    def test_wrong_nonce_changed_original_and_duplicate_slot_refuse(self):
        with self.assertRaisesRegex(ValueError, 'owned_client_prepared_context'):
            client.next_request(self.workspace, '0'*16, 'python', 'positive', REPO)
        client.next_request(self.workspace, self.nonce, 'python', 'positive', REPO)
        with self.assertRaises(ValueError): client.next_request(self.workspace, self.nonce, 'python', 'positive', REPO)
        original = self.workspace/'python-prefix.bin'; original.chmod(0o600); original.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'owned_client_prepared_case_changed'):
            client.next_request(self.workspace, self.nonce, 'python', 'owner-loss', REPO)

    def test_root_handoff_independently_matches_actual_parent_files_and_fixed_bytes(self):
        client.next_request(self.workspace, self.nonce, 'python', 'prefix', REPO)
        # Substitute only the fixed Root workspace location. Request/schema,
        # owned byte oracle, no-follow file reads and parent hashes are real.
        with mock.patch.object(producer, 'client_command', return_value={'workspace': self.workspace}):
            raw, case, before = producer.owned_request('a'*32, self.nonce, 'python', 'source', 'prefix')
            self.assertEqual(raw, (self.workspace/'slots/prefix/request.json').read_bytes())
            self.assertEqual(before, client.inventory(case))
            manifest = case/'manifest.json'; manifest.chmod(0o600); manifest.write_bytes(b'changed parent manifest')
            with self.assertRaisesRegex(ValueError, 'owned_representation_actual_parent_files'):
                producer.owned_request('a'*32, self.nonce, 'python', 'source', 'prefix')


if __name__ == '__main__': unittest.main()
