"""Real maximum-size PAW byte custody; Root transport substituted, no JS runs."""
from contextlib import contextmanager, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14'), str(REPO/'tests')]
import representation_owned_inputs as client
import representation_producer as producer
from paw.core import representation_bridge as bridge
from paw.core.javascript_representation_observer import browser_bytes
from paw.core.verify import verify_case
from test_representation_bridge import receipt_for


class Javascript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.workspace = self.root/'client'
        self.nonce = '1122334455667788'; self.entry = client.javascript_fixture(self.nonce)
        self.prepared = client.prepare(self.workspace, self.nonce, REPO, 'javascript')
        client.next_request(self.workspace, self.nonce, 'javascript', 'smoke', REPO)
        self.raw = (self.workspace/'slots/smoke/request.json').read_bytes()

    def tearDown(self): self.tmp.cleanup()

    def test_full_size_owned_bytes_and_actual_parent_match_root_regeneration(self):
        self.assertEqual(len(self.entry['original']), 256*1024)
        self.assertEqual(len(self.entry['selected']), 349676)
        self.assertEqual(browser_bytes(self.entry['original']), self.entry['selected'])
        self.assertEqual(len(self.prepared['cases']), 1)
        request = client.validate_owned(self.raw, self.entry, bridge)
        self.assertEqual(request['candidate']['profile'], producer.adapter.HTML)
        with mock.patch.object(producer, 'client_command', return_value={'workspace': self.workspace}):
            raw, parent, before = producer.owned_request('a'*32, self.nonce, 'javascript', 'source', 'smoke')
            self.assertEqual(raw, self.raw); self.assertEqual(before, client.inventory(parent))
            self.assertEqual((parent/'source.bin').read_bytes(), self.entry['original'])
            with self.assertRaises(ValueError): producer.owned_request('a'*32, '0'*16, 'javascript', 'source', 'smoke')
        self.assertFalse(self.prepared['vm_started']); self.assertFalse(self.prepared['execution_authorized'])

    def test_other_slots_and_duplicate_requests_refuse(self):
        for slot in sorted(client.SLOTS):
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                client.next_request(self.workspace, self.nonce, 'javascript', slot, REPO)
        for nonce in ['x'*16, 'a'*15, 'b'*17, '../escape']:
            with self.subTest(nonce=nonce), self.assertRaises(ValueError): client.javascript_fixture(nonce)

    def test_self_consistent_but_different_transform_cannot_get_owned_authority(self):
        original = bridge.validate_request(self.raw)
        for field, changed in [('environment', 'nodejs'), ('errors', 'replace'), ('source_sha256', '0'*64)]:
            value = copy.deepcopy(original); selected = value['binding']['derivation']['nodes'][-1]
            selected['transform']['parameters'][field] = changed
            selected['id'] = bridge.digest(bridge.node_canonical({k: v for k, v in selected.items() if k not in {'id', 'blob_path'}}))
            value['binding']['derivation']['selected'] = selected['id']
            value['candidate']['selection_binding_sha256'] = bridge.digest(bridge.canonical(value['binding']))
            raw = bridge.canonical(value)
            bridge.validate_request(raw)  # Generic custody deliberately permits other explicit derivations.
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'owned_javascript_exact_derivation'):
                client.validate_owned(raw, self.entry, bridge)

    def test_actual_import_seals_sidecar_and_preserves_exact_original(self):
        request = bridge.validate_request(self.raw); export = self.root/'inert-export'; export.mkdir(mode=0o700)
        (export/'request.json').write_bytes(self.raw)
        (export/'receipt.json').write_bytes(bridge.canonical(receipt_for(request, self.raw)))
        (export/'artifact-00.bin').write_bytes(b'out')
        @contextmanager
        def trusted(identifier):
            self.assertEqual(identifier, request['candidate']['request_id'])
            fd = os.open(export, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: yield fd
            finally: os.close(fd)
        regular_read = bridge.shared._read_regular
        def regular(*args, **kwargs):
            kwargs.pop('root_owned', None); return regular_read(*args, **kwargs)
        # Root provenance only is substituted; actual request/receipt/bytes and
        # seal validators run. This is not VM or browser acceptance.
        with mock.patch.object(bridge, 'trusted_export', trusted), mock.patch.object(bridge.shared, '_read_regular', side_effect=regular):
            value = client.next_request(self.workspace, self.nonce, 'javascript', 'smoke', REPO, collect=True)
        self.assertTrue(value['original_case_unchanged'])
        with redirect_stdout(io.StringIO()): self.assertTrue(verify_case(self.workspace/'sidecar-smoke/result'))
        for row in self.prepared['cases']: self.assertEqual(client.inventory(Path(row['case'])), row['case_inventory'])


if __name__ == '__main__': unittest.main()
