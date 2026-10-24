"""Sealed attachment custody, opaque receipts and refusal; no source executes."""
import copy
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock
import uuid

from paw.core import offline_bridge as bridge
from paw.core.evidence import seal_case
from paw.core.network_policy import EgressDenied
from test_synthetic_bridge import make_case, inventory


def attachment_case(root, source=b'print("owned case bridge")\n'):
    case = make_case(root); folder = case / 'attachments'; folder.mkdir()
    path = 'attachments/part-1-2-' + bridge.digest(source) + '.bin'
    (case / path).write_bytes(source)
    (case / 'attachments.json').write_text(json.dumps([{'filename': 'owned.py', 'part_id': '1.2',
        'size': len(source), 'sha256': bridge.digest(source), 'evidence_path': path, 'decoding_defects': []}]))
    seal_case(case); return case, path


def receipt_for(request, raw, status='completed'):
    frame = request['candidate']; now = frame['created_at']
    hashes = {k: '1'*64 for k in ['job_sha256', 'raw_result_sha256', 'source_inventory_sha256',
                                'policy_sha256', 'grant_sha256', 'readiness_sha256', 'consumption_sha256']}
    return {'schema': 'paw-s14-case-result-v1', 'producer_kind': 'local-root-verified-hash-offline',
        'request_id': frame['request_id'], 'request_sha256': bridge.digest(raw),
        'candidate_sha256': bridge.digest(bridge.canonical(frame)), 'binding_sha256': frame['case_reference_sha256'],
        'source_sha256': frame['source']['sha256'], 'execution_status': status,
        'runtime': {**hashes, 'bridge_contract_sha256': bridge.contract_hash(), 'vm_uuid': str(uuid.uuid4()),
            'image_sha256': bridge.shared.IMAGE_SHA256, 'source_count': 81, 'admitted_at': now,
            'completed_at': now, 'stop_seconds': .1, 'writers_stopped': True},
        'artifacts': [{'stored_as': 'artifact-00.bin', 'bytes': 3, 'sha256': bridge.digest(b'out')}]}


class OfflineBridge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.case, self.attachment = attachment_case(self.root); self.before = inventory(self.case)

    def tearDown(self): self.tmp.cleanup()

    def prepare(self):
        info = bridge.prepare(self.case, self.attachment, self.root / 'request')
        raw = Path(info['request']).read_bytes(); return bridge.validate_request(raw), raw, info

    def test_exact_attachment_frame_is_bound_to_unchanged_sealed_case_without_execution(self):
        request, raw, info = self.prepare(); frame = request['candidate']
        self.assertEqual(inventory(self.case), self.before)
        self.assertFalse(info['execution_authorized'])
        self.assertEqual(frame['source']['data_hex'], (self.case / self.attachment).read_bytes().hex())
        self.assertEqual(frame['case_reference_sha256'], bridge.digest(bridge.canonical(request['binding'])))
        self.assertEqual(Path(info['candidate']).read_bytes(), bridge.canonical(frame))

    def test_outside_paths_symlinks_special_files_and_in_case_output_refuse(self):
        for path in ['../outside.py', '/etc/passwd', 'attachments/../input.eml']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                bridge.prepare(self.case, path, self.root / 'out')
        with self.assertRaises(ValueError): bridge.prepare(self.case, self.attachment, self.case / 'out')
        self.assertEqual(inventory(self.case), self.before)

    def test_unsupported_formats_ambiguous_decoding_and_oversize_refuse(self):
        for mutation in ['html', 'decoding', 'oversize', 'nul']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); source = b'x'*16385 if mutation == 'oversize' else b'x\0' if mutation == 'nul' else b'owned'
                case, path = attachment_case(root, source); rows = json.loads((case / 'attachments.json').read_text())
                if mutation == 'html': rows[0]['filename'] = 'page.html'
                if mutation == 'decoding': rows[0]['decoding_defects'] = ['invalid-base64']
                (case / 'attachments.json').write_text(json.dumps(rows)); seal_case(case)
                with self.assertRaises(ValueError): bridge.prepare(case, path, root / 'out')
                self.assertFalse((root / 'out').exists())

    def test_live_owner_or_changed_seal_refuses_before_request(self):
        (self.root / 'jobs/analysis_ownedfixture/supervisor.json').write_text('{"tree_stopped":false}')
        with self.assertRaises(RuntimeError): bridge.prepare(self.case, self.attachment, self.root / 'out')
        self.assertFalse((self.root / 'out').exists())
        (self.root / 'jobs/analysis_ownedfixture/supervisor.json').write_text('{"tree_stopped":true}')
        (self.case / self.attachment).write_bytes(b'changed')
        with self.assertRaises(ValueError): bridge.prepare(self.case, self.attachment, self.root / 'out')

    def test_frame_binding_ids_hash_clock_and_contract_mutations_refuse(self):
        request, raw, _ = self.prepare()
        for mutation in ['parent', 'contract', 'source', 'id', 'clock']:
            value = copy.deepcopy(request)
            if mutation == 'parent': value['candidate']['case_reference_sha256'] = '0'*64
            elif mutation == 'contract': value['binding']['bridge_contract_sha256'] = '0'*64
            elif mutation == 'source': value['candidate']['source']['data_hex'] = '00'
            elif mutation == 'id': value['candidate']['request_id'] = '../escape'
            else: value['candidate']['created_at'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): bridge.validate_request(bridge.canonical(value))
        with self.assertRaises(ValueError): bridge.validate_request(b'{"schema":1,"schema":2}')

    def test_generic_receipt_retains_failed_timeout_and_cancelled_without_risk_verdict(self):
        request, raw, _ = self.prepare()
        for status in sorted(bridge.STATUSES):
            receipt = receipt_for(request, raw, status)
            self.assertEqual(bridge.validate_receipt(bridge.canonical(receipt), request, bridge.digest(raw))['execution_status'], status)
        for field, changed in [('writers_stopped', False), ('stop_seconds', True), ('admitted_at', 0),
                               ('readiness_sha256', 'bad'), ('bridge_contract_sha256', '0'*64)]:
            value = receipt_for(request, raw); value['runtime'][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_receipt_cross_request_source_inventory_and_traversal_refuse(self):
        request, raw, _ = self.prepare()
        for field, changed in [('request_id', '0'*32), ('source_sha256', '0'*64), ('candidate_sha256', '0'*64),
                               ('execution_status', 'malicious')]:
            value = receipt_for(request, raw); value[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))
        value = receipt_for(request, raw); value['artifacts'][0]['stored_as'] = '../escape'
        with self.assertRaises(ValueError): bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_unprivileged_exports_cannot_claim_root_custody(self):
        request, raw, info = self.prepare(); prefix = self.root / 'exports'
        (prefix / request['candidate']['request_id']).mkdir(parents=True)
        with mock.patch.object(bridge, 'EXPORT_ROOT', prefix), self.assertRaises(ValueError):
            bridge.import_result(self.case, info['request'], self.root / 'out')
        self.assertFalse((self.root / 'out').exists()); self.assertEqual(inventory(self.case), self.before)

    def test_local_api_always_enters_offline_policy(self):
        with mock.patch.object(bridge.shared, '_case_reference', side_effect=lambda *a: socket.socket()):
            for operation in [lambda: bridge.prepare(self.case, self.attachment, self.root / 'out'),
                              lambda: bridge.import_result(self.case, self.root / 'request.json', self.root / 'out')]:
                with self.assertRaises(EgressDenied): operation()


if __name__ == '__main__': unittest.main()
