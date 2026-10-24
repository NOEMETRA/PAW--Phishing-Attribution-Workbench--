"""Case/linkage and local-producer trust; no VM, URL or sample execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

from paw.core import synthetic_bridge as bridge
from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.network_policy import EgressDenied


def make_case(root):
    case = root / 'cases/case-ownedfixture'; case.mkdir(parents=True)
    owner = 'analysis_ownedfixture'
    (case / 'manifest.json').write_text(json.dumps({'analysis_job': owner, 'scope': 'constructed inert unit fixture'}))
    (case / 'execution.json').write_text(json.dumps({'status': 'completed'}))
    (case / 'original.eml').write_bytes(b'From: owner@fixture.invalid\r\nSubject: owned fixture\r\n\r\nInert.\r\n')
    jobs = root / 'jobs'; (jobs / owner).mkdir(parents=True)
    (jobs / (owner + '.json')).write_text(json.dumps({'origin': 'cli', 'status': 'completed'}))
    (jobs / owner / 'supervisor.json').write_text(json.dumps({'tree_stopped': True}))
    seal_case(case)
    return case


def inventory(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}


def receipt_for(request, raw):
    return {'schema': 'paw-s14-synthetic-result-v1', 'request_id': request['request_id'], 'request_sha256': bridge.digest(raw),
            'case_reference_sha256': request['case_reference_sha256'], 'profile': bridge.PROFILE,
            'fixture_sha256': bridge.FIXTURE_SHA256, 'producer_kind': 'local-root-verified-no-nic-synthetic',
            'status': 'completed', 'raw_result_sha256': bridge.digest(b'inert test witness, not KVM evidence'),
            'runtime': {'vm_uuid': str(uuid.uuid4()), 'job_sha256': '1' * 64, 'image_sha256': bridge.IMAGE_SHA256,
                        'source_inventory_sha256': '2' * 64, 'bridge_contract_sha256': bridge.digest(Path(bridge.__file__).read_bytes()),
                        'source_count': 61, 'started_at': request['created_at'], 'completed_at': request['created_at'],
                        'stop_seconds': .5, 'writers_stopped': True},
            'artifacts': [{'stored_as': f'artifact-{i:02d}.bin', 'bytes': len(data), 'sha256': bridge.digest(data)}
                          for i, data in enumerate([bridge.MARKER, b''])]}


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only local-root bridge')
class SyntheticBridge(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name); self.case = make_case(self.root)
        self.before = inventory(self.case)

    def tearDown(self): self.temp.cleanup()

    def request(self):
        value = bridge.prepare(self.case, self.root / 'request')
        raw = Path(value['request']).read_bytes()
        return bridge.validate_request(raw), raw

    def test_prepare_preserves_every_case_byte_and_contains_no_source_or_target(self):
        request, raw = self.request()
        self.assertEqual(inventory(self.case), self.before)
        self.assertTrue(verify_case(self.case))
        self.assertEqual(request['fixture_sha256'], bridge.FIXTURE_SHA256)
        self.assertEqual(request['case_reference_sha256'], bridge.digest(bridge.canonical(request['case_reference'])))
        for key in ['source_hex', 'url', 'command', 'path']: self.assertNotIn(key, request)

    def test_live_or_unknown_case_owner_refuses_before_creating_request(self):
        supervisor = self.root / 'jobs/analysis_ownedfixture/supervisor.json'
        for stopped in [False, None]:
            supervisor.write_text(json.dumps({'tree_stopped': stopped}))
            with self.subTest(stopped=stopped), self.assertRaisesRegex(RuntimeError, 'shutdown not confirmed'):
                bridge.prepare(self.case, self.root / 'out')
            self.assertFalse((self.root / 'out').exists())
        self.assertEqual(inventory(self.case), self.before)

    def test_changed_case_or_invalid_seal_refuses_without_resealing(self):
        (self.case / 'original.eml').write_bytes(b'changed after sealing')
        before = inventory(self.case)
        with self.assertRaisesRegex(ValueError, 'seal_invalid'): bridge.prepare(self.case, self.root / 'out')
        self.assertEqual(inventory(self.case), before); self.assertFalse((self.root / 'out').exists())

    def test_output_must_be_new_and_outside_original_case(self):
        for output in [self.case / 'lab', self.case, self.root]:
            with self.subTest(output=output), self.assertRaises(ValueError): bridge.prepare(self.case, output)
        self.assertEqual(inventory(self.case), self.before)

    def test_request_rejects_code_url_duplicate_keys_bad_scope_clock_and_parent(self):
        request, raw = self.request()
        mutations = [('source_hex', '7072696e74283129'), ('url', 'https://fixture.invalid/'), ('profile', 'browser'),
                     ('fixture_sha256', '0' * 64), ('created_at', True), ('expires_at', 0),
                     ('case_reference_sha256', '0' * 64), ('request_id', '../escape')]
        for key, changed in mutations:
            value = copy.deepcopy(request); value[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): bridge.validate_request(bridge.canonical(value))
        with self.assertRaisesRegex(ValueError, 'duplicate_key'): bridge.validate_request(b'{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, 'budget'): bridge.validate_request(b' ' * 4097)

    def test_valid_receipt_is_narrow_and_unknown_stop_partial_or_wrong_binding_refuses(self):
        request, raw = self.request(); receipt = receipt_for(request, raw)
        self.assertEqual(bridge.validate_receipt(bridge.canonical(receipt), request, bridge.digest(raw)), receipt)
        for key, value in [('writers_stopped', False), ('source_count', True), ('stop_seconds', True),
                           ('bridge_contract_sha256', '0' * 64), ('image_sha256', '0' * 64)]:
            changed = copy.deepcopy(receipt); changed['runtime'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(changed), request, bridge.digest(raw))
        for key, value in [('request_sha256', '0' * 64), ('case_reference_sha256', '0' * 64), ('status', 'cancelled')]:
            changed = copy.deepcopy(receipt); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(changed), request, bridge.digest(raw))

    def test_receipt_rejects_absolute_traversal_duplicate_and_oversized_artifacts(self):
        request, raw = self.request(); receipt = receipt_for(request, raw)
        for key, value in [('stored_as', '/etc/passwd'), ('stored_as', '../outside.bin'), ('bytes', 1025)]:
            changed = copy.deepcopy(receipt); changed['artifacts'][0][key] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(changed), request, bridge.digest(raw))
        changed = copy.deepcopy(receipt); changed['artifacts'][1] = changed['artifacts'][0]
        with self.assertRaises(ValueError): bridge.validate_receipt(bridge.canonical(changed), request, bridge.digest(raw))

    def test_unprivileged_export_is_never_promoted_to_stopped_producer_evidence(self):
        request, raw = self.request(); root = self.root / 'untrusted-exports'
        (root / request['request_id']).mkdir(parents=True)
        with mock.patch.object(bridge, 'EXPORT_ROOT', root):
            with self.assertRaisesRegex(ValueError, 'untrusted_export_directory'):
                bridge.import_result(self.case, self.root / 'request/request.json', self.root / 'out')
        self.assertFalse((self.root / 'out').exists()); self.assertEqual(inventory(self.case), self.before)

    def test_prepare_and_import_enforce_offline_policy_for_local_api_callers(self):
        def attempted_network(*args): socket.socket()
        with mock.patch.object(bridge, '_case_reference', side_effect=attempted_network):
            for operation in [lambda: bridge.prepare(self.case, self.root / 'out'),
                              lambda: bridge.import_result(self.case, self.root / 'request.json', self.root / 'out')]:
                with self.assertRaises(EgressDenied): operation()
        self.assertFalse((self.root / 'out').exists())

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO admission')
    def test_local_request_reader_refuses_symlinks_and_special_files_without_blocking(self):
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        link = self.root / 'link'; link.symlink_to(self.case / 'manifest.json')
        with self.assertRaises(ValueError): bridge._read_regular(fifo, 4096)
        with self.assertRaises(OSError): bridge._read_regular(link, 4096)


if __name__ == '__main__': unittest.main()
