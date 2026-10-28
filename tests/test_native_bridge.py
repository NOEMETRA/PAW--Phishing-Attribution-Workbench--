"""Inert native custody boundaries: no KVM, Root, interpreter or ELF execution."""
import base64
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import uuid

from paw.core import native_bridge as bridge, representation_bridge as legacy
from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.network_policy import EgressDenied
from test_representation_bridge import forensic_case, receipt_for as old_receipt
from test_synthetic_bridge import inventory
from linux_profile_fixtures import executable, changed

SHELL = b'#!/untrusted/shebang\n# exact harmless bytes; never run here\nprintf owned\n'


def receipt_for(request, raw):
    value = old_receipt(request, raw)
    value.update(schema='paw-s14-native-result-v1', producer_kind='local-root-verified-native-no-nic-v1')
    value['runtime']['bridge_contract_sha256'] = bridge.contract_hash()
    return value


class NativeBridge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.case, self.graph = forensic_case(self.root, SHELL); self.before = inventory(self.case)

    def tearDown(self): self.tmp.cleanup()

    def prepare(self, case=None, node=None, profile='shell'):
        info = bridge.prepare(case or self.case, node or self.graph.root, profile, self.root/uuid.uuid4().hex)
        raw = Path(info['request']).read_bytes()
        return bridge.validate_request(raw), raw, info

    def test_exact_shell_original_and_non_authority(self):
        request, raw, info = self.prepare()
        self.assertEqual(bytes.fromhex(request['candidate']['source']['data_hex']), SHELL)
        self.assertEqual(request['binding']['original_source']['sha256'], bridge.digest(SHELL))
        self.assertFalse(info['execution_authorized'])
        self.assertEqual(request['candidate']['provenance']['execution_authority'], 'none')
        self.assertEqual(inventory(self.case), self.before)
        self.assertEqual(Path(info['candidate']).read_bytes(), bridge.canonical(request['candidate']))
        self.assertEqual(request['binding']['bridge_contract_sha256'], bridge.contract_hash())
        self.assertNotEqual(bridge.contract_hash(), legacy.contract_hash())

    def test_derived_mime_binds_selected_bytes_and_full_ancestry(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = b'Content-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(SHELL)
            case, graph = forensic_case(Path(directory), raw)
            node = next(k for k in graph.nodes if graph.payload(k) == SHELL)
            request, _, _ = self.prepare(case, node)
            self.assertEqual(request['binding']['original_source']['sha256'], bridge.digest(raw))
            self.assertEqual(request['candidate']['source']['sha256'], bridge.digest(SHELL))
            self.assertGreater(len(request['binding']['derivation']['nodes']), 1)
            self.assertEqual(request['binding']['derivation']['selected'], node)

    def test_exact_maximum_shell_and_elf_sizes_including_over_old_512k_limit(self):
        elf = executable(); pairs = [('shell', b'#'+b'x'*(64*1024-2)+b'\n'),
                                    ('elf', elf+bytes(1024**2-len(elf)))]
        for profile, data in pairs:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                case, graph = forensic_case(Path(directory), data)
                request, raw, _ = self.prepare(case, graph.root, profile)
                self.assertEqual(bytes.fromhex(request['candidate']['source']['data_hex']), data)
                self.assertLess(len(raw), bridge.REQUEST_LIMIT)
                if profile == 'elf': self.assertGreater(len(raw), legacy.REQUEST_LIMIT)

    def test_invalid_empty_binary_foreign_architecture_and_over_budget_refuse(self):
        for profile, data in [('shell', b''), ('shell', b'\xff'), ('shell', b'x\0'),
                ('shell', b'x'*(64*1024+1)), ('elf', b'not ELF'),
                ('elf', changed(executable(), 18, '<H', 183)), ('elf', executable()+bytes(1024**2))]:
            with self.subTest(profile=profile, length=len(data)), tempfile.TemporaryDirectory() as directory:
                case, graph = forensic_case(Path(directory), data); out = Path(directory)/'refused'
                with self.assertRaises(ValueError): bridge.prepare(case, graph.root, profile, out)
                self.assertFalse(out.exists())

    def test_pie_admitted_but_no_host_loader_or_subprocess(self):
        data = executable('/lib64/ld-linux-x86-64.so.2', kind=3)
        with tempfile.TemporaryDirectory() as directory:
            case, graph = forensic_case(Path(directory), data)
            with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('host execution forbidden')):
                request, _, _ = self.prepare(case, graph.root, 'elf')
            self.assertEqual(request['candidate']['source']['sha256'], bridge.digest(data))

    def test_namespace_and_profiles_refuse_legacy_in_both_directions(self):
        _, raw, _ = self.prepare()
        with self.assertRaises(ValueError): legacy.validate_request(raw)
        old = legacy.prepare(self.case, self.graph.root, 'html', self.root/'old')
        with self.assertRaises(ValueError): bridge.validate_request(Path(old['request']).read_bytes())
        for profile in ['python', 'html', 'javascript', '/bin/sh', '', None]:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                bridge.prepare(self.case, self.graph.root, profile, self.root/'bad')

    def test_unknown_node_inside_case_existing_output_refuse(self):
        for node, out in [('../source.bin', self.root/'bad'), (self.graph.root, self.case/'out'),
                          (self.graph.root, self.root)]:
            with self.subTest(node=node, out=str(out)), self.assertRaises(ValueError):
                bridge.prepare(self.case, node, 'shell', out)
        self.assertEqual(inventory(self.case), self.before)

    def test_private_requests_under_permissive_umask(self):
        previous = os.umask(0)
        try: _, _, info = self.prepare()
        finally: os.umask(previous)
        self.assertEqual(Path(info['request']).parent.stat().st_mode & 0o777, 0o700)
        for key in ['request', 'candidate']: self.assertEqual(Path(info[key]).stat().st_mode & 0o777, 0o400)

    def test_unknown_stop_changed_seal_symlink_or_resealed_wrong_blob_refuses(self):
        for change in ['stop', 'source', 'link', 'blob']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                case, graph = forensic_case(Path(directory), SHELL)
                if change == 'stop':
                    (Path(directory)/'jobs/analysis_ownedfixture/supervisor.json').write_text('{"tree_stopped":false}')
                elif change == 'source': (case/'source.bin').write_bytes(b'changed')
                else:
                    blob = case/'blobs'/(bridge.digest(SHELL)+'.bin')
                    if change == 'link': blob.unlink(); blob.symlink_to(case/'source.bin')
                    else: blob.write_bytes(b'changed'); seal_case(case)
                with self.assertRaises((ValueError, RuntimeError)):
                    bridge.prepare(case, graph.root, 'shell', Path(directory)/'out')

    def test_request_shape_canonical_json_size_and_lease_refuse(self):
        request, raw, _ = self.prepare(); now = request['candidate']['created_at']
        for value in [raw+b' ', b'{"schema":1,"schema":2}', b'x'*(bridge.REQUEST_LIMIT+1)]:
            with self.assertRaises(ValueError): bridge.validate_request(value)
        for at in [now-1, now+900]:
            with self.assertRaises(ValueError): bridge.validate_request(raw, now=at)
        for field, value in [('profile', 'linux-python-offline-v1'), ('request_id', '../x'),
                             ('selection_binding_sha256', '0'*64), ('purpose', 'offline-explicit-forensic-selection-v1')]:
            changed_request = copy.deepcopy(request); changed_request['candidate'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): bridge.validate_request(bridge.canonical(changed_request))

    def test_source_and_binding_digest_or_claim_changes_refuse(self):
        request, _, _ = self.prepare()
        for kind in ['source', 'binding', 'origin', 'authority', 'lineage']:
            value = copy.deepcopy(request)
            if kind == 'source': value['candidate']['source']['data_hex'] = b'x'.hex()
            elif kind == 'binding': value['binding']['graph_sha256'] = '0'*64
            elif kind == 'origin': value['candidate']['provenance']['origin_verified'] = True
            elif kind == 'authority': value['candidate']['provenance']['execution_authority'] = 'granted'
            else: value['binding']['derivation']['nodes'][0]['transform']['version'] = 2
            with self.subTest(kind=kind), self.assertRaises(ValueError): bridge.validate_request(bridge.canonical(value))

    def test_receipt_all_finite_outcomes_and_exact_bindings(self):
        request, raw, _ = self.prepare()
        for status in sorted(bridge.STATUSES):
            value = receipt_for(request, raw); value['execution_status'] = status
            self.assertEqual(bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))['execution_status'], status)
        for field, changed_value in [('schema', 'paw-s14-representation-result-v1'),
                ('producer_kind', 'local-root-verified-representation-no-nic-v1'), ('profile', 'linux-x86_64-elf-offline-v1'),
                ('request_id', '0'*32), ('request_sha256', '0'*64), ('source_sha256', '0'*64),
                ('candidate_sha256', '0'*64), ('selection_binding_sha256', '0'*64), ('execution_status', 'safe')]:
            value = receipt_for(request, raw); value[field] = changed_value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_receipt_missing_authority_unknown_stop_network_and_runtime_refuse(self):
        request, raw, _ = self.prepare()
        for key, changed_value in [('grant_sha256', None), ('readiness_sha256', 'bad'), ('consumption_sha256', 'bad'),
                ('bridge_contract_sha256', legacy.contract_hash()), ('writers_stopped', False), ('stop_seconds', True),
                ('stop_seconds', 12), ('stop_seconds', float('inf')), ('network_interfaces', ['eth0']),
                ('source_count', True), ('admitted_at', 0), ('vm_uuid', 'bad')]:
            value = receipt_for(request, raw); value['runtime'][key] = changed_value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_receipt_opaque_artifact_budget_and_paths_refuse(self):
        request, raw, _ = self.prepare()
        for key, changed_value in [('stored_as', '../source.bin'), ('bytes', 1025), ('bytes', True), ('sha256', 'bad')]:
            value = receipt_for(request, raw); value['artifacts'][0][key] = changed_value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_local_unprivileged_export_never_becomes_root_authority(self):
        request, _, info = self.prepare(); prefix = self.root/'exports'
        (prefix/request['candidate']['request_id']).mkdir(parents=True)
        with mock.patch.object(bridge, 'EXPORT_ROOT', prefix), self.assertRaises(ValueError):
            bridge.import_result(self.case, info['request'], self.root/'out')
        self.assertFalse((self.root/'out').exists()); self.assertEqual(inventory(self.case), self.before)

    def test_wrong_parent_refuses_before_export_read(self):
        _, _, info = self.prepare()
        with tempfile.TemporaryDirectory() as directory:
            other, _ = forensic_case(Path(directory), SHELL)
            with mock.patch.object(bridge, 'trusted_export', side_effect=AssertionError('must refuse first')):
                with self.assertRaisesRegex(ValueError, 'does_not_match_case'):
                    bridge.import_result(other, info['request'], self.root/'out')

    @contextmanager
    def inert_export(self, request, raw, mutate=None):
        export = self.root/uuid.uuid4().hex; export.mkdir()
        (export/'request.json').write_bytes(raw)
        (export/'receipt.json').write_bytes(bridge.canonical(receipt_for(request, raw)))
        (export/'artifact-00.bin').write_bytes(b'out')
        if mutate: mutate(export)
        @contextmanager
        def fixture_export(identifier):
            self.assertEqual(identifier, request['candidate']['request_id'])
            with bridge._directory(export) as fd: yield fd
        reader = bridge.shared._read_regular
        def fixture_read(path, maximum, *, directory_fd=None, root_owned=False):
            return reader(path, maximum, directory_fd=directory_fd, root_owned=False)
        with mock.patch.object(bridge, 'trusted_export', fixture_export), mock.patch.object(bridge.shared, '_read_regular', fixture_read):
            yield

    def test_inert_sidecar_historical_request_private_files_and_original_unchanged(self):
        request, raw, info = self.prepare(); at = request['candidate']['expires_at']+100
        previous = os.umask(0)
        try:
            with self.inert_export(request, raw), mock.patch.object(time, 'time', return_value=at):
                result = bridge.import_result(self.case, info['request'], self.root/'out')
        finally: os.umask(previous)
        sidecar = Path(result['result']); self.assertTrue(verify_case(sidecar))
        self.assertEqual((sidecar/'artifact-00.bin').read_bytes(), b'out')
        self.assertEqual(inventory(self.case), self.before)
        self.assertEqual(json.loads((sidecar/'result.json').read_bytes())['selection_binding'], request['binding'])
        for path in sidecar.rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_corrupt_extra_changed_request_or_output_refuse_before_publication(self):
        request, raw, info = self.prepare()
        changes = [lambda p: (p/'extra.bin').write_bytes(b'extra'),
                   lambda p: (p/'request.json').write_bytes(raw+b' '),
                   lambda p: (p/'artifact-00.bin').write_bytes(b'bad')]
        for mutate in changes:
            with self.inert_export(request, raw, mutate), self.assertRaises(ValueError):
                bridge.import_result(self.case, info['request'], self.root/'out')
            self.assertFalse((self.root/'out').exists())
        self.assertEqual(inventory(self.case), self.before)

    def test_network_policy_guards_both_entrypoints(self):
        with mock.patch.object(bridge.shared, '_case_reference', side_effect=lambda *a: socket.socket()):
            for operation in [lambda: self.prepare(), lambda: bridge.import_result(self.case, 'request', self.root/'out')]:
                with self.assertRaises(EgressDenied): operation()


if __name__ == '__main__': unittest.main()
