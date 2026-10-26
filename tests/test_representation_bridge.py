"""Inert selection/receipt boundaries; these fixtures are not KVM acceptance."""
import base64
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock
import uuid

from paw.core import representation_bridge as bridge
from paw.core.evidence import seal_case
from paw.core.mime_representations import populate_mime_graph
from paw.core.representation_graph import Graph, GraphLimits
from paw.core.verify import verify_case
from paw.core.network_policy import EgressDenied
from test_synthetic_bridge import make_case, inventory

HTML = (b'Content-Type: text/html; charset=us-ascii\r\n'
        b'Content-Transfer-Encoding: base64\r\n\r\nPGI+b3duZWQ8L2I+Z')


def forensic_case(root, raw=HTML):
    old = make_case(root); case = old.with_name('case-forensic-'+uuid.uuid4().hex); old.rename(case)
    graph = Graph(raw, GraphLimits(source_bytes=8*1024**2, representation_bytes=24*1024**2,
                                  work_bytes=64*1024**2, nodes=64))
    report = populate_mime_graph(graph); (case/'source.bin').write_bytes(raw)
    (case/'blobs').mkdir(); (case/'report').mkdir()
    for name, data in graph.blobs.items(): (case/'blobs'/(name+'.bin')).write_bytes(data)
    (case/'report/representations.json').write_bytes(bridge.canonical(graph.record()))
    (case/'report/interpretations.json').write_bytes(bridge.canonical({'mime': report, 'html': []}))
    (case/'manifest.json').write_bytes(bridge.canonical({'schema': 'paw-forensic-case-v1', 'case_id': case.name,
        'case_kind': 'forensic_representations', 'analysis_job': 'analysis_ownedfixture',
        'source': {'path': 'source.bin', 'bytes': len(raw), 'sha256': bridge.digest(raw)},
        'representation_root': graph.root, 'classification': 'not_evaluated', 'execution_authority': 'none'}))
    (case/'execution.json').write_bytes(bridge.canonical({'status': 'completed', 'coverage': 'partial'}))
    seal_case(case); return case, graph


def receipt_for(request, raw):
    frame = request['candidate']; now = frame['created_at']
    hashes = {key: '1'*64 for key in ['job_sha256', 'raw_result_sha256', 'source_inventory_sha256',
        'policy_sha256', 'grant_sha256', 'readiness_sha256', 'consumption_sha256', 'image_certificate_sha256', 'context_sha256']}
    return {'schema': 'paw-s14-representation-result-v1', 'producer_kind': 'local-root-verified-representation-no-nic-v1',
        'request_id': frame['request_id'], 'request_sha256': bridge.digest(raw),
        'candidate_sha256': bridge.digest(bridge.canonical(frame)), 'profile': frame['profile'],
        'selection_binding_sha256': frame['selection_binding_sha256'], 'source_sha256': frame['source']['sha256'],
        'execution_status': 'completed', 'runtime': {**hashes, 'bridge_contract_sha256': bridge.contract_hash(),
        'vm_uuid': str(uuid.uuid4()), 'image_sha256': 'e'*64, 'source_count': 90, 'admitted_at': now,
        'completed_at': now, 'stop_seconds': .1, 'writers_stopped': True, 'network_interfaces': []},
        'artifacts': [{'stored_as': 'artifact-00.bin', 'bytes': 3, 'sha256': bridge.digest(b'out')}]}


class RepresentationBridge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.case, self.graph = forensic_case(self.root); self.before = inventory(self.case)
        self.node = next(key for key, row in self.graph.nodes.items() if row['kind'] == 'partial_decoded_candidate')

    def tearDown(self): self.tmp.cleanup()

    def prepare(self, node=None):
        info = bridge.prepare(self.case, node or self.node, 'html', self.root/uuid.uuid4().hex)
        raw = Path(info['request']).read_bytes(); return bridge.validate_request(raw), raw, info

    def test_partial_candidate_binds_exact_original_graph_lineage_and_coverage(self):
        request, raw, info = self.prepare(); binding = request['binding']
        self.assertEqual(binding['original_source']['sha256'], bridge.digest(HTML))
        self.assertEqual(binding['graph_sha256'], bridge.digest((self.case/'report/representations.json').read_bytes()))
        self.assertEqual(binding['interpretations_sha256'], bridge.digest((self.case/'report/interpretations.json').read_bytes()))
        self.assertEqual(binding['case_coverage'], 'partial')
        self.assertEqual(binding['derivation']['selected'], self.node)
        self.assertEqual(request['candidate']['source']['data_hex'], b'<b>owned</b>'.hex())
        self.assertFalse(binding['derivation']['nodes'][-1]['complete_transform'])
        self.assertFalse(info['execution_authorized']); self.assertEqual(inventory(self.case), self.before)
        self.assertEqual(Path(info['candidate']).read_bytes(), bridge.canonical(request['candidate']))

    def test_same_bytes_different_interpretation_has_different_bound_selection(self):
        matches = [key for key, row in self.graph.nodes.items() if self.graph.payload(key) == b'<b>owned</b>']
        self.assertGreaterEqual(len(matches), 2)
        first, _, _ = self.prepare(matches[0]); second, _, _ = self.prepare(matches[1])
        self.assertEqual(first['candidate']['source'], second['candidate']['source'])
        self.assertNotEqual(first['binding']['derivation']['selected'], second['binding']['derivation']['selected'])
        self.assertNotEqual(first['candidate']['selection_binding_sha256'], second['candidate']['selection_binding_sha256'])

    def test_python_bytes_are_explicit_not_compiled_or_executed(self):
        source = b'raise RuntimeError("OWNED inert source must not execute on host")\n'
        with tempfile.TemporaryDirectory() as directory:
            case, graph = forensic_case(Path(directory), b'Content-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(source))
            node = next(key for key in graph.nodes if graph.payload(key) == source)
            info = bridge.prepare(case, node, 'python', Path(directory)/'request')
            request = bridge.validate_request(Path(info['request']).read_bytes())
            self.assertEqual(request['candidate']['source']['data_hex'], source.hex())
            self.assertFalse(info['execution_authorized'])

    def test_private_outputs_under_permissive_caller_umask(self):
        previous = os.umask(0)
        try: _, _, info = self.prepare()
        finally: os.umask(previous)
        self.assertEqual(Path(info['request']).parent.stat().st_mode & 0o777, 0o700)
        for name in ['request', 'candidate']:
            self.assertEqual(Path(info[name]).stat().st_mode & 0o777, 0o400)

    def test_explicit_node_profile_and_separate_new_destination_required(self):
        for node, profile, destination in [('../source.bin', 'html', self.root/'out'),
                (self.node, 'shell', self.root/'out'), (self.node, 'html', self.case/'out'),
                (self.node, 'html', self.root)]:
            with self.subTest(node=node, profile=profile), self.assertRaises(ValueError):
                bridge.prepare(self.case, node, profile, destination)
        self.assertEqual(inventory(self.case), self.before)

    def test_original_empty_python_binary_and_profile_budget_refuse(self):
        for data, profile in [(b'', 'html'), (b'\xff', 'python'), (b'x\0', 'python'),
                              (b'x'*16385, 'python'), (b'x'*(512*1024+1), 'html')]:
            with self.subTest(size=len(data), profile=profile), tempfile.TemporaryDirectory() as directory:
                case, graph = forensic_case(Path(directory), data)
                with self.assertRaises(ValueError): bridge.prepare(case, graph.root, profile, Path(directory)/'out')
                self.assertFalse((Path(directory)/'out').exists())

    def test_active_unknown_stop_and_changed_seal_refuse(self):
        path = self.root/'jobs/analysis_ownedfixture/supervisor.json'
        path.write_text('{"tree_stopped":false}')
        with self.assertRaises(RuntimeError): self.prepare()
        path.write_text('{"tree_stopped":true}'); (self.case/'source.bin').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.prepare()

    def test_symlink_or_resealed_wrong_blob_original_graph_refuses(self):
        for changed in ['symlink', 'blob', 'original', 'graph']:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                case, graph = forensic_case(Path(directory)); node = next(key for key, row in graph.nodes.items() if row['kind'] == 'partial_decoded_candidate')
                blob = case/('blobs/'+graph.nodes[node]['sha256']+'.bin')
                if changed == 'symlink': blob.unlink(); blob.symlink_to(case/'source.bin')
                elif changed == 'blob': blob.write_bytes(b'changed'); seal_case(case)
                elif changed == 'original': (case/'source.bin').write_bytes(b'changed'); seal_case(case)
                else:
                    record = graph.record(); record['nodes'][-1]['transform']['version'] = 2
                    (case/'report/representations.json').write_bytes(bridge.canonical(record)); seal_case(case)
                with self.assertRaises((ValueError, OSError)): bridge.prepare(case, node, 'html', Path(directory)/'out')
                self.assertFalse((Path(directory)/'out').exists())

    def test_request_identity_provenance_lease_and_source_mutations_refuse(self):
        request, _, _ = self.prepare()
        for field in ['schema', 'profile', 'source', 'parent', 'provenance', 'clock', 'contract', 'selected']:
            value = copy.deepcopy(request)
            if field == 'schema': value['schema'] = 'paw-s14-browser-case-request-v1'
            elif field == 'profile': value['candidate']['profile'] = 'linux-shell-offline-v1'
            elif field == 'source': value['candidate']['source']['data_hex'] = '00'
            elif field == 'parent': value['candidate']['selection_binding_sha256'] = '0'*64
            elif field == 'provenance': value['candidate']['provenance']['origin_verified'] = True
            elif field == 'clock': value['candidate']['created_at'] = True
            elif field == 'contract': value['binding']['bridge_contract_sha256'] = '0'*64
            else: value['binding']['derivation']['selected'] = '0'*64
            with self.subTest(field=field), self.assertRaises(ValueError): bridge.validate_request(bridge.canonical(value))

    def test_ancestor_transformation_identity_order_and_aggregate_are_checked(self):
        request, _, _ = self.prepare()
        for mutation in ['hash', 'order', 'depth', 'parent', 'metadata', 'count']:
            value = copy.deepcopy(request); rows = value['binding']['derivation']['nodes']
            if mutation == 'hash': rows[-1]['transform']['parameters']['unbound'] = 1
            elif mutation == 'order': rows.reverse()
            elif mutation == 'depth': rows[-1]['depth'] = True
            elif mutation == 'parent': rows[-1]['parents'] = [{}]
            elif mutation == 'metadata': rows[-1]['notes'] = ['x'*8193]
            else: rows.extend(copy.deepcopy(rows)*64)
            value['candidate']['selection_binding_sha256'] = bridge.digest(bridge.canonical(value['binding']))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): bridge.validate_request(bridge.canonical(value))

    def test_duplicate_keys_noncanonical_and_complex_json_refuse(self):
        request, raw, _ = self.prepare()
        for content in [b'{"schema":1,"schema":2}', raw+b' ', b'['*34+b'0'+b']'*34,
                        b'{"x":NaN}', b' '*(bridge.REQUEST_LIMIT+1)]:
            with self.assertRaises(ValueError): bridge.validate_request(content)

    def test_old_attachment_validator_rejects_new_namespace(self):
        from paw.core import browser_bridge, offline_bridge
        _, raw, _ = self.prepare()
        for old in [browser_bridge, offline_bridge]:
            with self.assertRaises(ValueError): old.validate_request(raw)

    def test_receipt_profiles_and_failure_statuses_are_custody_not_verdict(self):
        request, raw, _ = self.prepare()
        for status in sorted(bridge.STATUSES):
            value = receipt_for(request, raw); value['execution_status'] = status
            self.assertEqual(bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))['execution_status'], status)

    def test_cross_parent_source_candidate_profile_or_old_receipt_refuse(self):
        request, raw, _ = self.prepare()
        for field, changed in [('request_id', '0'*32), ('source_sha256', '0'*64), ('candidate_sha256', '0'*64),
                ('selection_binding_sha256', '0'*64), ('profile', 'linux-python-offline-v1'),
                ('producer_kind', 'local-root-verified-browser-offline'), ('execution_status', 'safe')]:
            value = receipt_for(request, raw); value[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_unknown_stop_network_or_missing_grant_readiness_refuses_publication(self):
        request, raw, _ = self.prepare()
        for field, changed in [('writers_stopped', False), ('stop_seconds', True), ('stop_seconds', 12),
                ('stop_seconds', float('inf')), ('network_interfaces', ['lo']), ('grant_sha256', 'bad'),
                ('readiness_sha256', 'bad'), ('consumption_sha256', 'bad'), ('admitted_at', 0)]:
            value = receipt_for(request, raw); value['runtime'][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_opaque_artifact_paths_count_and_lengths_are_finite(self):
        request, raw, _ = self.prepare()
        for field, changed in [('stored_as', '../source.bin'), ('bytes', True), ('bytes', 1025), ('sha256', 'bad')]:
            value = receipt_for(request, raw); value['artifacts'][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.validate_receipt(bridge.canonical(value), request, bridge.digest(raw))

    def test_unprivileged_export_is_not_a_root_receipt(self):
        request, _, info = self.prepare(); prefix = self.root/'exports'
        (prefix/request['candidate']['request_id']).mkdir(parents=True)
        with mock.patch.object(bridge, 'EXPORT_ROOT', prefix), self.assertRaises(ValueError):
            bridge.import_result(self.case, info['request'], self.root/'out')
        self.assertFalse((self.root/'out').exists()); self.assertEqual(inventory(self.case), self.before)

    def test_inert_import_seals_separate_opaque_sidecar_and_preserves_parent(self):
        request, raw, info = self.prepare(); export = self.root/'inert-export'; export.mkdir()
        (export/'request.json').write_bytes(raw)
        (export/'receipt.json').write_bytes(bridge.canonical(receipt_for(request, raw)))
        (export/'artifact-00.bin').write_bytes(b'out')
        @contextmanager
        def fixture_export(identifier):
            self.assertEqual(identifier, request['candidate']['request_id'])
            with bridge._directory(export) as fd: yield fd
        reader = bridge.shared._read_regular
        def fixture_read(path, maximum, *, directory_fd=None, root_owned=False):
            return reader(path, maximum, directory_fd=directory_fd, root_owned=False)
        with mock.patch.object(bridge, 'trusted_export', fixture_export), mock.patch.object(bridge.shared, '_read_regular', fixture_read):
            result = bridge.import_result(self.case, info['request'], self.root/'out')
        sidecar = Path(result['result']); self.assertTrue(verify_case(sidecar))
        self.assertEqual((sidecar/'artifact-00.bin').read_bytes(), b'out')
        self.assertEqual(inventory(self.case), self.before)
        self.assertEqual(json.loads((sidecar/'result.json').read_bytes())['selection_binding'], request['binding'])

    def test_wrong_case_even_with_valid_request_cannot_import(self):
        request, raw, info = self.prepare()
        with tempfile.TemporaryDirectory() as directory:
            other, _ = forensic_case(Path(directory))
            with self.assertRaisesRegex(ValueError, 'does_not_match_case'):
                bridge.import_result(other, info['request'], self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_network_policy_wraps_prepare_and_import(self):
        with mock.patch.object(bridge.shared, '_case_reference', side_effect=lambda *a: socket.socket()):
            for operation in [lambda: self.prepare(), lambda: bridge.import_result(self.case, 'request', self.root/'out')]:
                with self.assertRaises(EgressDenied): operation()


if __name__ == '__main__': unittest.main()
