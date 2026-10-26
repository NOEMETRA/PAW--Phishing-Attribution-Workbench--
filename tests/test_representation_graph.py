import hashlib
import json
from pathlib import Path
import sys
import unittest

from paw.core import representation_graph as graph


class DerivationGraph(unittest.TestCase):
    def test_original_bytes_remain_separate_from_missing_padding_candidate(self):
        value = graph.Graph(b'Zg'); nodes = graph.base64_views(value, value.root)
        self.assertEqual(value.payload(value.root), b'Zg'); self.assertEqual(len(nodes), 1)
        self.assertEqual(value.payload(nodes[0]), b'f')
        node = value.nodes[nodes[0]]; self.assertEqual(node['parents'], [value.root])
        self.assertEqual(node['transform']['name'], 'base64-add-missing-padding')
        self.assertEqual(node['transform']['parameters']['added_padding_bytes'], 2)
        self.assertFalse(node['origin_verified']); self.assertEqual(node['execution_authority'], 'none')
        self.assertEqual(value.record()['status'], 'partial')

    def test_base64_length_one_mod_four_is_only_explicit_partial_prefix(self):
        value = graph.Graph(b'Zm9vZ'); nodes = graph.base64_views(value, value.root)
        self.assertEqual(value.payload(nodes[0]), b'foo'); node = value.nodes[nodes[0]]
        self.assertFalse(node['complete_transform']); self.assertEqual(node['transform']['parameters']['normalized_suffix_omitted_bytes'], 1)
        self.assertEqual(value.payload(value.root), b'Zm9vZ')

    def test_invalid_middle_character_does_not_disappear_into_full_decode(self):
        value = graph.Graph(b'Zm9v!YmFy'); nodes = graph.base64_views(value, value.root)
        self.assertEqual(value.payload(nodes[0]), b'foo')
        self.assertEqual(value.nodes[nodes[0]]['kind'], 'partial_decoded_candidate')
        self.assertEqual(value.nodes[nodes[0]]['transform']['parameters']['normalized_suffix_omitted_bytes'], 5)

    def test_whitespace_removal_and_noncanonical_bits_are_recorded(self):
        value = graph.Graph(b'Zg==\r\n\t '); node = graph.base64_views(value, value.root)[0]
        self.assertEqual(value.nodes[node]['transform']['parameters']['removed_ascii_whitespace_bytes'], 4)
        self.assertEqual(value.payload(node), b'f')
        value = graph.Graph(b'Zh=='); node = graph.base64_views(value, value.root)[0]
        self.assertIn('noncanonical_pad_bits_or_spelling', value.nodes[node]['notes'])

    def test_qp_invalid_escapes_and_dangling_equals_are_preserved(self):
        value = graph.Graph(b'hello=20world=\r\n=QZ==\nend=')
        node = graph.quoted_printable_view(value, value.root)
        self.assertEqual(value.payload(node), b'hello world=QZ=end=')
        self.assertFalse(value.nodes[node]['complete_transform'])
        self.assertEqual(value.nodes[node]['transform']['parameters']['soft_breaks_removed'], 2)
        self.assertEqual(value.payload(value.root), b'hello=20world=\r\n=QZ==\nend=')

    def test_charset_choices_have_distinct_provenance_and_no_replacement(self):
        value = graph.Graph(b'\x80')
        self.assertIsNone(graph.text_view(value, value.root, 'utf-8'))
        latin = graph.text_view(value, value.root, 'iso-8859-1')
        windows = graph.text_view(value, value.root, 'windows-1252')
        self.assertEqual(value.payload(latin), '\u0080'.encode()); self.assertEqual(value.payload(windows), '\u20ac'.encode())
        self.assertNotEqual(latin, windows); self.assertIsNone(graph.text_view(value, value.root, 'utf-7'))

    def test_identity_text_view_shares_blob_but_not_interpretation_identity(self):
        value = graph.Graph(b'\xef\xbb\xbftext\r\n\x00'); text = graph.text_view(value, value.root, 'utf-8')
        self.assertNotEqual(text, value.root); self.assertEqual(value.payload(text), value.payload(value.root))
        self.assertEqual(len(value.blobs), 1); self.assertEqual(len(value.nodes), 2)

    def test_depth_node_byte_and_work_budgets_leave_original_and_explicit_omissions(self):
        for limits, reason in [(graph.GraphLimits(source_bytes=4, representation_bytes=4), 'representation_bytes'),
                               (graph.GraphLimits(source_bytes=4, representation_bytes=64, nodes=1), 'node_count')]:
            value = graph.Graph(b'Zg==', limits); self.assertEqual(graph.base64_views(value, value.root), [])
            self.assertEqual(value.payload(value.root), b'Zg=='); self.assertEqual(value.omissions[-1]['reason'], reason)
        value = graph.Graph(b'a', graph.GraphLimits(source_bytes=1, representation_bytes=64, depth=1))
        first = graph.text_view(value, value.root, 'utf-8'); self.assertIsNone(graph.text_view(value, first, 'utf-8'))
        self.assertEqual(value.omissions[-1]['reason'], 'depth')
        value = graph.Graph(b'aa', graph.GraphLimits(source_bytes=2, representation_bytes=64, work_bytes=1))
        self.assertIsNone(graph.text_view(value, value.root, 'utf-8')); self.assertEqual(value.omissions[-1]['reason'], 'work_bytes')

    def test_graph_identity_hashes_and_paths_recompute_without_payload_json_or_authority(self):
        value = graph.Graph(b'Zm9v'); graph.base64_views(value, value.root); record = value.record()
        for node in record['nodes']:
            data = {k:v for k,v in node.items() if k not in {'id','blob_path'}}
            self.assertEqual(graph.digest(graph.canonical(data)), node['id'])
            self.assertEqual(hashlib.sha256(value.payload(node['id'])).hexdigest(), node['sha256'])
            self.assertEqual(node['blob_path'], 'blobs/'+node['sha256']+'.bin')
        self.assertLess(len(json.dumps(record)), 8192)
        with self.assertRaises(ValueError): value.add('original', b'other', [], 'original-bytes', {}, complete=True)
        with self.assertRaises(ValueError): value.add('candidate', b'other', ['x'*64], 'unknown-parent', {}, complete=True)

    def test_caller_metadata_and_returned_records_cannot_mutate_provenance(self):
        value = graph.Graph(b'original'); parents = [value.root]; parameters = {'policy': ['strict']}
        node = value.add('candidate', b'view', parents, 'owned-test-transform', parameters, complete=True)
        before = graph.canonical(value.record())
        parents.clear(); parameters['policy'].append('changed')
        self.assertEqual(graph.canonical(value.record()), before)
        record = value.record(); record['nodes'][1]['transform']['parameters']['policy'].append('external change')
        self.assertEqual(graph.canonical(value.record()), before)

    def test_omission_inventory_overflow_remains_explicit(self):
        value = graph.Graph(b'a', graph.GraphLimits(source_bytes=1, nodes=1))
        for _ in range(3): graph.text_view(value, value.root, 'utf-8')
        record = value.record()
        self.assertEqual(len(record['omissions']), 1)
        self.assertEqual(record['omission_count'], 3)
        self.assertEqual(record['omissions_not_retained'], 2)
        self.assertEqual(record['status'], 'partial')


if __name__ == '__main__': unittest.main()
