import sys
import unittest
from pathlib import Path

from paw.core.representation_graph import Graph, GraphLimits
from paw.core.mime_representations import populate_mime_graph, MimeViewLimits


class MimeViews(unittest.TestCase):
    def build(self, raw, **kwargs):
        graph = Graph(raw); report = populate_mime_graph(graph, **kwargs)
        self.assertEqual(graph.payload(graph.root), raw)
        self.assertFalse(report['origin_verified']); self.assertEqual(report['execution_authority'], 'none')
        for row in report['parts']:
            wire = row['wire_body_node']
            if wire:
                params = graph.nodes[wire]['transform']['parameters']
                self.assertEqual(graph.payload(wire), raw[params['start']:params['end']])
        return graph, report

    def test_structured_charset_repairs_are_partial_without_changing_parser_choice(self):
        for header in [b'Content-Type: text/html; charset=us-ascii; charset=utf-8',
                       b'Content-Type: text/html; charset="us-ascii']:
            raw = header+b'\r\n\r\n<p>owned</p>'
            graph, report = self.build(raw); row = report['parts'][0]
            self.assertEqual(report['status'], 'partial')
            self.assertIn('structured_declaration_defects', row['issues'])
            self.assertIn('InvalidHeaderDefect', row['declarations'][0]['structured_defects'])
            self.assertFalse(graph.nodes[row['parser_selected_node']]['complete_transform'])
            self.assertEqual(graph.payload(row['parser_selected_node']), b'<p>owned</p>')
            text = row['selected_text_node']
            self.assertEqual(graph.nodes[text]['transform']['parameters']['input_charset'], 'us-ascii')

    def test_structured_multipart_declaration_defect_reaches_child_context(self):
        raw = (b'Content-Type: multipart/mixed; boundary=x; boundary=y\r\n\r\n'
               b'--x\r\nContent-Type: text/html\r\n\r\n<p>owned</p>\r\n--x--\r\n')
        graph, report = self.build(raw); parent, child = report['parts']
        self.assertIn('structured_declaration_defects', parent['issues'])
        self.assertEqual(child['partial_ancestor_paths'], ['0'])
        self.assertIn('partial_ancestor_context', child['issues'])
        self.assertFalse(graph.nodes[child['parser_selected_node']]['complete_transform'])
        self.assertEqual(graph.payload(child['parser_selected_node']), b'<p>owned</p>')

    def test_structured_defect_inventory_is_bounded_with_explicit_overflow(self):
        from email.errors import InvalidHeaderDefect
        from email.policy import EmailPolicy
        from unittest.mock import patch
        class Defective(str):
            defects = tuple(InvalidHeaderDefect('owned') for _ in range(40))
        with patch.object(EmailPolicy, 'header_fetch_parse', lambda self, name, value: Defective(value)):
            graph, report = self.build(b'Content-Type: text/html\r\n\r\n<p>owned</p>')
        declaration = report['parts'][0]['declarations'][0]
        self.assertEqual(declaration['structured_defect_count'], 40)
        self.assertEqual(len(declaration['structured_defects']), 16)
        self.assertEqual(declaration['structured_defects_omitted'], 24)
        self.assertEqual(report['status'], 'partial')

    def test_recovered_html_text_keeps_candidate_parent_and_partial_ancestry(self):
        raw = b'Content-Type: text/html; charset=us-ascii\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+b3duZWQ8L2I+Z'
        graph, report = self.build(raw); row = report['parts'][0]
        self.assertEqual(graph.payload(row['parser_selected_node']), b'PGI+b3duZWQ8L2I+Z')
        self.assertEqual(len(row['candidate_text_nodes']), 1)
        text = row['candidate_text_nodes'][0]; candidate = row['candidate_nodes'][0]
        self.assertEqual(graph.nodes[text]['parents'], [candidate])
        self.assertEqual(graph.payload(text), b'<b>owned</b>')
        self.assertFalse(graph.nodes[candidate]['complete_transform'])
        self.assertNotEqual(text, row['selected_text_node']); self.assertEqual(report['status'], 'partial')

    def test_nonascii_declaration_octets_keep_exact_hex_and_http_json_encoding(self):
        import json
        import hashlib
        for raw in [b'Content-Type: text/html; x=\xff\r\n\r\n<p>owned</p>',
                    b'Content-Type: text/\xff\n\nowned',
                    b'Content-Transfer-Encoding: \xff\n\nowned',
                    b'Content-Disposition: attachment; filename=\xff\n\nowned']:
            graph, report = self.build(raw)
            json.dumps(report, ensure_ascii=False, allow_nan=False).encode('utf-8', 'strict')
            rows = [row for part in report['parts'] for row in part['declarations'] if row['status'] == 'non_ascii_octets']
            self.assertTrue(rows)
            for row in rows:
                self.assertEqual(hashlib.sha256(bytes.fromhex(row['value_hex'])).hexdigest(), row['sha256'])
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(graph.payload(graph.root), raw)

    def test_missing_padding_keeps_parser_choice_and_wire_and_candidate_separate(self):
        raw = b'Content-Type: text/html; charset=us-ascii\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+eDwvYj4'
        graph, report = self.build(raw); row = report['parts'][0]
        self.assertEqual(graph.payload(row['wire_body_node']), b'PGI+eDwvYj4')
        self.assertEqual(graph.payload(row['parser_selected_node']), b'<b>x</b>')
        self.assertEqual(len(row['candidate_nodes']), 1)
        self.assertNotEqual(row['parser_selected_node'], row['candidate_nodes'][0])
        self.assertEqual(graph.nodes[row['candidate_nodes'][0]]['transform']['parameters']['added_padding_bytes'], 1)

    def test_invalid_length_does_not_replace_parser_undecoded_bytes_with_recovery(self):
        graph, report = self.build(b'Content-Transfer-Encoding: base64\n\nZm9vZ')
        row = report['parts'][0]
        self.assertEqual(graph.payload(row['parser_selected_node']), b'Zm9vZ')
        self.assertEqual(graph.payload(row['candidate_nodes'][0]), b'foo')
        self.assertEqual(graph.nodes[row['parser_selected_node']]['transform']['parameters']['byte_source'], 'undecoded_failed_transfer_encoding')
        self.assertEqual(report['status'], 'partial')

    def test_quoted_printable_dangling_equals_differs_explicitly_from_parser_output(self):
        graph, report = self.build(b'Content-Transfer-Encoding: quoted-printable\r\n\r\nowned=')
        row = report['parts'][0]
        self.assertEqual(graph.payload(row['parser_selected_node']), b'owned')
        self.assertEqual(graph.payload(row['candidate_nodes'][0]), b'owned=')
        self.assertFalse(graph.nodes[row['candidate_nodes'][0]]['complete_transform'])

    def test_duplicate_declarations_keep_first_parser_and_finite_other_cte_candidate(self):
        graph, report = self.build(b'Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nZg==')
        row = report['parts'][0]
        self.assertEqual(graph.payload(row['parser_selected_node']), b'f')
        self.assertEqual({graph.payload(node) for node in row['candidate_nodes']}, {b'f', b'Zg=='})
        self.assertIn('duplicate_declarations_first_parser_selection', row['issues'])
        self.assertEqual(len(row['declarations']), 2); self.assertEqual(report['status'], 'partial')

    def test_closed_multipart_maps_exact_leaf_wire_slices(self):
        raw = b'Content-Type: multipart/mixed; boundary=x\r\n\r\npreamble\r\n--x\r\nContent-Type: text/html\r\n\r\n<b>owned</b>\r\n--x--\r\nepilogue'
        graph, report = self.build(raw); row = report['parts'][1]
        self.assertEqual(row['path'], '0.0')
        self.assertEqual(graph.payload(row['wire_body_node']), b'<b>owned</b>')
        self.assertEqual(graph.payload(row['parser_selected_node']), b'<b>owned</b>')

    def test_missing_boundary_close_keeps_original_and_parser_view_without_invented_mapping(self):
        raw = b'Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Transfer-Encoding: base64\n\nZg=='
        graph, report = self.build(raw); row = report['parts'][1]
        self.assertIsNone(row['wire_body_node']); self.assertEqual(graph.payload(row['parser_selected_node']), b'f')
        self.assertEqual(row['candidate_nodes'], [])
        self.assertIn('complete_selected_boundary_mapping_unavailable', report['parts'][0]['issues'])
        self.assertIn('exact_wire_body_unavailable', [item['reason'] for item in graph.omissions])

    def test_missing_separator_does_not_guess_body_after_malformed_header(self):
        graph, report = self.build(b'Subject: owned\nnot a header\n\nbody')
        row = report['parts'][0]; self.assertIsNone(row['wire_body_node'])
        self.assertIn('MissingHeaderBodySeparatorDefect', row['structure_defects'])
        self.assertEqual(report['status'], 'partial')

    def test_charset_failure_retains_binary_selected_bytes_without_replacement(self):
        graph, report = self.build(b'Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: binary\r\n\r\n\xff\x00')
        row = report['parts'][0]; self.assertEqual(graph.payload(row['parser_selected_node']), b'\xff\x00')
        self.assertIsNone(row['selected_text_node'])
        self.assertIn('strict_charset_decode_failed', [item['reason'] for item in graph.omissions])

    def test_embedded_message_not_serialized_or_interpreted(self):
        graph, report = self.build(b'Content-Type: message/rfc822\r\n\r\nSubject: inner\r\n\r\nowned')
        row = report['parts'][0]; self.assertEqual(len(report['parts']), 1)
        self.assertEqual(graph.payload(row['wire_body_node']), b'Subject: inner\r\n\r\nowned')
        self.assertIsNone(row['parser_selected_node']); self.assertEqual(report['status'], 'partial')

    def test_part_header_depth_and_work_budgets_are_explicit(self):
        raw = b'Content-Type: multipart/mixed; boundary=x\n\n--x\n\none\n--x\n\ntwo\n--x--\n'
        graph, report = self.build(raw, limits=MimeViewLimits(parts=1))
        self.assertEqual(report['parts'], []); self.assertIn('parser_unavailable:MimeLimitExceeded', report['issues'])
        graph, report = self.build(b'Content-Transfer-Encoding: base64\n\nZg==', limits=MimeViewLimits(header_bytes=10))
        self.assertIsNone(report['parts'][0]['wire_body_node']); self.assertEqual(report['status'], 'partial')
        graph = Graph(b'Subject: owned\n\nbody', GraphLimits(work_bytes=1))
        report = populate_mime_graph(graph); self.assertEqual(report['issues'], ['graph_work_budget'])


if __name__ == '__main__': unittest.main()
