import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from paw.core.representation_graph import Graph, GraphLimits, text_view
from paw.core.html_representation_observer import observe_html, HTMLLimits


class HTMLObservation(unittest.TestCase):
    def observe(self, raw, limits=HTMLLimits()):
        graph = Graph(raw); text = text_view(graph, graph.root, 'utf-8')
        report = observe_html(graph, text, limits)
        self.assertEqual(graph.payload(graph.root), raw)
        self.assertEqual(report['representation'], text)
        self.assertFalse(report['origin_verified']); self.assertEqual(report['execution_authority'], 'none')
        return graph, report

    def test_markup_observation_does_not_execute_script_or_fetch_references(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            graph, report = self.observe(b'<html><body><script>fetch("https://example.invalid/")</script><img src="file:///owned-canary"><form action="https://example.invalid/"></form></body></html>')
        self.assertEqual(report['status'], 'observed')
        self.assertEqual(report['script_start_tags'], 1); self.assertEqual(report['reference_attributes_observed'], 2)

    def test_truncated_script_and_start_tag_are_partial_without_repaired_dom(self):
        for raw in [b'<html><script>owned(', b'<html><a href="owned', b'<div><!-- unfinished']:
            graph, report = self.observe(raw)
            self.assertEqual(report['status'], 'partial')
            self.assertTrue(report['issues']); self.assertNotIn('dom', report)

    def test_mismatch_is_lexical_not_browser_validity_verdict(self):
        _, report = self.observe(b'<p>one<p>two')
        self.assertEqual(report['status'], 'partial')
        self.assertIn('lexically_unclosed_start_tags', report['issues'])
        self.assertNotIn('valid', report); self.assertNotIn('malicious', report)

    def test_only_explicit_utf8_view_can_be_observed_and_characters_are_preserved(self):
        raw = b'\xef\xbb\xbf<p>\xe2\x82\xac\r\n&#65;&amp;\x00</p>'
        graph, report = self.observe(raw)
        self.assertEqual(graph.payload(report['representation']), raw)
        self.assertEqual(report['character_references_observed'], 2)
        with self.assertRaises(ValueError): observe_html(graph, graph.root)

    def test_depth_token_tag_input_and_work_budgets_are_explicit(self):
        cases = [(b'<a><b><c>', HTMLLimits(depth=2), 'lexical_open_tag_depth'),
                 (b'<a></a><b></b>', HTMLLimits(tokens=2), 'token_count'),
                 (b'<a href="longvalue">', HTMLLimits(tag_characters=8), 'tag_characters'),
                 (b'<p>owned</p>', HTMLLimits(input_bytes=4), 'html_input_bytes')]
        for raw, limits, reason in cases:
            graph, report = self.observe(raw, limits)
            self.assertEqual(report['status'], 'partial'); self.assertIn(reason, report['issues'])
            self.assertIn(reason, [item['reason'] for item in graph.omissions])
        graph = Graph(b'<p>', GraphLimits(work_bytes=3)); text = text_view(graph, graph.root, 'utf-8')
        self.assertEqual(observe_html(graph, text)['issues'], ['graph_work_budget'])

    def test_events_keep_digests_and_decoded_positions_not_urls_or_host_paths(self):
        _, report = self.observe(b'<a href="https://example.invalid/private">owned</a>')
        self.assertEqual(report['first_events'][0]['text_line_column'], [1, 0])
        self.assertNotIn('example.invalid', str(report)); self.assertNotIn('href', report['first_events'][0])
        self.assertEqual(len(report['first_events'][0]['raw_tag_utf8_sha256']), 64)


if __name__ == '__main__': unittest.main()
