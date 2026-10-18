"""Graph syntax must not promote header text into topology or attribution."""
import copy
import re
import unittest

from paw.core.graphs import attribution_graph


LABEL_TEXTS = [
    '"] --> Forged["origin',
    'literal #quot; #35; &quot; <b>not markup</b> `markdown` \\ [IPv6:2001:db8::1]',
    'first\r\n%%{init: {securityLevel: loose}}%%\nclick Hop1 callback\x00last',
    'Unicode: 日本語 città \u2028next',
]


def labels(graph):
    """Read only the emitted quoted declarations, independently of the writer."""
    return re.findall(r'^  (?:\w+ --> )?(\w+)\["([^"\r\n]*)"\]$', graph, re.M)


def decode(text):
    return re.sub(r'#(\d+);', lambda match: chr(int(match[1])), text)


class AttributionGraphContracts(unittest.TestCase):
    def test_source_labels_cannot_change_declarations_or_add_commands(self):
        for text in LABEL_TEXTS:
            with self.subTest(text=text):
                hops = [{'ip': '2001:db8::1', 'by': text, 'header_index': 7}]
                domain = {'domain': text, 'registrar': text, 'created': text}
                original = copy.deepcopy((hops, domain))
                graph = attribution_graph(hops, 1, domain)
                declared = dict(labels(graph))
                self.assertEqual(set(declared), {'Email', 'Scope', 'Hop1', 'FromDomain'})
                self.assertEqual(len(graph.splitlines()), 6)
                self.assertIn(text, decode(declared['Hop1']))
                self.assertEqual(decode(declared['FromDomain']), f'{text} | Reg: {text} | Created: {text}')
                self.assertEqual((hops, domain), original)

    def test_badge_belongs_to_one_declaration_and_edges_reuse_plain_ids(self):
        hops = [{'ip': '8.8.8.8', 'by': 'mx.example', 'header_index': 1},
                {'ip': '8.8.8.8', 'by': 'mx.outlook.com', 'header_index': 0,
                 'role': 'recipient_mx_internal'},
                {'ip': None, 'by': 'last.example', 'header_index': 2}]
        graph = attribution_graph(hops, 2, {})
        declarations = dict(labels(graph))
        self.assertEqual(graph.count('UNVERIFIED TRANSMITTING CANDIDATE'), 1)
        self.assertIn('UNVERIFIED TRANSMITTING CANDIDATE', declarations['Hop2'])
        self.assertIn('Received header index 0', declarations['Hop2'])
        self.assertIn('MX-internal heuristic', declarations['Hop2'])
        self.assertIn('  Hop2 --> Hop3["', graph)
        self.assertNotIn('<<ORIGIN>>', graph)
        self.assertIn('unverified Received header observations', declarations['Email'])
        self.assertIn('roles are hostname heuristics', declarations['Scope'])

    def test_no_matching_candidate_never_creates_a_badge(self):
        for hops in ([], [{'ip': None, 'by': '[IPv6:2001:db8::1]'}]):
            for index in (None, 0, 10):
                with self.subTest(hops=hops, index=index):
                    graph = attribution_graph(hops, index, None)
                    self.assertNotIn('TRANSMITTING CANDIDATE', graph)
                    self.assertIn('unverified Received header observations', graph)


if __name__ == '__main__':
    unittest.main()
