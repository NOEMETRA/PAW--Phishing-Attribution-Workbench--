"""Graph syntax must not promote header text into topology or attribution."""
import copy
import re
import unittest

from paw.core.graphs import attribution_graph, domain_graph


LABEL_TEXTS = [
    '"] --> Forged["origin',
    'literal #quot; #35; &quot; <b>not markup</b> `markdown` \\ [IPv6:2001:db8::1]',
    'first\r\n%%{init: {securityLevel: loose}}%%\nclick Hop1 callback\x00last',
    'Unicode: 日本語 città \u2028next',
]


def labels(graph):
    """Read quoted declarations, including two declarations on the same edge."""
    return re.findall(r'\b(\w+)\["([^"\r\n]*)"\]', graph)


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


class DomainGraphContracts(unittest.TestCase):
    def test_source_fields_stay_text_in_the_existing_five_nodes(self):
        for text in LABEL_TEXTS + ['Example Registrar (EU)', 'end']:
            with self.subTest(text=text):
                domain = {'domain': text, 'registrar': text, 'created': text,
                          'ns': [text, 'ns.example'], 'mx': [text, 'mx.example']}
                original = copy.deepcopy(domain)
                graph = domain_graph(domain)
                declared = dict(labels(graph))
                self.assertEqual(set(declared), {'D', 'R', 'C', 'NS', 'MX'})
                self.assertEqual(len(graph.splitlines()), 5)
                self.assertEqual(decode(declared['D']), text)
                self.assertEqual(decode(declared['R']), f'Registrar: {text}')
                self.assertEqual(decode(declared['C']), f'Created: {text}')
                self.assertEqual(decode(declared['NS']), f'NS: {text}, ns.example')
                self.assertEqual(decode(declared['MX']), f'MX: {text}, mx.example')
                self.assertEqual(domain, original)

    def test_unavailable_domain_has_a_nonempty_display_label_without_changing_source(self):
        for domain in ({}, {'domain': ''}, {'domain': None}):
            with self.subTest(domain=domain):
                original = copy.deepcopy(domain)
                declared = dict(labels(domain_graph(domain)))
                self.assertEqual(declared['D'], 'Domain unavailable')
                self.assertEqual(declared['NS'], 'NS: -')
                self.assertEqual(declared['MX'], 'MX: -')
                self.assertEqual(domain, original)


if __name__ == '__main__':
    unittest.main()
