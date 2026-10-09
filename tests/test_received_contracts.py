"""Received header claims must retain field scope and uncertainty, offline."""
import unittest
import ipaddress
from paw.core.received import normalize_received
from paw.core.header_forgery import analyze_received_anomalies
from paw.core.header_forgery import received_score_components
from paw.core.ip_observations import classify_ip
from paw.core.network_policy import offline_policy, violations

DATE = '; Wed, 8 Oct 2025 10:00:00 +0000'


def hop(line):
    with offline_policy(True):
        return normalize_received([line+DATE])['ordered_hops'][0]


class ReceivedContracts(unittest.TestCase):
    def test_sender_ipv6_is_not_replaced_by_receiver_ipv4(self):
        value = hop('from sender.example (IPv6:2001:4860:4860::8888) by mx.example (192.0.2.10) with ESMTP id 203.0.113.17')
        self.assertEqual(value['ip'],'2001:4860:4860::8888')
        self.assertEqual(value['ip_observation']['status'],'parsed')
        self.assertFalse(value['ip_observation']['verified'])
        self.assertEqual({c['scope'] for c in value['ip_candidates']},{'from','by','id'})

    def test_receiver_or_queue_id_ip_is_not_a_sender_ip(self):
        for line in ('from sender.example by mx.example (8.8.8.8) with ESMTP',
                     'from sender.example by mx.example with ESMTP id 8.8.8.8'):
            with self.subTest(line=line):
                value = hop(line)
                self.assertIsNone(value['ip'])
                self.assertEqual(value['ip_observation']['status'],'unavailable')
                self.assertTrue(value['ip_candidates'])

    def test_multiple_distinct_sender_ip_claims_are_ambiguous(self):
        value = hop('from sender.example (8.8.8.8 [9.9.9.9]) by mx.example')
        self.assertIsNone(value['ip'])
        self.assertEqual(value['ip_observation']['status'],'unsupported')
        self.assertEqual(value['parsing']['status'],'partial')

    def test_mapped_ipv6_literal_is_kept_whole(self):
        value = hop('from [IPv6:::ffff:192.0.2.5] by mx.example')
        self.assertEqual(ipaddress.ip_address(value['ip']),ipaddress.ip_address('::ffff:192.0.2.5'))
        candidate, = value['ip_candidates']
        self.assertEqual(value['raw'][slice(*candidate['source_span'])],'[IPv6:::ffff:192.0.2.5]')
        self.assertEqual(value['ip_observation']['classification']['category'],'documentation')

    def test_clause_words_in_comments_are_not_selected_as_fields(self):
        value = hop('(by fake.example) from sender.example (comment from fake.example) by mx.example with ESMTP')
        self.assertEqual(value['by'],'mx.example')
        self.assertTrue(value['from'].startswith('sender.example'))
        self.assertEqual(value['parsing']['status'],'parsed')
        value = hop('from (comment \\) text) sender.example (8.8.8.8) by mx.example')
        self.assertEqual(value['from_host'],'sender.example')
        self.assertEqual(value['ip'],'8.8.8.8')

    def test_unbalanced_comments_do_not_establish_sender_ip(self):
        value = hop('from sender.example (8.8.8.8 by mx.example')
        self.assertIsNone(value['ip'])
        self.assertEqual(value['parsing']['status'],'partial')

    def test_no_provider_name_can_establish_verified_receiver_boundary(self):
        values = [hop('from sender.example (10.0.0.1) by mx.example'),
                  hop('from relay.outlook.com (127.0.0.1) by mx.outlook.com')]
        result = analyze_received_anomalies(values)
        self.assertIsNone(result['private_ip_before_boundary'])
        self.assertEqual(result['receiver_boundary']['status'],'not_evaluated')
        self.assertFalse(result['receiver_boundary']['verified'])
        self.assertEqual({entry['category'] for entry in result['ip_observations']},{'private_rfc1918','loopback'})

    def test_literal_or_single_label_by_is_only_a_syntax_observation(self):
        for host,kind in (('[IPv6:2001:db8::1]','address_literal'),('MAILBOX01','single_label'),('mx.example','domain')):
            with self.subTest(host=host):
                value = hop('from sender.example by '+host)
                self.assertEqual(value['by_observation']['kind'],kind)
                self.assertFalse(value['by_observation']['verified'])

    def test_missing_from_and_oversized_fields_have_explicit_partial_coverage(self):
        for line in ('by mx.example (8.8.8.8)', 'from sender.example ('+'x'*65537+') by mx.example'):
            with self.subTest(length=len(line)):
                value = hop(line)
                self.assertIsNone(value['ip'])
                self.assertEqual(value['parsing']['status'],'partial')
                self.assertEqual(value['raw'],line+DATE)

    def test_source_spans_and_header_order_are_preserved_without_dns(self):
        lines = ['from a.example (8.8.8.8) by b.example'+DATE,
                 'from b.example (9.9.9.9) by c.example'+DATE]
        before = len(violations())
        with offline_policy(True):
            result = normalize_received(lines)
        self.assertEqual(len(violations()),before)
        self.assertEqual([h['raw'] for h in result['ordered_hops']],list(reversed(lines)))
        self.assertEqual([h['header_index'] for h in result['ordered_hops']],[1,0])
        for value in result['ordered_hops']:
            for candidate in value['ip_candidates']:
                self.assertIn(candidate['ip'],value['raw'][slice(*candidate['source_span'])])
            self.assertIsNone(value['ptr'])

    def test_address_categories_do_not_conflate_private_loopback_or_multicast(self):
        for ip,category in (('10.0.0.1','private_rfc1918'),('fc00::1','unique_local'),
                            ('127.0.0.1','loopback'),('fe80::1','link_local'),
                            ('100.64.0.1','shared_address_space'),('192.0.2.1','documentation'),
                            ('3fff::1','documentation'),
                            ('0.0.0.0','unspecified'),('224.0.0.1','multicast'),
                            ('::ffff:224.0.0.1','multicast'),('8.8.8.8','public')):
            with self.subTest(ip=ip):
                self.assertEqual(classify_ip(ip)['category'],category)

    def test_missing_host_or_duplicate_clauses_do_not_select_sender_ip(self):
        for line in ('from sender.example (8.8.8.8) by',
                     'from (8.8.8.8) by mx.example',
                     'from sender.example (8.8.8.8) by mx.example by other.example',
                     'junk from sender.example (8.8.8.8) by mx.example',
                     'from malformed..example (8.8.8.8) by mx.example'):
            value = hop(line)
            self.assertIsNone(value['ip'])
            self.assertEqual(value['parsing']['status'],'partial')

    def test_hostname_and_address_category_penalties_are_descriptive_only(self):
        value = analyze_received_anomalies([hop('from a.example (127.0.0.1) by MAILBOX01')])
        self.assertEqual(value['invalid_fqdn_count'],1)
        self.assertEqual(received_score_components(value),{
            'received_non_monotonic_dates':0,'received_private_ip_before_boundary':0,'received_invalid_fqdn':0})

    def test_semicolon_in_comment_is_not_the_timestamp_delimiter(self):
        value = hop('from a.example (comment; text [8.8.8.8]) by mx.example')
        self.assertEqual(value['date'],'2025-10-08T10:00:00+00:00')
        self.assertEqual(value['ip'],'8.8.8.8')

    def test_scoped_or_network_tokens_are_not_silently_truncated(self):
        for token in ('8.8.8.8/24','fe80::1%eth0','[IPv6:fe80::1%eth0]','8.8.8.8.example'):
            with self.subTest(token=token):
                value = hop('from sender.example ('+token+') by mx.example')
                self.assertIsNone(value['ip'])
                self.assertEqual(value['ip_candidates'],[])

    def test_malformed_bracket_fragments_cannot_supply_sender_ip(self):
        for token in ('[8.8.8.8', '8.8.8.8]', '[IPv6:::ffff:8.8.8.8',
                      'IPv6:::ffff:8.8.8.8]', '[[8.8.8.8]', '[8.8.8.8]]',
                      '[ 8.8.8.8', '[[8.8.8.8]]'):
            with self.subTest(token=token):
                line = 'from sender.example ('+token+') by mx.example'
                value = hop(line)
                self.assertEqual(value['raw'],line+DATE)
                self.assertIsNone(value['ip'])
                self.assertEqual(value['ip_observation']['status'],'unsupported')
                self.assertEqual(value['parsing']['status'],'partial')
                self.assertTrue(any('bracket' in issue.lower() for issue in value['parsing']['issues']))
                self.assertEqual(value['ip_candidates'],[])

    def test_valid_literal_candidates_remain_whole_next_to_malformed_fragment(self):
        value = hop('from sender.example (8.8.8.8]) by mx.example ([9.9.9.9])')
        self.assertIsNone(value['ip'])
        self.assertEqual(value['parsing']['status'],'partial')
        candidate, = value['ip_candidates']
        self.assertEqual(candidate['scope'],'by')
        self.assertEqual(candidate['text'],'[9.9.9.9]')
        self.assertEqual(value['raw'][slice(*candidate['source_span'])],candidate['text'])

    def test_bracketed_ip_requires_boundaries_around_the_whole_token(self):
        for literal in ('[8.8.8.8]','[IPv6:::ffff:8.8.8.8]'):
            for prefix,suffix in (('', '.example'),('', '/24'),('', '%eth0'),('', ':443'),
                                  ('host', ''),('host.', ''),('x/', ''),('', '-suffix')):
                with self.subTest(literal=literal,prefix=prefix,suffix=suffix):
                    line = 'from sender.example ('+prefix+literal+suffix+') by mx.example'
                    value = hop(line)
                    self.assertEqual(value['raw'],line+DATE)
                    self.assertIsNone(value['ip'])
                    self.assertEqual(value['ip_candidates'],[])
                    self.assertEqual(value['ip_observation']['status'],'unsupported')
                    self.assertEqual(value['parsing']['status'],'partial')
        value = hop('from sender.example ([8.8.8.8]/24) by mx.example ([9.9.9.9])')
        self.assertIsNone(value['ip'])
        candidate, = value['ip_candidates']
        self.assertEqual(candidate['text'],'[9.9.9.9]')
        self.assertEqual(candidate['scope'],'by')

    def test_bracketed_ip_with_supported_delimiters_retains_exact_span(self):
        for prefix,suffix in (('', ''),(' ', ' '),('(', ')'),('"', '"'),('', ', text')):
            with self.subTest(prefix=prefix,suffix=suffix):
                value = hop('from sender.example ('+prefix+'[8.8.8.8]'+suffix+') by mx.example')
                self.assertEqual(value['ip'],'8.8.8.8')
                self.assertEqual(value['parsing']['status'],'parsed')
                candidate, = value['ip_candidates']
                self.assertEqual(candidate['text'],'[8.8.8.8]')
                self.assertEqual(value['raw'][slice(*candidate['source_span'])],candidate['text'])


if __name__ == '__main__':
    unittest.main()
