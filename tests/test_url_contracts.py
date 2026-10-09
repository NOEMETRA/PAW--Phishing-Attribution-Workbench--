"""URL evidence regressions; constructed strings are not accuracy ground truth."""
import base64
import json
from email.message import EmailMessage
import unittest
from urllib.parse import quote

from paw.core.mime_analysis import analyze_mime
from paw.core.network_policy import offline_policy, violations
from paw.core.url_evidence import build_url_evidence, extract_text_url_candidates
from paw.deobfuscate.core import DeobfuscationEngine
from paw.deobfuscate.homoglyph import HomoglyphDetector
from paw.deobfuscate.url import URLDeobfuscator, http_url_status


def encoded(value):
    return base64.b64encode(value.encode('utf-8')).decode('ascii')


class URLContracts(unittest.TestCase):
    def setUp(self):
        self.engine = DeobfuscationEngine()

    def test_reserved_and_nested_percent_escapes_preserve_destination_bytes(self):
        urls = ['https://example.invalid/a%2Fb?x=a%26admin%3D1',
            'https://example.invalid/a%252Fb?next=https%3A%2F%2Ftarget.invalid%2Fa%252Fb',
            'https://example.invalid/%70%61y?x=%23%3F%2B%25%FF#%2F',
            'HTTPS://EXAMPLE.invalid/a?x=1&x=2&empty=&plus=a+b',
            'https://example.invalid/a[.]b?x=[dot]#(.)']
        for url in urls:
            with self.subTest(url=url):
                result = self.engine.deobfuscate_url(url)
                self.assertEqual(result['final_url'], url)
                self.assertEqual(result['network_url'], url)
                self.assertFalse(result['is_changed'])
                self.assertEqual(result['transformations'], [])
                self.assertEqual(result['suspicion_score'], 0)

    def test_refang_is_limited_to_scheme_and_hostname(self):
        url = 'hxxps://u(.)s:pw@example[.]invalid/a[.]b?next=a%26b%3Dc#(.)'
        result = self.engine.deobfuscate_url(url)
        self.assertEqual(result['final_url'], 'https://u(.)s:pw@example.invalid/a[.]b?next=a%26b%3Dc#(.)')
        self.assertEqual(result['url_provenance'], 'derived_text_url')
        self.assertTrue(result['network_target'])

    def test_whole_url_decoding_stops_before_resource_escapes(self):
        target = 'hxxps://example[.]invalid/a%2Fb?x=a%26b%3D1'
        result = self.engine.deobfuscate_url(quote(quote(target, safe=''), safe=''))
        self.assertEqual(result['final_url'], 'https://example.invalid/a%2Fb?x=a%26b%3D1')
        self.assertEqual(len(result['transformations']), 3)

    def test_whole_hex_and_base64_text_urls_retain_their_origin(self):
        target = 'https://example.invalid/a%2Fb'
        for value in [encoded(target), ''.join('\\x%02x' % ord(c) for c in target)]:
            result = self.engine.deobfuscate_url(value)
            self.assertEqual(result['final_url'], target)
            self.assertEqual(result['original_url'], value)
            self.assertEqual(result['url_provenance'], 'derived_text_url')

    def test_query_base64_is_a_separate_candidate_not_a_rewritten_target(self):
        target = 'https://target.invalid/a%2Fb'
        token = encoded(target)
        wrapper = 'https://tracking.invalid/click?url=' + token + '&url=&plus=a+b'
        result = self.engine.deobfuscate_url(wrapper)
        self.assertEqual(result['final_url'], wrapper)
        candidate, = result['embedded_url_candidates']
        self.assertEqual(candidate['url'], target)
        self.assertEqual(candidate['encoded_value'], token)
        self.assertEqual(candidate['source_component'], 'query_value')
        self.assertEqual(candidate['source_name'], 'url')
        self.assertEqual(candidate['source_index'], 0)
        self.assertFalse(candidate['network_target'])
        self.assertEqual(candidate['status'], 'candidate_not_verified')
        self.assertEqual(build_url_evidence([wrapper], [result])[0], [wrapper])

    def test_path_base64_and_duplicate_query_values_keep_locations(self):
        token = encoded('https://target.invalid/login').rstrip('=')
        wrapper = 'https://tracking.invalid/' + token + '?next=' + token + '&next=' + token
        result = self.engine.deobfuscate_url(wrapper)
        self.assertEqual(result['final_url'], wrapper)
        candidates = result['embedded_url_candidates']
        self.assertEqual([(c['source_component'], c['source_index']) for c in candidates],
            [('path_segment', 1), ('query_value', 0), ('query_value', 1)])

    def test_nested_encoded_url_candidate_does_not_change_parent_query(self):
        target = 'https://target.invalid/a%2Fb?x=a%26b'
        token = '%61' + quote(encoded(target), safe='')[1:]
        wrapper = 'https://tracking.invalid/?next=' + token
        result = self.engine.deobfuscate_url(wrapper)
        self.assertEqual(result['final_url'], wrapper)
        self.assertEqual(result['embedded_url_candidates'][0]['url'], target)
        self.assertEqual(len(result['embedded_url_candidates'][0]['decoding']), 2)

    def test_base64_decoding_never_silently_discards_bad_utf8(self):
        token = base64.b64encode(b'https://target.invalid/\xff').decode('ascii')
        wrapper = 'https://tracking.invalid/?next=' + token
        self.assertEqual(self.engine.deobfuscate_url(wrapper)['embedded_url_candidates'], [])

    def test_tracking_json_url_values_are_candidates_with_field_provenance(self):
        target = 'https://target.invalid/a%2Fb?x=a%26b%3D1'
        data = {'email_id':'fixture', 'href':target, 'nested':{'a/b~c':[target]}}
        token = encoded(json.dumps(data))
        wrapper = 'https://tracking.invalid/click/' + token
        result = self.engine.deobfuscate_url(wrapper)
        self.assertEqual(result['final_url'], wrapper)
        self.assertEqual([c['url'] for c in result['embedded_url_candidates']], [target, target])
        self.assertEqual([c['source_json_pointer'] for c in result['embedded_url_candidates']],
                         ['/href', '/nested/a~1b~0c/0'])
        self.assertTrue(all(c['encoded_value'] == token and not c['network_target']
                            for c in result['embedded_url_candidates']))
        self.assertEqual(build_url_evidence([wrapper], [result])[0], [wrapper])

    def test_tracking_json_decoding_is_bounded_and_never_guesses_url_from_prose(self):
        decoder = URLDeobfuscator()
        decoder.max_json_nodes = 3
        token = encoded(json.dumps({'text':'This mentions https://target.invalid/a', 'other':[0] * 30}))
        result = decoder.deobfuscate_url('https://tracking.invalid/click/' + token)
        self.assertEqual(result['embedded_url_candidates'], [])
        self.assertEqual(result['analysis_status'], 'partial')
        data = {'next':{'next':{'href':'https://target.invalid/a'}}}
        decoder.max_json_depth = 1
        result = decoder.deobfuscate_url('https://tracking.invalid/?x=' + encoded(json.dumps(data)))
        self.assertEqual(result['embedded_url_candidates'], [])
        self.assertEqual(result['analysis_status'], 'partial')

    def test_visual_confusables_never_replace_the_observed_host(self):
        for url in ['https://аррӏе.com/login', 'https://xn--80ak6aa92e.com/login',
                    'https://sub.xn--80ak6aa92e.com:8443/login']:
            with self.subTest(url=url):
                result = self.engine.deobfuscate_url(url)
                self.assertEqual(result['final_url'], url)
                self.assertEqual(result['network_url'], url)
                host = result['hostname_analysis']
                self.assertTrue(host['comparison_only'])
                self.assertIn('apple.com', host['visual_skeleton'])
                self.assertFalse(host['complete_unicode_confusables_coverage'])
                self.assertEqual(result['transformations'], [])
                self.assertTrue(any(i['type'] == 'hostname_visual_confusable' for i in result['suspicion_indicators']))
                targets, evidence = build_url_evidence([url], [result])
                self.assertEqual(targets, [url])
                self.assertEqual(evidence[0]['provenance'], 'observed')

    def test_homoglyph_public_api_preserves_urls_too(self):
        url = 'https://аррӏе.com/a'
        result = HomoglyphDetector().deobfuscate_url(url)
        self.assertEqual(result['final_url'], url)
        self.assertFalse(result['is_changed'])
        self.assertEqual(result['hostname_analysis']['visual_skeleton'], 'apple.com')

    def test_userinfo_path_query_and_fragment_do_not_become_hostname_confusables(self):
        url = 'https://аррӏе:pw@example.invalid/аррӏе?q=аррӏе#аррӏе'
        result = self.engine.deobfuscate_url(url)
        self.assertEqual(result['final_url'], url)
        self.assertEqual(result['hostname_analysis']['visual_skeleton'], 'example.invalid')
        self.assertFalse(any(i['type'] == 'hostname_visual_confusable' for i in result['suspicion_indicators']))
        self.assertTrue(any(i['type'] == 'userinfo_in_url' for i in result['suspicion_indicators']))

    def test_http_userinfo_is_not_misidentified_as_an_email_address(self):
        result = self.engine.deobfuscate_url('https://user@example.invalid/login')
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result.get('is_email', False))
        email = self.engine.deobfuscate_url('user@example.invalid')
        self.assertTrue(email['is_email'])
        self.assertFalse(email['network_target'])

    def test_invalid_ports_missing_hosts_controls_and_backslashes_are_evidence_only(self):
        urls = ['https://example.invalid:bad/a', 'https://example.invalid:65536/a',
            'https:///missing', 'https://[::1/a', 'https://example.invalid/\nnext',
            'https://example.invalid\\@target.invalid/', 'https://example%40target.invalid/']
        for url in urls:
            with self.subTest(url=url):
                result = self.engine.deobfuscate_url(url)
                self.assertEqual(result['status'], 'invalid')
                self.assertEqual(result['final_url'], url)
                self.assertIsNone(result['network_url'])
                targets, evidence = build_url_evidence([url], [result])
                self.assertEqual(targets, [])
                self.assertEqual(evidence[0]['url'], url)
                self.assertFalse(evidence[0]['network_target'])

    def test_ipv6_with_port_and_ip_literal_signals_are_preserved(self):
        for url in ['https://[::1]:8443/a', 'http://192.0.2.1:8443/a']:
            result = self.engine.deobfuscate_url(url)
            self.assertEqual(result['final_url'], url)
            self.assertTrue(any(i['type'] == 'ip_in_url' for i in result['suspicion_indicators']))
            self.assertTrue(any(i['type'] == 'non_standard_port' for i in result['suspicion_indicators']))

    def test_oversize_and_deeply_encoded_urls_stop_explicitly(self):
        url = 'https://example.invalid/' + 'a' * 65536
        result = self.engine.deobfuscate_url(url)
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['network_target'])
        self.assertEqual(build_url_evidence([url], [result])[0], [])
        value = 'https://example.invalid/a'
        for _ in range(10):
            value = quote(value, safe='')
        result = self.engine.deobfuscate_url(value)
        self.assertEqual(result['status'], 'partial')
        self.assertLessEqual(len(result['decoding_attempts']), 4)
        self.assertEqual(result['final_url'], value)

    def test_embedded_candidate_and_token_budgets_are_explicit(self):
        token = encoded('https://target.invalid/a')
        wrapper = 'https://tracking.invalid/?' + '&'.join('x=' + token for _ in range(40))
        result = self.engine.deobfuscate_url(wrapper)
        self.assertEqual(result['analysis_status'], 'partial')
        self.assertEqual(result['final_url'], wrapper)
        self.assertEqual(len(result['embedded_url_candidates']), 32)
        decoder = URLDeobfuscator()
        decoder.max_tokens = 2
        result = decoder.deobfuscate_url(wrapper)
        self.assertEqual(len(result['embedded_url_candidates']), 2)
        self.assertEqual(result['analysis_status'], 'partial')

    def test_candidate_extraction_avoids_domain_prose_and_email_suffixes(self):
        text = 'user@example.invalid invoice.pdf Price 100% SPECIAL-OFFER! https://example.invalid/a hxxps://other[.]invalid/b https%3A%2F%2Fencoded.invalid%2Fc'
        self.assertEqual(extract_text_url_candidates(text), ['https://example.invalid/a',
            'hxxps://other[.]invalid/b', 'https%3A%2F%2Fencoded.invalid%2Fc'])

    def test_network_inventory_is_deterministic_and_contains_no_embedded_candidates(self):
        raw = 'hxxps://example[.]invalid/a'
        observed = ['https://observed.invalid/a', 'https://observed.invalid/a']
        results = [self.engine.deobfuscate_url(raw), self.engine.deobfuscate_url(raw)]
        targets, evidence = build_url_evidence(observed, results)
        self.assertEqual(targets, ['https://observed.invalid/a', 'https://example.invalid/a'])
        self.assertEqual(len(evidence), 2)
        self.assertEqual(evidence[1]['source_url'], raw)
        self.assertEqual(evidence[1]['provenance'], 'derived_text_url')

    def test_observed_target_keeps_each_distinct_derived_provenance(self):
        target = 'https://example.invalid/a%2Fb'
        sources = ['hxxps://example[.]invalid/a%2Fb', quote(target, safe=''), encoded(target)]
        results = [self.engine.deobfuscate_url(value) for value in sources]
        # Repeated results and the unchanged observed URL add no duplicate records.
        results += [results[0], self.engine.deobfuscate_url(target)]
        targets, evidence = build_url_evidence([target, target], results)
        self.assertEqual(targets, [target])
        self.assertEqual(evidence[0]['provenance'], 'observed')
        self.assertEqual([e['source_url'] for e in evidence[1:]], sources)
        for record, result in zip(evidence[1:], results):
            self.assertEqual(record['url'], target)
            self.assertEqual(record['transformations'], result['transformations'])
            self.assertEqual(record['provenance'], 'derived_text_url')

    def test_colliding_derived_targets_keep_distinct_sources_without_observation(self):
        target = 'https://example.invalid/a'
        sources = ['hxxps://example[.]invalid/a', quote(target, safe='')]
        results = [self.engine.deobfuscate_url(value) for value in sources]
        targets, evidence = build_url_evidence([], results + results)
        self.assertEqual(targets, [target])
        self.assertEqual([e['source_url'] for e in evidence], sources)
        self.assertEqual([e['transformations'] for e in evidence],
                         [r['transformations'] for r in results])

    def test_malformed_percent_escapes_are_preserved_as_invalid_evidence(self):
        malformed = ['%', '%0', '%ZZ', '%0G', '%G0', '%2%20', '%%20']
        locations = ['https://example.invalid/{}', 'https://example.invalid/?x={}',
                     'https://example.invalid/#{}', 'https://user{}@example.invalid/a',
                     'https://example{}.invalid/a']
        for location in locations:
            for escape in malformed:
                value = location.format(escape)
                with self.subTest(url=value):
                    self.assertEqual(http_url_status(value)[0], 'invalid')
                    result = self.engine.deobfuscate_url(value)
                    self.assertEqual(result['status'], 'invalid')
                    self.assertEqual(result['final_url'], value)
                    self.assertIsNone(result['network_url'])
                    targets, evidence = build_url_evidence([value], [result])
                    self.assertEqual(targets, [])
                    self.assertEqual(evidence[0]['url'], value)
                    self.assertEqual(evidence[0]['status'], 'invalid')
                    self.assertFalse(evidence[0]['network_target'])

    def test_complete_percent_octets_remain_unchanged_network_targets(self):
        octets = ''.join('%%%02X' % value for value in range(256))
        for value in ['https://example.invalid/' + octets,
                      'https://example.invalid/?x=' + octets,
                      'https://example.invalid/#' + octets,
                      'https://example.invalid/%ff%2f%25ZZ%252']:
            with self.subTest(url=value):
                self.assertEqual(http_url_status(value), ('completed', None))
                result = self.engine.deobfuscate_url(value)
                self.assertEqual(result['network_url'], value)
                self.assertEqual(result['final_url'], value)
                self.assertEqual(build_url_evidence([value], [result])[0], [value])

    def test_malformed_derived_and_embedded_urls_never_become_targets(self):
        malformed = 'https://example.invalid/%ZZ?x=%0G'
        for source in ['hxxps://example[.]invalid/%ZZ?x=%0G', quote(malformed, safe=''),
                       encoded(malformed)]:
            with self.subTest(source=source):
                result = self.engine.deobfuscate_url(source)
                self.assertEqual(result['status'], 'invalid')
                self.assertEqual(result['final_url'], source)
                self.assertFalse(result['network_target'])
                self.assertEqual(build_url_evidence([], [result])[0], [])
        wrapper = 'https://tracking.invalid/?next=' + encoded(malformed)
        result = self.engine.deobfuscate_url(wrapper)
        self.assertEqual(result['embedded_url_candidates'], [])
        self.assertEqual(build_url_evidence([wrapper], [result])[0], [wrapper])

    def test_failed_url_recovery_paths_remain_in_evidence(self):
        malformed = 'https://example.invalid/%ZZ'
        sources = ['hxxps://example[.]invalid/%ZZ', quote(malformed, safe=''),
                   encoded(malformed), ''.join('\\x%02x' % ord(c) for c in malformed)]
        results = [self.engine.deobfuscate_url(source) for source in sources]
        targets, evidence = build_url_evidence([], results + results)
        self.assertEqual(targets, [])
        self.assertEqual([e['source_url'] for e in evidence], sources)
        for record, result in zip(evidence, results):
            self.assertEqual(record['url'], result['original_url'])
            self.assertEqual(record['provenance'], 'text_url_candidate')
            self.assertEqual(record['status'], 'invalid')
            self.assertEqual(record['reason'], 'Malformed percent escape in URL')
            self.assertFalse(record['network_target'])
            self.assertEqual(record['decoding_attempts'], result['decoding_attempts'])
            self.assertEqual(record['decoding_attempts'][-1]['to'], malformed)

    def test_partial_url_recovery_and_oversize_inputs_remain_in_evidence(self):
        deep = 'https://example.invalid/a'
        for _ in range(10):
            deep = quote(deep, safe='')
        oversize = 'https://example.invalid/' + 'a' * 65536
        results = [self.engine.deobfuscate_url(value) for value in [deep, oversize]]
        targets, evidence = build_url_evidence([], results)
        self.assertEqual(targets, [])
        self.assertEqual([e['source_url'] for e in evidence], [deep, oversize])
        for record in evidence:
            self.assertEqual(record['status'], 'partial')
            self.assertTrue(record['reason'])
            self.assertFalse(record['network_target'])
        self.assertEqual(len(evidence[0]['decoding_attempts']), 4)
        self.assertEqual(evidence[1]['decoding_attempts'], [])

    def test_unresolved_text_candidates_remain_in_evidence(self):
        sources = [encoded('https is mentioned but this is not a URL'), 'https%ZZ',
                   base64.b64encode(b'https://example.invalid/\xff').decode('ascii')]
        results = [self.engine.deobfuscate_url(value) for value in sources]
        targets, evidence = build_url_evidence([], results)
        self.assertEqual(targets, [])
        self.assertEqual([e['source_url'] for e in evidence], sources)
        for record, result in zip(evidence, results):
            self.assertEqual(record['status'], 'not_url')
            self.assertEqual(record['reason'], result['reason'])
            self.assertEqual(record['decoding_attempts'], result['decoding_attempts'])
            self.assertFalse(record['network_target'])

    def test_observed_invalid_evidence_is_not_duplicated_by_unchanged_results(self):
        invalid = 'https://example.invalid/%ZZ'
        oversize = 'https://example.invalid/' + 'a' * 65536
        results = [self.engine.deobfuscate_url(value) for value in [invalid, oversize]]
        targets, evidence = build_url_evidence([invalid, oversize], results + results)
        self.assertEqual(targets, [])
        self.assertEqual(len(evidence), 2)
        self.assertEqual([e['source_url'] for e in evidence], [invalid, oversize])
        self.assertTrue(all(e['provenance'] == 'observed' for e in evidence))
        self.assertTrue(all(e['decoding_attempts'] == [] for e in evidence))

    def test_mime_extraction_preserves_case_entities_and_reserved_url_bytes(self):
        message = EmailMessage()
        message.set_content('<a href="HTTPS://example.invalid/a%2Fb?x=a%26b&amp;next=1">go</a>', subtype='html')
        result = analyze_mime(message)
        self.assertEqual(result['urls'], ['HTTPS://example.invalid/a%2Fb?x=a%26b&next=1'])

    def test_url_interpretation_uses_no_network_or_child_process(self):
        before = len(violations())
        with offline_policy(True):
            for url in ['https://аррӏе.com/a', 'https://tracking.invalid/?x=' + encoded('https://target.invalid/a')]:
                self.assertEqual(self.engine.deobfuscate_url(url)['status'], 'completed')
        self.assertEqual(len(violations()), before)


if __name__ == '__main__':
    unittest.main()
