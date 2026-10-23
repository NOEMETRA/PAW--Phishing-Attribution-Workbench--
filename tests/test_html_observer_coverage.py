"""Static observation availability is independent of numeric risk evidence."""
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case
from paw.deobfuscate.core import DeobfuscationEngine
from paw.deobfuscate.html import HTMLDeobfuscator, html_observation_coverage


class HTMLObserverCoverage(unittest.TestCase):
    def test_completed_empty_is_distinct_from_unavailable(self):
        for source in ('<p>plain</p>', ''):
            result = HTMLDeobfuscator().deobfuscate_html(source)
            for row in result['observer_coverage'].values():
                self.assertEqual((row['status'], row['observed_count'], row['omitted_count']), ('completed', 0, 0))
        with patch('paw.deobfuscate.html.HAS_BEAUTIFULSOUP', False):
            result = HTMLDeobfuscator().deobfuscate_html('<form></form>')
        for row in result['observer_coverage'].values():
            self.assertEqual(row['status'], 'not_evaluated')
            self.assertIsNone(row['observed_count'])
            self.assertIsNone(row['omitted_count'])
        self.assertEqual(result['assessment_status'], 'partial')

    def test_each_observer_failure_is_named_and_propagates_without_risk(self):
        methods = {'hidden_elements':'_analyze_hidden_elements', 'forms':'_analyze_form_obfuscation',
                   'iframes':'_analyze_iframes', 'javascript':'_analyze_inline_javascript'}
        for name, method in methods.items():
            with self.subTest(name=name), patch.object(HTMLDeobfuscator, method, side_effect=RuntimeError('private detail')):
                result = DeobfuscationEngine().analyze_artifacts({'html':'<p>static</p>'})
            html = result['deobfuscated_artifacts']['html']
            failed = html['observer_coverage'][name]
            self.assertEqual(failed['status'], 'failed')
            self.assertEqual(failed['issues'], [{'code':'observer_error', 'exception_type':'RuntimeError'}])
            self.assertIsNone(failed['observed_count'])
            self.assertIsNone(failed['omitted_count'])
            self.assertEqual(sum(row['status']=='failed' for row in html['observer_coverage'].values()), 1)
            self.assertEqual(result['coverage']['html']['status'], 'partial')
            self.assertEqual(result['assessment_status'], 'partial')
            with offline_policy(True):
                score = score_case({}, {}, {'domain':'example.invalid'}, headers={'deobfuscation_analysis':result})
            self.assertEqual(score['score_components']['deobfuscation_heuristics'], 0)

    def test_real_parser_and_selector_errors_do_not_become_completed_empty(self):
        with patch('paw.deobfuscate.html._observation_soup', side_effect=ValueError('bad parser')):
            result = HTMLDeobfuscator().deobfuscate_html('<p>literal</p>')
        self.assertEqual(result['encoded_attribute_candidates']['status'], 'partial')
        self.assertTrue(all(row['status']=='failed' for row in result['observer_coverage'].values()))
        with patch('bs4.BeautifulSoup.select', side_effect=ValueError('selector')):
            result = HTMLDeobfuscator().deobfuscate_html('<form></form>')
        self.assertEqual(result['observer_coverage']['hidden_elements']['status'], 'failed')
        self.assertEqual(result['observer_coverage']['forms']['status'], 'completed')

    def test_record_limits_count_actual_omissions_for_each_observer(self):
        samples = {'hidden_elements':('<div style="display:none">x</div>', 'hidden_elements', None),
                   'forms':('<form></form>', 'form_analysis', 'forms'),
                   'iframes':('<iframe></iframe>', 'iframe_analysis', 'iframes'),
                   'javascript':('<script>eval("inert")</script>', 'javascript_analysis', 'inline_scripts')}
        for name, (source, section, key) in samples.items():
            for count in (256, 257):
                with self.subTest(name=name, count=count):
                    result = HTMLDeobfuscator().deobfuscate_html(source*count)
                    row = result['observer_coverage'][name]
                    self.assertEqual((row['observed_count'], row['inventoried_count'], row['omitted_count']),
                                     (count, 256, count-256))
                    records = result[section] if key is None else result[section][key]
                    self.assertEqual(len(records), 256)
                    self.assertEqual(row['status'], 'partial' if count>256 else 'completed')

    def test_hidden_counts_are_selector_matches_not_unique_elements(self):
        result = HTMLDeobfuscator().deobfuscate_html('<input type="hidden" style="display:none">')
        self.assertEqual(result['observer_coverage']['hidden_elements']['observed_count'], 2)
        self.assertEqual(len(result['hidden_elements']), 2)

    def test_form_input_budget_and_omitted_form_inputs_are_counted(self):
        source = '<form>'+'<input type="hidden" value="http-example">'*1025+'</form><form><input></form>'
        result = HTMLDeobfuscator().deobfuscate_html(source)
        row = result['observer_coverage']['forms']
        self.assertEqual((row['observed_input_count'], row['inventoried_input_count'], row['omitted_input_count']), (1026, 1024, 2))
        first, second = result['form_analysis']['forms']
        self.assertEqual(len(first['suspicious_indicators']), 1024)
        self.assertEqual(second['inputs'], [])
        source = '<form><input></form>'*257
        row = HTMLDeobfuscator().deobfuscate_html(source)['observer_coverage']['forms']
        self.assertEqual((row['omitted_count'], row['observed_input_count'], row['omitted_input_count']), (1, 257, 1))

    def test_retained_script_and_iframe_aggregates_do_not_include_omitted_rows(self):
        result = HTMLDeobfuscator().deobfuscate_html('<script>console.log("inert")</script>'*256+'<script>eval("inert")</script>')
        self.assertEqual(result['javascript_analysis']['suspicious_patterns'], [])
        result = HTMLDeobfuscator().deobfuscate_html('<iframe></iframe>'*256+'<iframe src="javascript:inert" width="0"></iframe>')
        self.assertEqual(result['iframe_analysis']['suspicious_count'], 0)

    def test_script_preview_truncation_has_counts_and_preserved_source(self):
        source = '<script>'+'x'*250+'</script>'
        result = HTMLDeobfuscator().deobfuscate_html(source)
        row = result['observer_coverage']['javascript']
        self.assertEqual((row['truncated_content_count'], row['omitted_content_characters']), (1, 50))
        self.assertEqual(result['original_html'], source)
        source = '<div style="display:none">'+'x'*250+'</div>'
        result = HTMLDeobfuscator().deobfuscate_html(source)
        row = result['observer_coverage']['hidden_elements']
        self.assertEqual(row['truncated_content_count'], 1)
        self.assertEqual(row['omitted_content_characters'], result['hidden_elements'][0]['element_length']-200)

    def test_missing_bare_css_and_large_dimensions_are_not_invented_zero(self):
        for dimensions in ('', 'width height', 'width="1px"', 'width="100%"', 'width="-1"', 'width="'+'9'*5000+'"'):
            result = HTMLDeobfuscator().deobfuscate_html('<iframe src="https://example.invalid/" '+dimensions+'></iframe>')
            self.assertEqual(result['iframe_analysis']['suspicious_count'], 0)
            self.assertEqual(result['iframe_analysis']['iframes'][0]['visibility'], 'not_evaluated')
        for value in ('0', '1', '0001'):
            result = HTMLDeobfuscator().deobfuscate_html('<iframe src="https://example.invalid/" width="'+value+'"></iframe>')
            self.assertEqual(result['iframe_analysis']['suspicious_count'], 1)

    def test_document_coverage_is_independent_and_metadata_only(self):
        sources = ['<form></form>'*257, '<p>ordinary</p>']
        result = HTMLDeobfuscator().deobfuscate_documents(sources)
        summary = html_observation_coverage(result)
        self.assertEqual(summary['document_count'], 2)
        self.assertEqual([row['status'] for row in summary['documents']], ['partial', 'descriptive_only'])
        self.assertNotIn('original_html', str(summary))
        self.assertEqual(html_observation_coverage({})['status'], 'not_evaluated')

    def test_observer_state_does_not_leak_between_calls_or_emit_network(self):
        engine = HTMLDeobfuscator()
        with offline_policy(True):
            before = violations()
            first = engine.deobfuscate_html('<form></form>'*257)
            second = engine.deobfuscate_html('<p>ordinary</p>')
            self.assertEqual(violations(), before)
        self.assertEqual(first['assessment_status'], 'partial')
        self.assertEqual(second['assessment_status'], 'descriptive_only')


if __name__ == '__main__':
    unittest.main()
