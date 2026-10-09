"""HTML evidence contracts; constructed strings are not accuracy ground truth."""
import base64
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case
from paw.deobfuscate.core import DeobfuscationEngine
from paw.deobfuscate.html import HTMLDeobfuscator


class HTMLContracts(unittest.TestCase):
    def test_routine_entities_preserve_html_and_do_not_add_risk(self):
        for source in ('<p>A &amp; B&nbsp;&#233;</p>',
                       '<a href="https://example.invalid/a%2Fb?x=1&amp;y=2">link</a>',
                       '<p>&amp;amp;lt;form&amp;amp;gt;</p>'):
            for engine in (HTMLDeobfuscator(), DeobfuscationEngine()):
                with self.subTest(source=source,engine=type(engine).__name__):
                    result = engine.deobfuscate_html(source)
                    self.assertEqual(result['original_html'], source)
                    self.assertEqual(result['final_html'], source)
                    self.assertEqual(result['suspicion_score'], 0)
                    self.assertEqual(result['assessment_status'], 'descriptive_only')
                    self.assertEqual(result['risk_detection'], 'not_evaluated')

    def test_escaped_markup_does_not_fabricate_forms_iframes_or_scripts(self):
        source = ('<p>&lt;form action="https://example.invalid"&gt;'
                  '&lt;input type="password"&gt;&lt;/form&gt;'
                  '&lt;iframe src="https://example.invalid" width="0"&gt;&lt;/iframe&gt;'
                  '&lt;script&gt;eval("hello")&lt;/script&gt;</p>')
        result = DeobfuscationEngine().deobfuscate_html(source)
        self.assertEqual(result['form_analysis']['forms'], [])
        self.assertEqual(result['iframe_analysis']['iframes'], [])
        self.assertEqual(result['javascript_analysis']['inline_scripts'], [])
        self.assertEqual(result['final_html'], source)

    def test_real_static_elements_remain_observations_without_execution(self):
        source = ('<form action="https://example.invalid"><input type="password"></form>'
                  '<iframe src="https://example.invalid" width="0"></iframe>'
                  '<script>eval("hello")</script><div style="display:none">preheader</div>')
        with offline_policy(True):
            before = violations()
            result = DeobfuscationEngine().deobfuscate_html(source)
            self.assertEqual(result['final_html'], source)
            self.assertEqual(len(result['form_analysis']['forms']), 1)
            self.assertEqual(len(result['iframe_analysis']['iframes']), 1)
            self.assertEqual(len(result['javascript_analysis']['inline_scripts']), 1)
            self.assertGreater(len(result['hidden_elements']), 0)
            self.assertEqual(result['risk_detection'], 'not_evaluated')
            self.assertFalse(result['calibrated'])
            self.assertEqual(violations(), before)

    def test_script_tags_in_comments_are_not_reported_as_real_scripts(self):
        source = '<!-- <script>eval("comment")</script> --><script>console.log("real")</script>'
        result = DeobfuscationEngine().deobfuscate_html(source)
        scripts = result['javascript_analysis']['inline_scripts']
        self.assertEqual(len(scripts),1)
        self.assertEqual(scripts[0]['content'],'console.log("real")')
        self.assertEqual(result['javascript_analysis']['suspicious_patterns'],[])

    def test_data_uri_decoding_is_separate_and_never_rewrites_an_attribute(self):
        payload = '<form action="https://example.invalid"><input type="password"></form>'
        token = base64.b64encode(payload.encode()).decode()
        source = '<iframe src="data:text/html;base64,'+token+'"></iframe>'
        result = DeobfuscationEngine().deobfuscate_html(source)
        self.assertEqual(result['final_html'], source)
        self.assertEqual(result['form_analysis']['forms'], [])
        candidate, = result['encoded_attribute_candidates']['candidates']
        self.assertEqual(candidate['decoded_text'], payload)
        self.assertTrue(candidate['candidate_only'])
        self.assertFalse(candidate['network_target'])

    def test_binary_invalid_and_oversized_data_uris_are_not_lossily_decoded(self):
        for token,status in ((base64.b64encode(b'\xff\xfe\x00').decode(),'opaque_bytes'),
                             ('not!base64','invalid'), ('A'*16385,'partial')):
            source = '<img src="data:image/png;base64,'+token+'">'
            with self.subTest(status=status):
                result = HTMLDeobfuscator().deobfuscate_html(source)
                self.assertEqual(result['final_html'], source)
                candidate, = result['encoded_attribute_candidates']['candidates']
                self.assertEqual(candidate['status'], status)
                self.assertIsNone(candidate.get('decoded_text'))

    def test_missing_optional_parser_is_explicit_without_a_completed_result(self):
        with patch('paw.deobfuscate.html.HAS_BEAUTIFULSOUP',False):
            result = DeobfuscationEngine().analyze_artifacts({'html':'<p>hello &amp; world</p>'})
        html = result['deobfuscated_artifacts']['html']
        self.assertEqual(html['assessment_status'], 'partial')
        self.assertEqual(html['parsing_status'], 'not_evaluated')
        self.assertEqual(result['coverage']['html']['status'], 'partial')
        self.assertIsNone(result['suspicion_score'])

    def test_attribute_candidate_and_node_limits_are_explicit(self):
        for source,expected in (('<img src="data:text/plain;base64,YQ==">'*33,32),
                                ('<div></div>'*1024+'<img src="data:text/plain;base64,YQ==">',0)):
            with self.subTest(expected=expected):
                result = HTMLDeobfuscator().deobfuscate_html(source)
                self.assertEqual(result['final_html'],source)
                self.assertEqual(result['encoded_attribute_candidates']['status'],'partial')
                self.assertEqual(len(result['encoded_attribute_candidates']['candidates']),expected)
                self.assertEqual(result['assessment_status'],'partial')

    def test_html_only_and_mixed_results_expose_descriptive_coverage(self):
        engine = DeobfuscationEngine()
        only = engine.analyze_artifacts({'html':'<p>A &amp; B</p>'})
        self.assertEqual(only['assessment_status'], 'descriptive_only')
        self.assertIsNone(only['suspicion_score'])
        self.assertEqual(only['coverage']['html']['risk_detection'], 'not_evaluated')
        with offline_policy(True):
            score = score_case({}, {}, {'domain':'example.org'}, profile='strict',
                               headers={'deobfuscation_analysis':only})
        self.assertEqual(score['score_components']['deobfuscation_heuristics'], 0)
        mixed = engine.analyze_artifacts({'html':'<p>A &amp; B</p>', 'urls':['hxxps://example[.]invalid']})
        self.assertEqual(mixed['assessment_status'], 'partial')
        self.assertGreater(mixed['suspicion_score'], 0)

    def test_direct_and_engine_html_schemas_match_and_reanalysis_is_idempotent(self):
        source = '<p>&amp;amp; &lt;strong&gt;Caffè&lt;/strong&gt;</p>'
        direct = HTMLDeobfuscator().deobfuscate_html(source)
        engine = DeobfuscationEngine().deobfuscate_html(source)
        self.assertEqual(engine, direct)
        self.assertEqual(DeobfuscationEngine().deobfuscate_html(engine['final_html']), engine)


if __name__ == '__main__':
    unittest.main()
