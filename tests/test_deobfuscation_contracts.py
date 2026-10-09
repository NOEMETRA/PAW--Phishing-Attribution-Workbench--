"""Text observations preserve evidence; fixtures do not establish accuracy."""
import unittest

from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case
from paw.deobfuscate.core import DeobfuscationEngine
from paw.deobfuscate.text import TextDeobfuscator


class TextDeobfuscationContracts(unittest.TestCase):
    def test_ordinary_text_is_not_rewritten_into_obfuscation_evidence(self):
        samples = ('Hello! Invoice 12345 costs 24.95 EUR. Order ID 67890.',
                   'Caffè già pagato: 2,95 €; Noël, São Paulo, Straße.',
                   'Release v1.4.5\n  ALL CAPS API docs: https://example.invalid/a%2Fb?x=1&y=2',
                   'pls msg ur team; login ID 2; pwd is a variable name.',
                   'first sentence! second sentence? third sentence.\n', '',
                   'a' * 10000)
        for sample in samples:
            for analyzer in (TextDeobfuscator(), DeobfuscationEngine()):
                with self.subTest(sample=sample[:40], analyzer=type(analyzer).__name__):
                    result = analyzer.deobfuscate_text(sample)
                    self.assertEqual(result['original_text'], sample)
                    self.assertEqual(result['final_text'], sample)
                    self.assertEqual(result['transformations'], [])
                    self.assertEqual(result['suspicion_score'], 0)
                    self.assertEqual(result['assessment_status'], 'descriptive_only')

    def test_visual_comparison_is_separate_from_original_text_and_risk(self):
        sample = 'Paypa1: рayраl, gοοgle. Привет мир! Καλημέρα!'
        result = DeobfuscationEngine().deobfuscate_text(sample)
        comparison = result['visual_comparison']
        self.assertTrue(comparison['comparison_only'])
        self.assertFalse(comparison['complete_unicode_confusables_coverage'])
        self.assertNotEqual(comparison['text'], sample)
        self.assertEqual(result['final_text'], sample)
        self.assertEqual(result['suspicion_score'], 0)
        self.assertEqual(result['transformations'], [])

    def test_text_observations_do_not_inflate_final_attribution_score(self):
        engine = DeobfuscationEngine()
        with offline_policy(True):
            for text in ('Hello world. Version 1234!', 'URGENT verify your account', 'рayраl login'):
                result = engine.analyze_artifacts({'text':text})
                score = score_case({}, {}, {'domain':'example.org'}, profile='strict',
                                   headers={'deobfuscation_analysis':result})
                self.assertEqual(score['score_components']['deobfuscation_heuristics'], 0)
                self.assertEqual(score['decision_score'], .05)
                self.assertEqual(result['suspicion_score'], 0)
                self.assertEqual(result['techniques_detected'], [])
                self.assertEqual(violations(), [])

    def test_repeated_analysis_does_not_change_text_or_create_layers(self):
        sample = 'ALL CAPS! ID: 12345.\nEmail: hello@example.invalid.  2,95 €'
        engine = DeobfuscationEngine()
        result = engine.deobfuscate_text(sample)
        self.assertEqual(engine.deobfuscate_text(result['final_text']), result)

    def test_actual_encoded_urls_keep_the_url_specific_contract(self):
        engine = DeobfuscationEngine()
        source = 'hxxps://example[.]invalid/a%2Fb?x=a%26b'
        result = engine.analyze_artifacts({'text':source, 'urls':[source]})
        url, = result['deobfuscated_artifacts']['urls']
        self.assertEqual(result['deobfuscated_artifacts']['text']['final_text'], source)
        self.assertEqual(url['final_url'], 'https://example.invalid/a%2Fb?x=a%26b')
        self.assertGreater(url['suspicion_score'], 0)
        self.assertGreater(len(url['transformations']), 0)


if __name__ == '__main__':
    unittest.main()
