"""Text observations preserve evidence; fixtures do not establish accuracy."""
import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

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
                self.assertIsNone(result['suspicion_score'])
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

    def test_direct_and_engine_text_apis_share_the_declared_indicator_schema(self):
        for sample in ('', 'URGENT verify your account', 'рayраl'):
            with self.subTest(sample=sample):
                direct = TextDeobfuscator().deobfuscate_text(sample)
                self.assertEqual(direct['suspicion_indicators'], [])
                self.assertEqual(direct, DeobfuscationEngine().deobfuscate_text(sample))

    def test_top_level_distinguishes_text_observations_from_nontext_heuristics(self):
        engine = DeobfuscationEngine()
        for sample in ('', 'hello', 'URGENT verify your password', 'рayраl'):
            with self.subTest(sample=sample):
                result = engine.analyze_artifacts({'text':sample, 'urls':[], 'html':'', 'javascript':''})
                self.assertEqual(result['assessment_status'], 'descriptive_only')
                self.assertIsNone(result['suspicion_score'])
                self.assertEqual(result['complexity_rating'], 'not_evaluated')
                self.assertEqual(result['coverage']['text']['risk_detection'], 'not_evaluated')
                self.assertEqual(result['coverage']['text']['status'], 'descriptive_only')
                self.assertFalse(result['calibrated'])
        mixed = engine.analyze_artifacts({'text':'URGENT verify account', 'urls':['hxxps://example[.]invalid']})
        self.assertEqual(mixed['assessment_status'], 'partial')
        self.assertGreater(mixed['suspicion_score'], 0)
        self.assertEqual(mixed['score_scope'], 'nontext_transformations_only')
        self.assertEqual(mixed['coverage']['text']['risk_detection'], 'not_evaluated')
        url_only = engine.analyze_artifacts({'urls':['https://example.invalid']})
        self.assertEqual(url_only['assessment_status'], 'heuristic_only')
        self.assertEqual(url_only['coverage']['text']['status'], 'not_evaluated')
        empty = engine.analyze_artifacts({})
        self.assertEqual(empty['assessment_status'], 'not_evaluated')
        self.assertIsNone(empty['suspicion_score'])

    def test_human_cli_and_json_expose_unassessed_text_instead_of_negative_detection(self):
        from paw.__main__ import main
        sample = 'URGENT verify your account and enter your password'
        with tempfile.TemporaryDirectory(prefix='paw-text-cli-') as temporary:
            source = Path(temporary) / 'sample.txt'
            source.write_text(sample, encoding='utf-8')
            for option, value in (('--text',sample), ('--file',str(source))):
                output = io.StringIO()
                with offline_policy(True), patch('sys.argv',['paw','deobfuscate',option,value]), contextlib.redirect_stdout(output):
                    main()
                self.assertIn('descriptive_only', output.getvalue())
                self.assertIn('not_evaluated', output.getvalue())
                self.assertNotIn('Suspicion Score:', output.getvalue())
                self.assertNotIn('Complexity: none', output.getvalue())
            output = io.StringIO()
            with offline_policy(True), patch('sys.argv',['paw','deobfuscate','--text',sample,'--json']), contextlib.redirect_stdout(output):
                main()
            data = json.loads(output.getvalue())
            self.assertIsNone(data['suspicion_score'])
            self.assertEqual(data['assessment_status'], 'descriptive_only')
            output = io.StringIO()
            with offline_policy(True), patch('sys.argv',['paw','deobfuscate','--url','hxxps://example[.]invalid']), contextlib.redirect_stdout(output):
                main()
            self.assertIn('nontext_transformations_only', output.getvalue())
            self.assertIn('Text risk detection: not_evaluated', output.getvalue())


if __name__ == '__main__':
    unittest.main()
