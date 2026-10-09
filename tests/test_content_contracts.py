"""Uncalibrated content observations cannot authorize actions or infer safety."""
import unittest

from paw.core.ml_scorer import MLScorer, get_ml_scorer, score_email_for_canary
from paw.core.network_policy import offline_policy, violations
from paw.core.scoring import score_case, finalize_score


class ContentContracts(unittest.TestCase):
    def setUp(self):
        self.scorer = MLScorer()

    def test_neutral_length_does_not_create_risk_or_recommend_actions(self):
        for length in (0, 100, 600, 100000):
            with self.subTest(length=length):
                result = self.scorer.score_email({'body': 'a' * length})
                self.assertEqual(result['phishing_score'], 0)
                self.assertEqual(result['risk_level'], 'not_evaluated')
                self.assertFalse(result['recommendations']['block_email'])
                self.assertFalse(result['recommendations']['inject_canary'])
                self.assertFalse(result['recommendations']['flag_for_review'])

    def test_style_is_measured_from_original_case_but_not_scored(self):
        lower = self.scorer.score_email({'body': 'plain text'})
        upper = self.scorer.score_email({'body': 'PLAIN TEXT!!!???'})
        self.assertGreater(upper['features']['capitalization_ratio'], 0)
        self.assertEqual(lower['features']['capitalization_ratio'], 0)
        self.assertEqual(upper['features']['exclamation_marks'], 3)
        self.assertEqual(upper['features']['question_marks'], 3)
        self.assertEqual(lower['phishing_score'], upper['phishing_score'])
        self.assertEqual(upper['recommendations'], lower['recommendations'])

    def test_missing_sender_is_coverage_not_a_reputation_penalty(self):
        for data in ({}, {'from': None, 'subject': None, 'body': None}, {'from': 'not-an-address'}):
            with self.subTest(data=data):
                result = self.scorer.score_email(data)
                self.assertEqual(result['features']['sender_pattern_score'], 0)
                self.assertEqual(result['phishing_score'], 0)
                self.assertFalse(result['coverage']['sender_verified'])
                self.assertNotEqual(result['coverage']['sender_syntax'], 'parsed')

    def test_indicator_sum_has_visible_contributions_and_no_operational_actions(self):
        text = ' '.join(self.scorer.urgency_words + self.scorer.threat_words)
        result = self.scorer.score_email({'body': text + ' ID: 123456 customer support security team',
                                         'from': 'user12345@many-labels.example.xyz'})
        self.assertGreater(result['phishing_score'], 0)
        self.assertAlmostEqual(sum(result['contributions'].values()), result['phishing_score'])
        self.assertTrue(result['recommendations']['flag_for_review'])
        self.assertFalse(result['recommendations']['block_email'])
        self.assertFalse(result['recommendations']['inject_canary'])
        self.assertEqual(result['risk_level'], 'not_evaluated')
        self.assertFalse(result['calibrated'])
        self.assertEqual(result['assessment_status'], 'heuristic_only')
        self.assertEqual(result['schema_version'], 2)
        self.assertIn('not a probability', result['limitation'])
        self.assertEqual(set(result['contributions']), set(result['weights']))
        self.assertEqual(result['evidence']['urgency_score'], self.scorer.urgency_words)

    def test_nontextual_inputs_are_not_silently_treated_as_missing(self):
        for field in ('body', 'subject', 'from'):
            for value in (0, False, 123, [], b'urgent'):
                with self.subTest(field=field, value=value), self.assertRaises(TypeError):
                    self.scorer.score_email({field: value})

    def test_neutral_padding_and_punctuation_preserve_semantic_score(self):
        original = self.scorer.score_email({'body': 'Verify your account immediately'})
        padded = self.scorer.score_email({'body': 'Verify your account immediately ' + 'a' * 100000 + '!?' * 500})
        self.assertEqual(original['phishing_score'], padded['phishing_score'])
        self.assertEqual(original['contributions'], padded['contributions'])
        self.assertEqual(original['recommendations'], padded['recommendations'])

    def test_word_boundaries_do_not_match_incidental_substrings(self):
        result = self.scorer.score_email({'body': 'refundability importantissimo village login'})
        self.assertEqual(result['features']['urgency_score'], 0)
        self.assertEqual(result['features']['threat_score'], 0)
        self.assertEqual(result['features']['mixed_languages'], 0)

    def test_phrase_matching_accepts_case_and_whitespace(self):
        result = self.scorer.score_email({'subject': 'ACTION\tREQUIRED', 'body': 'Verify\nYour ACCOUNT'})
        self.assertIn('action required', result['evidence']['urgency_score'])
        self.assertIn('verify your account', result['evidence']['threat_score'])

    def test_sender_display_name_does_not_supply_address_patterns(self):
        ordinary = self.scorer.score_email({'from': 'ordinary@example.org'})
        display = self.scorer.score_email({'from': '"Project 123456 -- a.b.c.xyz" <ordinary@example.org>'})
        self.assertEqual(ordinary['features']['sender_pattern_score'], display['features']['sender_pattern_score'])
        self.assertEqual(display['features']['sender_pattern_score'], 0)
        for address in ('user@example.xyz', 'User <USER@EXAMPLE.XYZ>'):
            result = self.scorer.score_email({'from': address})
            self.assertGreater(result['features']['sender_pattern_score'], 0)
            self.assertIn('listed_tld', result['evidence']['sender_pattern_score'])
            self.assertFalse(result['coverage']['sender_verified'])

    def test_auxiliary_observations_do_not_change_final_attribution_score(self):
        baseline = finalize_score(score_case({}, {}, {'domain': 'example.org'}, headers={}))
        result = finalize_score(score_case({}, {}, {'domain': 'example.org'}, headers={
            'ml_score': self.scorer.score_email({'body': 'urgent verify your account'}),
            'phishing_analysis': {'phishing_score': 1000}}))
        self.assertEqual(result, baseline)

    def test_legacy_entry_point_is_same_offline_non_operational_contract(self):
        before = len(violations())
        with offline_policy(True):
            result = score_email_for_canary({'body': 'urgent account suspended'})
            self.assertEqual(result, get_ml_scorer().score_email({'body': 'urgent account suspended'}))
        self.assertEqual(len(violations()), before)
        self.assertFalse(result['recommendations']['inject_canary'])
        self.assertFalse(result['recommendations']['block_email'])


if __name__ == '__main__':
    unittest.main()
