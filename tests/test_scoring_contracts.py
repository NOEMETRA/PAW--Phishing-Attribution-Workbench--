"""Score explanations and numeric boundaries, not classifier accuracy fixtures."""
import math
import unittest

from paw.core.network_policy import offline_policy
from paw.core.scoring import score_case, finalize_score


class ScoringContracts(unittest.TestCase):
    def test_additions_cannot_impersonate_engine_owned_components(self):
        import copy
        names = ('header_observations', 'verified_authentication_failures',
                 'sender_domain_heuristics', 'deobfuscation_heuristics',
                 'dynamic_observations', 'profile_modifier', 'legacy_base')
        for name in names:
            for legacy in (False, True):
                original = {'score':0} if legacy else score_case({}, {}, {'domain':'example.org'})
                result = copy.deepcopy(original)
                with self.subTest(name=name, legacy=legacy), self.assertRaises(ValueError):
                    finalize_score(result, additional_components={name:.4})
                self.assertEqual(result, original)

    def test_subthreshold_values_within_old_tolerance_stay_below_the_boundary(self):
        for profile, suspicious, malicious in (('default',.55,.72),('strict',.52,.68),('conservative',.58,.76)):
            for threshold, decision in ((suspicious,'Inconclusive'),
                                        (malicious,'Suspicious or compromised account')):
                for value in (threshold-5e-13, math.nextafter(threshold, -math.inf)):
                    with self.subTest(profile=profile, threshold=threshold, value=value):
                        result = finalize_score({'score':value}, profile)
                        self.assertLess(result['decision_score'], threshold)
                        self.assertEqual(result['decision'], decision)

    def test_deobfuscation_can_produce_a_genuinely_subthreshold_value(self):
        result = score_case({'skew_s':601, 'fqdn_ok':False}, {}, {'domain':'example.org'},
            profile='strict', headers={'deobfuscation_analysis':{'deobfuscated_artifacts':{
                'text':{'suspicion_score':(.52-5e-13-.35)/.18}}}})
        self.assertLess(result['decision_score'], .52)
        self.assertEqual(result['decision'], 'Inconclusive')
        self.assertEqual(finalize_score(result)['decision'], 'Inconclusive')

    def test_version_two_profile_changes_are_rejected_without_mutation(self):
        import copy
        for original_profile in ('default', 'strict', 'conservative'):
            for requested_profile in ('default', 'strict', 'conservative'):
                if requested_profile == original_profile:
                    continue
                original = score_case({}, {}, {'domain':'example.org'}, profile=original_profile)
                result = copy.deepcopy(original)
                with self.subTest(original=original_profile, requested=requested_profile), self.assertRaises(ValueError):
                    finalize_score(result, requested_profile, additional=.1)
                self.assertEqual(result, original)

    def test_finalize_cannot_promote_a_score_rounded_up_to_threshold(self):
        with offline_policy(True):
            result = score_case({'skew_s':601, 'fqdn_ok':False}, {}, {'domain':'example.org'},
                profile='strict', headers={'deobfuscation_analysis':{
                    'deobfuscated_artifacts':{'text':{'suspicion_score':.94}}}})
        self.assertEqual(result['score'], .52)
        self.assertEqual(result['decision'], 'Inconclusive')
        self.assertEqual(finalize_score(result, 'strict')['decision'], 'Inconclusive')
        self.assertAlmostEqual(result['decision_score'], .5192)

    def test_additions_use_unrounded_base_and_keep_named_components(self):
        result = score_case({'skew_s':601}, {}, {'domain':'example.org'}, profile='strict',
            headers={'deobfuscation_analysis':{'deobfuscated_artifacts':{'text':{'suspicion_score':.94}}}})
        result = finalize_score(result, 'strict', additional_components={'received_time_order':.1})
        self.assertEqual(result['decision'], 'Inconclusive')
        self.assertAlmostEqual(result['raw_score'], .5192)
        self.assertEqual(result['score_components']['received_time_order'], .1)
        self.assertAlmostEqual(math.fsum(result['score_components'].values()), result['raw_score'])

    def test_components_separate_verified_failure_from_header_observations(self):
        auth = {'spf':{'verification':{'status':'completed','result':'fail'}},
                'dkim':{'verification':{'status':'not_evaluated','result':'fail'}}}
        result = score_case({'fqdn_ok':False}, auth, {'domain':'example.org'})
        self.assertEqual(result['score_components']['verified_authentication_failures'], .4)
        self.assertAlmostEqual(result['score_components']['header_observations'], .1)
        self.assertFalse(result['calibrated'])
        self.assertEqual(result['decision_scope'], 'heuristic_attribution_review')
        self.assertIn('unverified', result['component_sources']['header_observations'])

    def test_negative_profile_offset_survives_clipping_before_additions(self):
        result = score_case({}, {}, {'domain':'example.org'}, profile='conservative')
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['raw_score'], -.05)
        result = finalize_score(result, 'conservative', additional=.02)
        self.assertEqual(result['score'], 0)
        self.assertAlmostEqual(result['raw_score'], -.03)

    def test_legacy_plain_score_inputs_still_accept_additional_signals(self):
        result = finalize_score({'score':.65}, 'strict', additional=.1)
        self.assertEqual(result['decision'], 'Likely malicious infrastructure')
        self.assertAlmostEqual(result['raw_score'], .75)
        self.assertEqual(result['score_components']['legacy_base'], .65)
        self.assertEqual(result['score_components']['additional_signals'], .1)

    def test_finalizing_twice_without_new_signals_is_idempotent(self):
        result = score_case({}, {}, {'domain':'example.org'}, profile='strict')
        first = finalize_score(result, 'strict', additional_components={'received_structure':.05})
        import copy
        expected = copy.deepcopy(first)
        self.assertEqual(finalize_score(first, 'strict'), expected)
        self.assertEqual(finalize_score(first), expected)

    def test_exact_thresholds_and_profiles_remain_defined(self):
        for profile, suspicious, malicious in (('default',.55,.72),('strict',.52,.68),('conservative',.58,.76)):
            with self.subTest(profile=profile):
                for value, decision in ((suspicious-.0001,'Inconclusive'),
                    (suspicious,'Suspicious or compromised account'),
                    (malicious-.0001,'Suspicious or compromised account'),
                    (malicious,'Likely malicious infrastructure')):
                    result = finalize_score({'score':value}, profile)
                    self.assertEqual(result['decision'], decision)
                    self.assertEqual(result['thresholds'], {'suspicious':suspicious,'malicious':malicious})

    def test_nonfinite_raw_components_or_additions_cannot_create_verdicts(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                finalize_score({'score':0, 'raw_score':value})
            with self.assertRaises(ValueError):
                finalize_score({'score':0}, additional_components={'extra':value})
            with self.assertRaises(ValueError):
                score_case({}, {}, {'domain':'example.org'}, headers={
                    'deobfuscation_analysis':{'deobfuscated_artifacts':{'text':{'suspicion_score':value}}}})

    def test_manual_display_score_mutation_cannot_silently_override_components(self):
        result = score_case({}, {}, {'domain':'example.org'})
        result['score'] = .9
        with self.assertRaises(ValueError):
            finalize_score(result)

    def test_component_mismatch_cannot_be_published_as_a_valid_explanation(self):
        result = score_case({}, {}, {'domain':'example.org'})
        result['score_components']['unexpected'] = .5
        with self.assertRaises(ValueError):
            finalize_score(result)

    def test_nonfinite_url_is_rejected_even_when_max_could_hide_it(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                score_case({}, {}, {'domain':'example.org'}, headers={
                    'deobfuscation_analysis':{'deobfuscated_artifacts':{'urls':[
                        {'suspicion_score':.5}, {'suspicion_score':value}]}}})

    def test_component_names_and_boolean_signals_are_rejected(self):
        for component in ({'extra':True}, {'':.1}, {1:.1}):
            with self.subTest(component=component), self.assertRaises(ValueError):
                finalize_score({'score':0}, additional_components=component)
        with self.assertRaises(ValueError):
            finalize_score({'score':0, 'score_components':{'':0}})

    def test_false_or_empty_numeric_deobfuscation_values_are_not_missing_evidence(self):
        for value in (False, True, ''):
            for part in ('text', 'html', 'urls'):
                artifact = [{'suspicion_score':value}] if part == 'urls' else {'suspicion_score':value}
                with self.subTest(value=value, part=part), self.assertRaises(ValueError):
                    score_case({}, {}, {'domain':'example.org'}, headers={
                        'deobfuscation_analysis':{'deobfuscated_artifacts':{part:artifact}}})


if __name__ == '__main__':
    unittest.main()
