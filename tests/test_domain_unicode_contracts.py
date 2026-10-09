"""Domain representations are observations, not phishing labels."""
import unittest

from paw.core.scoring import score_case, is_mixed_script


class DomainUnicodeContracts(unittest.TestCase):
    def score(self, domain, headers=None):
        return score_case({}, {}, {'domain':domain}, headers=headers)

    def test_unicode_and_ace_do_not_add_automatic_risk(self):
        for domain in ('café.invalid', 'пример.рф', 'exаmple.invalid'):
            ace = domain.encode('idna').decode('ascii')
            with self.subTest(domain=domain):
                for spelling in (domain, ace):
                    result = self.score(spelling)
                    self.assertEqual(result['score_components']['sender_domain_heuristics'], 0)
                    self.assertIsNone(result['mixed_flag'])
                self.assertEqual(self.score(domain)['raw_score'], self.score(ace)['raw_score'])

    def test_legacy_mixed_script_helper_does_not_claim_script_analysis(self):
        for value in ('example.invalid', 'café.invalid', 'xn--caf-dma.invalid', None):
            self.assertIsNone(is_mixed_script(value))

    def test_idn_observation_has_representation_parity(self):
        unicode = self.score('café.invalid')['sender_domain_observations']['unicode_domain']
        ace = self.score('XN--CAF-DMA.INVALID.')['sender_domain_observations']['unicode_domain']
        for record in (unicode, ace):
            self.assertEqual(record['status'], 'observed_unverified')
            self.assertEqual(record['normalized_domain'], 'xn--caf-dma.invalid')
            self.assertEqual(record['unicode_domain'], 'café.invalid')
            self.assertIs(record['decoded_non_ascii'], True)
            self.assertIs(record['verified'], False)
            self.assertEqual(record['script_analysis_status'], 'not_evaluated')
            self.assertEqual(record['contribution'], 0)

    def test_ascii_is_descriptive_and_scripts_remain_unevaluated(self):
        record = self.score('example.invalid')['sender_domain_observations']['unicode_domain']
        self.assertIs(record['decoded_non_ascii'], False)
        self.assertIs(record['mixed_script'], None)

    def test_bad_ace_has_partial_observation(self):
        record = self.score('xn--a.invalid')['sender_domain_observations']['unicode_domain']
        self.assertEqual(record['status'], 'partial')
        self.assertIsNone(record['unicode_domain'])
        self.assertIsNone(record['decoded_non_ascii'])
        self.assertEqual(record['contribution'], 0)

    def test_from_metadata_gates_unicode_observation(self):
        for headers in ({'from_header_count':2}, {'from_identity':{'status':'partial'}},
                        {'header_field_defects':[{'field':'From'}]},
                        {'from':'a@other.invalid'}, {'from':'Group: a@café.invalid;'}):
            with self.subTest(headers=headers):
                record = self.score('café.invalid', headers)['sender_domain_observations']['unicode_domain']
                self.assertEqual(record['status'], 'unavailable')
                self.assertIsNone(record['normalized_domain'])
                self.assertIsNone(record['decoded_non_ascii'])
                self.assertEqual(record['contribution'], 0)

    def test_missing_domain_is_unknown(self):
        record = self.score('')['sender_domain_observations']['unicode_domain']
        self.assertEqual(record['status'], 'unavailable')
        self.assertIsNone(record['decoded_non_ascii'])

    def test_existing_other_contributions_remain(self):
        self.assertEqual(self.score('a.click')['score_components']['sender_domain_heuristics'], .1)
        self.assertEqual(self.score('example.invalid', {'from':'Apple <a@example.invalid>'})
                         ['score_components']['sender_domain_heuristics'], .2)
        self.assertEqual(self.score('example.invalid', {'reply_to':'b@other.invalid'})
                         ['score_components']['sender_domain_heuristics'], .15)


if __name__ == '__main__':
    unittest.main()
