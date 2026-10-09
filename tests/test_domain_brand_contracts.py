"""Bounded domain spelling contracts, not verified brand ownership or labels."""
import json
import unittest
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_eml_bytes
from paw.core.scoring import score_case


class DomainBrandContracts(unittest.TestCase):
    def score(self,domain,headers=None,**kwargs):
        return score_case({}, {}, {'domain':domain},headers={'from':'a@'+domain} if headers is None else headers,**kwargs)

    def observation(self,domain,**kwargs):
        return self.score(domain,**kwargs)['sender_domain_observations']['domain_brand_comparison']

    def test_transport_label_does_not_hide_registrable_lookalike(self):
        for domain in ('paypa1.com','mail.paypa1.com','mx.mail.paypa1.com','mail.paypa1.co.uk'):
            with self.subTest(domain=domain):
                result=self.score(domain)
                self.assertEqual(result['score_components']['sender_domain_heuristics'],.2)
                self.assertEqual(result['bk_score'],.83)

    def test_actual_brand_spelling_has_no_automatic_domain_risk(self):
        for domain in ('paypal.com','mail.paypal.com','google.com','accounts.google.com'):
            self.assertEqual(self.score(domain)['score_components']['sender_domain_heuristics'],0)

    def test_leftmost_and_exact_subdomain_signals_are_retained(self):
        for domain in ('paypa1.attacker.com','paypal.attacker.com','google.github.io'):
            self.assertEqual(self.score(domain)['score_components']['sender_domain_heuristics'],.2)

    def test_two_lookalike_labels_add_only_one_domain_contribution(self):
        self.assertEqual(self.score('appl3.paypa1.com')['score_components']['sender_domain_heuristics'],.2)

    def test_private_tenant_registrable_label_is_compared(self):
        record=self.observation('mail.paypa1.github.io')
        self.assertEqual(record['registrable_domain'],'paypa1.github.io')
        self.assertIs(record['private_suffix'],True)
        self.assertEqual(record['contribution'],.2)

    def test_public_suffix_labels_are_not_brand_candidates(self):
        record=self.observation('mail.example.co.uk')
        self.assertEqual([row['label'] for row in record['comparisons']],['mail','example'])

    def test_unknown_suffix_keeps_leftmost_comparison_with_partial_coverage(self):
        record=self.observation('paypa1.invalid')
        self.assertEqual(record['status'],'partial')
        self.assertIsNone(record['registrable_domain'])
        self.assertEqual(record['contribution'],.2)
        self.assertEqual(len(record['comparisons']),1)

    def test_domain_only_legacy_input_is_attributed_to_supplied_hint(self):
        result=score_case({}, {}, {'domain':'mail.paypa1.com'})
        record=result['sender_domain_observations']['domain_brand_comparison']
        self.assertEqual(record['source'],'supplied_domain')
        self.assertEqual(record['contribution'],.2)
        self.assertIs(record['verified'],False)
        self.assertEqual(record['ownership_status'],'not_evaluated')

    def test_missing_or_defective_identity_does_not_create_similarity_evidence(self):
        for headers in ({'from_header_count':0},{'from_header_count':2},
                        {'from_identity':{'status':'partial'}},
                        {'from':'a@other.com'}, {'from':'Group: a@paypa1.com;'},
                        {'from':'a@paypa1.com','header_field_defects':[{'field':'From'}]}):
            with self.subTest(headers=headers):
                result=self.score('paypa1.com',headers=headers)
                record=result['sender_domain_observations']['domain_brand_comparison']
                self.assertEqual(record['status'],'not_evaluated')
                self.assertIsNone(record['max_similarity'])
                self.assertIsNone(result['bk_score'])
                self.assertEqual(record['contribution'],0)
                self.assertIn('domain_brand_comparison',result['coverage']['not_evaluated'])
                self.assertEqual(result['score_components']['sender_domain_heuristics'],0)

    def test_json_preserves_original_identity_defects(self):
        headers=parse_eml_bytes(b'From: Name\xff <a@paypa1.com>\r\n\r\nhello')
        first=self.score('paypa1.com',headers=headers)
        second=self.score('paypa1.com',headers=json.loads(json.dumps(headers)))
        self.assertEqual(first,second)
        self.assertEqual(first['score_components']['sender_domain_heuristics'],0)

    def test_normalized_case_and_direct_root_dot_are_equivalent(self):
        first=score_case({}, {}, {'domain':'mail.paypa1.com'})
        second=score_case({}, {}, {'domain':'MAIL.PAYPA1.COM.'})
        self.assertEqual(first['sender_domain_observations']['domain_brand_comparison'],
                         second['sender_domain_observations']['domain_brand_comparison'])

    def test_similarity_threshold_is_unrounded_and_unchanged(self):
        for label,expected in (('abcdefgxxx',.2),('abcdefxxxx',0),('abcdefghij',0)):
            self.assertEqual(self.score(label+'.com',brand_seeds=['abcdefghij'])['score_components']['sender_domain_heuristics'],expected)

    def test_missing_or_invalid_domain_has_unknown_similarity(self):
        for domain in ('','a..com','paypa1'+'x'*64+'.com'):
            result=score_case({}, {}, {'domain':domain})
            self.assertIsNone(result['bk_score'])
            self.assertEqual(result['sender_domain_observations']['domain_brand_comparison']['status'],'not_evaluated')

    def test_local_suffix_extraction_attempts_no_egress(self):
        before=len(violations())
        with offline_policy():
            record=self.observation('mail.paypa1.github.io')
        self.assertEqual(record['contribution'],.2)
        self.assertEqual(len(violations()),before)


if __name__=='__main__': unittest.main()
