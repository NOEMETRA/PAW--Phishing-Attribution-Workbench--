"""Legacy TLD-list spelling contracts; no domain reputation or accuracy labels."""
import json
import unittest
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_eml_bytes
from paw.core.scoring import risky_tlds, score_case


class TldContracts(unittest.TestCase):
    def score(self,domain='example.click',headers=None,**kwargs):
        return score_case({}, {}, {'domain':domain},headers={'from':'a@example.click'} if headers is None else headers,**kwargs)

    def observation(self,**kwargs):
        return self.score(**kwargs)['sender_domain_observations']['tld_comparison']

    def test_normalized_case_and_root_dot_hints_retain_one_contribution(self):
        for domain in ('example.click','EXAMPLE.CLICK','example.click.'):
            with self.subTest(domain=domain):
                score=self.score(domain)
                self.assertEqual(score['score_components']['sender_domain_heuristics'],.1)
                record=score['sender_domain_observations']['tld_comparison']
                self.assertEqual(record,self.observation())

    def test_incomplete_or_ambiguous_from_cannot_promote_a_hint(self):
        invalid=({'from':None},{'from_header_count':1},{'from_identity':None},
                 {'from':'a@example.click','from_header_count':2},
                 {'from':'a@example.click','from_identity':{'status':'partial'}},
                 {'from':'a@other.com'},{'from':'Group: a@example.click;'},
                 parse_eml_bytes(b'Subject: Missing\r\n\r\nhello'))
        for headers in invalid:
            for version in (headers,json.loads(json.dumps(headers))):
                with self.subTest(headers=version):
                    score=self.score(headers=version)
                    self.assertEqual(score['score_components']['sender_domain_heuristics'],0)
                    record=score['sender_domain_observations']['tld_comparison']
                    self.assertEqual(record['status'],'not_evaluated')
                    self.assertEqual(record['source'],'message_headers')
                    self.assertIsNone(record['listed'])
                    self.assertIsNone(record['tld'])
                    self.assertIsNone(record['result'])
                    self.assertEqual(record['contribution'],0)
                    self.assertIn('tld_comparison',score['coverage']['not_evaluated'])

    def test_original_and_json_from_defects_block_the_rule(self):
        for raw in (b'From: Name\xff <a@example.click>\r\n\r\nhello',
                    b'From: a@example.click.\r\n\r\nhello'):
            headers=parse_eml_bytes(raw)
            first=self.score(headers=headers)
            second=self.score(headers=json.loads(json.dumps(headers)))
            self.assertEqual(first,second)
            self.assertEqual(first['score_components']['sender_domain_heuristics'],0)

    def test_field_defect_metadata_survives_clean_rendered_from(self):
        score=self.score(headers={'from':'a@example.click','header_field_defects':[{'field':'From'}]})
        self.assertEqual(score['score_components']['sender_domain_heuristics'],0)

    def test_valid_unlisted_suffix_does_not_establish_reputation(self):
        record=self.observation(domain='example.com',headers={'from':'a@example.com'})
        self.assertEqual(record['status'],'observed_unverified')
        self.assertEqual(record['result'],'not_listed')
        self.assertIs(record['listed'],False)
        self.assertEqual(record['contribution'],0)
        self.assertIs(record['verified'],False)
        self.assertEqual(record['reputation_status'],'not_evaluated')

    def test_unknown_suffix_is_only_a_final_label_observation(self):
        record=self.observation(domain='example.invalid',headers={'from':'a@example.invalid'})
        self.assertEqual(record['tld'],'.invalid')
        self.assertEqual(record['scope'],'normalized_final_domain_label_static_list')
        self.assertEqual(record['reputation_status'],'not_evaluated')
        self.assertEqual(record['contribution'],0)

    def test_headerless_legacy_hint_is_explicitly_sourced(self):
        record=self.observation(headers={})
        self.assertEqual(record['source'],'supplied_domain')
        self.assertEqual(record['contribution'],.1)
        self.assertIs(record['verified'],False)

    def test_missing_invalid_and_single_label_domains_are_unevaluated(self):
        for domain in ('','click','example..click','x'*64+'.click'):
            with self.subTest(domain=domain):
                record=self.observation(domain=domain,headers={})
                self.assertEqual(record['status'],'not_evaluated')
                self.assertIsNone(record['listed'])
                self.assertEqual(record['contribution'],0)

    def test_static_list_and_weight_are_preserved(self):
        self.assertEqual(risky_tlds(),{'.click','.icu','.cfd','.rest','.tk','.gq','.ml','.ga','.cf'})
        for suffix in risky_tlds():
            record=self.observation(domain='example'+suffix,headers={})
            self.assertEqual(record['result'],'listed')
            self.assertEqual(record['listed_tlds'],sorted(risky_tlds()))
            self.assertEqual(record['contribution'],.1)

    def test_subdomain_label_is_not_a_tld_match(self):
        record=self.observation(domain='click.example.com',headers={})
        self.assertEqual(record['tld'],'.com')
        self.assertEqual(record['contribution'],0)

    def test_other_domain_contributions_remain_separate(self):
        score=score_case({}, {}, {'domain':'mail.paypa1.click','nrd_days':10},headers={'from':'a@mail.paypa1.click'})
        self.assertAlmostEqual(score['score_components']['sender_domain_heuristics'],.45)
        self.assertEqual(score['sender_domain_observations']['domain_brand_comparison']['contribution'],.2)
        self.assertEqual(score['sender_domain_observations']['tld_comparison']['contribution'],.1)

    def test_observation_attempts_no_egress(self):
        before=len(violations())
        with offline_policy(True):
            record=self.observation()
        self.assertEqual(record['contribution'],.1)
        self.assertEqual(len(violations()),before)


if __name__=='__main__': unittest.main()
