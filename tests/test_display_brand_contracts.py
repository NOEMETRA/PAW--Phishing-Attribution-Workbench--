"""Display-name/domain structure contracts; no ownership or phishing labels."""
import json
import unittest
from paw.core.scoring import score_case
from paw.core.parser_mail import parse_eml_bytes


class DisplayBrandContracts(unittest.TestCase):
    def score(self, domain, name='Google', headers=None):
        return score_case({}, {}, {'domain':domain},headers=headers if headers is not None else {'from':name+' <a@'+domain+'>'})

    def test_service_subdomains_do_not_invent_display_brand_mismatch(self):
        for domain in ('accounts.google.com','mail.accounts.google.com','accounts.google.co.uk'):
            self.assertEqual(self.score(domain)['score_components']['sender_domain_heuristics'],0)

    def test_existing_mismatch_and_hosted_namespace_risk_remain(self):
        for domain in ('news.attacker.com','news.google.github.io','news.google.blogspot.com','example.invalid'):
            self.assertEqual(self.score(domain)['score_components']['sender_domain_heuristics'],.2)

    def test_original_exact_subdomain_brand_rule_is_unchanged(self):
        self.assertEqual(self.score('google.attacker.com')['score_components']['sender_domain_heuristics'],.2)

    def test_claimed_brand_label_is_not_verified_ownership(self):
        record=self.score('accounts.google.com')['sender_domain_observations']['display_brand_comparison']
        self.assertEqual(record['result'],'registrable_label_match')
        self.assertEqual(record['public_registrable_domain'],'google.com')
        self.assertEqual(record['contribution'],0)
        self.assertIs(record['verified'],False)
        self.assertEqual(record['ownership_status'],'not_evaluated')

    def test_missing_or_disagreeing_from_domain_cannot_score_a_display_name(self):
        for domain,headers in (('',{'from':'Google <a@example.com>'}),
                               ('other.com',{'from':'Google <a@example.com>'}),
                               ('example.com',{'from':'Google <a@example.com>','from_header_count':2}),
                               ('example.com',{'from':'Google <a@example.com>','from_identity':{'status':'partial'}})):
            self.assertEqual(self.score(domain,headers=headers)['score_components']['sender_domain_heuristics'],0)

    def test_json_defects_are_preserved(self):
        headers=parse_eml_bytes(b'From: Google\xff <a@accounts.google.com>\r\n\r\nhello')
        first=self.score('accounts.google.com',headers=headers)
        second=self.score('accounts.google.com',headers=json.loads(json.dumps(headers)))
        self.assertEqual(first,second)
        record=first['sender_domain_observations']['display_brand_comparison']
        self.assertEqual(record['status'],'not_evaluated')
        self.assertIsNone(record['result'])

    def test_no_display_name_is_no_brand_match(self):
        record=self.score('example.com',headers={'from':'google@example.com'})['sender_domain_observations']['display_brand_comparison']
        self.assertEqual(record['result'],'no_brand_match')
        self.assertEqual(record['contribution'],0)

    def test_quoted_and_encoded_names_keep_same_result(self):
        records=[]
        for value in ('Google <a@accounts.google.com>','"Google" <a@accounts.google.com>',
                      '=?utf-8?b?R29vZ2xl?= <a@accounts.google.com>'):
            records.append(self.score('accounts.google.com',headers={'from':value})['sender_domain_observations']['display_brand_comparison'])
        self.assertEqual(records[0],records[1])
        self.assertEqual(records[0],records[2])


if __name__=='__main__': unittest.main()
