"""Unverified mailbox-domain comparisons must preserve parsing uncertainty."""
import json
import unittest
from paw.core.parser_mail import parse_eml_bytes
from paw.core.scoring import score_case, _extract_domain
from paw.core.network_policy import offline_policy, violations
from paw.core.authentication import infer_alignment


def headers(reply, extra=b'', sender=b'a@example.invalid'):
    return parse_eml_bytes(b'From: '+sender+b'\r\nReply-To: '+reply+b'\r\n'+extra+b'\r\nhello')


def contribution(data, domain='example.invalid'):
    return score_case({}, {}, {'domain':domain}, headers=data)['score_components']['sender_domain_heuristics']


class ReplyDomainContracts(unittest.TestCase):
    def test_comments_and_quoted_local_parts_are_not_domain_text(self):
        for value in ('a@example.invalid (support)', '"a@b"@example.invalid',
                      '"other@evil.invalid" <a@example.invalid>'):
            with self.subTest(value=value):
                self.assertEqual(_extract_domain(value),'example.invalid')
                self.assertEqual(contribution({'reply_to':value}),0)

    def test_lists_and_groups_do_not_pick_first_mailbox(self):
        for value in ('a@other.invalid, b@example.invalid', 'Team: a@other.invalid;',
                      'a@other.invalid, undisclosed:;', 'undisclosed:;'):
            with self.subTest(value=value):
                self.assertEqual(_extract_domain(value),'')
                self.assertEqual(contribution({'reply_to':value}),0)

    def test_missing_from_domain_is_not_a_mismatch(self):
        self.assertEqual(contribution({'reply_to':'a@other.invalid'},''),0)

    def test_domain_case_dot_and_idna_equivalence(self):
        for reply, sender in (('a@EXAMPLE.INVALID','example.invalid'),
                              ('a@example.invalid.','example.invalid'),
                              ('a@xn--bcher-kva.invalid','bücher.invalid')):
            with self.subTest(reply=reply):
                # Domain normalization affects only the Reply-To comparison;
                # other existing heuristics are measured separately.
                base = contribution({},sender)
                self.assertEqual(contribution({'reply_to':reply},sender),base)

    def test_suffix_relationship_and_unrelated_weight(self):
        for value in ('a@news.example.invalid','a@example.invalid'):
            self.assertEqual(contribution({'reply_to':value},'news.example.invalid'),0)
        self.assertEqual(contribution({'reply_to':'a@other.invalid'}),.15)
        self.assertEqual(contribution({'reply_to':'a@evil-example.invalid'}),.15)

    def test_duplicate_reply_to_does_not_select_first_occurrence(self):
        data = headers(b'a@other.invalid',b'Reply-To: b@example.invalid\r\n')
        self.assertEqual(contribution(data),0)
        self.assertEqual(data['reply_to_header_count'],2)
        self.assertEqual(data['reply_to_domain']['status'],'unsupported')

    def test_original_reply_defects_survive_json_scoring(self):
        data = headers(b'Name\xff <a@other.invalid>')
        self.assertEqual(contribution(data),0)
        self.assertEqual(contribution(json.loads(json.dumps(data))),0)
        self.assertEqual(data['reply_to_domain']['status'],'partial')
        self.assertIsNone(data['reply_to_domain']['domain'])

    def test_ambiguous_from_does_not_establish_comparison(self):
        data = headers(b'a@other.invalid',b'From: b@example.invalid\r\n')
        self.assertEqual(contribution(data),0)
        data = headers(b'a@other.invalid',sender=b'Team: a@example.invalid;')
        self.assertEqual(contribution(data),0)

    def test_missing_or_malformed_reply_is_explicit_and_unverified(self):
        for value,status in ((b'a@other.invalid','parsed'),(b'broken','partial')):
            data = headers(value)
            observation = data['reply_to_domain']
            self.assertEqual(observation['status'],status)
            self.assertEqual(observation['source'],'message_headers')
            self.assertEqual(observation['verification'],'not_evaluated')
        absent = parse_eml_bytes(b'From: a@example.invalid\r\n\r\nhello')
        self.assertEqual(absent['reply_to_header_count'],0)
        self.assertEqual(absent['reply_to_domain']['status'],'unavailable')

    def test_recovered_from_fragment_is_not_a_comparison_operand(self):
        data = headers(b'a@other.invalid',sender=b'a@exa mple.invalid')
        self.assertEqual(data['from_identity']['status'],'partial')
        with offline_policy(True):
            auth = infer_alignment(data,data['from'],'')
        self.assertEqual(auth['from_domain'],'exa')
        for value in (data,json.loads(json.dumps(data))):
            with self.subTest(persisted=isinstance(value['from'],str) and not hasattr(value['from'],'defects')):
                result = score_case({},auth,{'domain':auth['from_domain']},headers=value)
                comparison = result['sender_domain_observations']['reply_to_comparison']
                self.assertEqual(comparison['contribution'],0)
                self.assertEqual(comparison['status'],'not_evaluated')
                self.assertIsNone(comparison['result'])

    def test_legacy_or_persisted_from_uncertainty_cannot_bypass_gate(self):
        cases = [({'from':'a@exa mple.invalid','reply_to':'a@other.invalid'},'exa'),
                 ({'from':'a@example.invalid','reply_to':'a@other.invalid',
                   'from_identity':{'status':'partial'}},'example.invalid'),
                 ({'from':'a@example.invalid','reply_to':'a@other.invalid',
                   'header_field_defects':[{'field':'From','type':'InvalidHeaderDefect'}]},'example.invalid'),
                 ({'from':'a@other.invalid','reply_to':'b@third.invalid'},'example.invalid')]
        for value,domain in cases:
            with self.subTest(headers=value):
                comparison = score_case({}, {}, {'domain':domain},headers=value)['sender_domain_observations']['reply_to_comparison']
                self.assertEqual(comparison['contribution'],0)
                self.assertEqual(comparison['status'],'not_evaluated')

    def test_comparison_exposes_coverage_without_network_or_authentication(self):
        before = len(violations())
        with offline_policy(True):
            score = score_case({}, {}, {'domain':''},headers=headers(b'a@other.invalid'))
        self.assertEqual(len(violations()),before)
        observation = score['sender_domain_observations']['reply_to_comparison']
        self.assertEqual(observation['status'],'not_evaluated')
        self.assertIsNone(observation['result'])
        self.assertFalse(observation['verified'])
        self.assertEqual(score['score_components']['verified_authentication_failures'],0)


if __name__ == '__main__':
    unittest.main()
