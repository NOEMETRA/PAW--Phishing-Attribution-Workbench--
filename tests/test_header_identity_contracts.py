"""Mailbox syntax/evidence contracts; constructed headers are not accuracy labels."""
from email import policy
import json
import unittest

from paw.core.parser_mail import parse_eml_bytes
from paw.core.scoring import extract_display_name, score_case


class HeaderIdentityContracts(unittest.TestCase):
    def test_unquoted_quoted_and_encoded_multiword_names_are_equivalent(self):
        values = ('PayPal A <user@example.invalid>', '"PayPal A" <user@example.invalid>',
                  '=?utf-8?b?UGF5UGFsIEE=?= <user@example.invalid>')
        scores = []
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(extract_display_name(value),'PayPal A')
                scores.append(score_case({}, {}, {'domain':'example.invalid'},headers={'from':value})['score_components']['sender_domain_heuristics'])
        self.assertEqual(scores,[.2,.2,.2])

    def test_bare_mailbox_never_fabricates_a_display_name_from_local_part(self):
        self.assertEqual(extract_display_name('paypal@merchant.invalid'),'')
        score = score_case({}, {}, {'domain':'merchant.invalid'},headers={'from':'paypal@merchant.invalid'})
        self.assertEqual(score['score_components']['sender_domain_heuristics'],0)

    def test_ambiguous_and_malformed_fields_do_not_pick_a_name(self):
        for value in ('PayPal <a@example.invalid>, Other <b@example.invalid>',
                      'PayPal <broken>', 'PayPal <a@example.invalid', '', None):
            with self.subTest(value=value):
                self.assertEqual(extract_display_name(value),'')

    def test_comments_and_escaped_quotes_use_structured_display_name(self):
        self.assertEqual(extract_display_name('a@example.invalid (PayPal)'), '')
        self.assertEqual(extract_display_name('"PayPal \\"A\\"" <a@example.invalid>'), 'PayPal "A"')

    def test_undecodable_from_bytes_are_exposed_without_penalty(self):
        source = b'From: PayPal \xff <a@example.invalid>\r\nTo: b@example.invalid\r\nSubject: fixture\r\n\r\nhello\r\n'
        headers = parse_eml_bytes(source)
        self.assertTrue(headers['header_defects'])
        issue, = headers['header_field_defects']
        self.assertEqual(issue['field'],'From')
        self.assertEqual(issue['header_index'],0)
        self.assertEqual(issue['type'],'UndecodableBytesDefect')
        self.assertEqual(issue['source'],'message_headers')
        self.assertEqual(extract_display_name(headers['from']),'')
        score = score_case({}, {}, {'domain':'example.invalid'},headers=headers)
        self.assertEqual(score['score_components']['sender_domain_heuristics'],0)
        self.assertEqual(score['score_components']['verified_authentication_failures'],0)

    def test_duplicate_field_defects_keep_occurrence_indices(self):
        source = b'From: A <a@example.invalid>\r\nFrom: B \xff <b@example.invalid>\r\n\r\nhello\r\n'
        headers = parse_eml_bytes(source)
        self.assertEqual(headers['from_header_count'],2)
        issue, = headers['header_field_defects']
        self.assertEqual(issue['header_index'],1)
        self.assertEqual(issue['field'],'From')

    def test_reported_reply_and_date_field_defects_are_collected(self):
        source = b'From: A <a@example.invalid>\r\nReply-To: B \xff <b@example.invalid>\r\nDate: not a date\r\nSubject: \xff\r\n\r\nhello\r\n'
        headers = parse_eml_bytes(source)
        self.assertTrue({'Reply-To','Date'} <= {issue['field'] for issue in headers['header_field_defects']})

    def test_valid_header_fields_have_no_defects_and_remain_unverified(self):
        headers = parse_eml_bytes(b'From: PayPal A <a@example.invalid>\r\nReply-To: b@example.invalid\r\nSubject: fixture\r\n\r\nhello\r\n')
        self.assertEqual(headers['header_field_defects'],[])
        self.assertEqual(headers['header_defects'],[])
        self.assertEqual(extract_display_name(headers['from']),'PayPal A')
        self.assertEqual(getattr(headers['from'],'addresses')[0].domain,'example.invalid')

    def test_serialized_header_defects_keep_the_same_identity_contribution(self):
        headers = parse_eml_bytes(b'From: PayPal\xff <a@example.invalid>\r\n\r\nhello')
        persisted = json.loads(json.dumps(headers))
        domain = {'domain':'example.invalid'}
        before = score_case({}, {}, domain,headers=headers)
        after = score_case({}, {}, domain,headers=persisted)
        self.assertEqual(before,after)
        self.assertEqual(after['score_components']['sender_domain_heuristics'],0)

    def test_multiple_from_fields_do_not_select_first_display_name(self):
        headers = parse_eml_bytes(b'From: PayPal A <a@example.invalid>\r\nFrom: Other <b@example.invalid>\r\n\r\nhello')
        score = score_case({}, {}, {'domain':'example.invalid'},headers=headers)
        self.assertEqual(score['score_components']['sender_domain_heuristics'],0)

    def test_named_or_extra_groups_are_not_selected_as_a_sender_mailbox(self):
        for value in ('Group: PayPal <a@example.invalid>;',
                      'PayPal <a@example.invalid>, undisclosed:;', 'Automated System:;'):
            with self.subTest(value=value):
                headers = parse_eml_bytes(('From: '+value+'\r\n\r\nhello').encode())
                self.assertEqual(extract_display_name(value),'')
                self.assertEqual(headers['from_identity']['status'],'unsupported')
                self.assertEqual(headers['header_field_defects'],[])
                self.assertEqual(headers['header_defects'],[])
                score = score_case({}, {}, {'domain':'example.invalid'},headers=headers)
                self.assertEqual(score['score_components']['sender_domain_heuristics'],0)


if __name__ == '__main__':
    unittest.main()
