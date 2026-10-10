"""Top-level parser observations, not authenticity or accuracy labels."""
import base64
from dataclasses import replace
from email.message import EmailMessage
import hashlib
import json
import unittest
from email import policy

from paw.core.header_inventory import HeaderInventoryLimits, inventory_headers
from paw.core.parser_mail import parse_message_bytes


class HeaderInventoryTests(unittest.TestCase):
    def inventory(self, raw, **limits):
        return inventory_headers(parse_message_bytes(raw), raw,
            replace(HeaderInventoryLimits(), **limits))

    def test_order_duplicates_folds_and_source_binding(self):
        raw = (b'From: a@example.invalid\r\nX-Trace: first\r\nx-trace: second\r\n'
               b'X-Fold: one\r\n\ttwo\r\nSubject: =?utf-8?b?Y2Fmw6k=?=\r\n\r\nbody')
        result = self.inventory(raw)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['source']['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['source']['path'], 'input.eml')
        pairs = list(parse_message_bytes(raw).raw_items())
        self.assertEqual(len(result['fields']), len(pairs))
        for index, (field, (name, value)) in enumerate(zip(result['fields'], pairs)):
            self.assertEqual(field['header_index'], index)
            self.assertEqual(field['name'], name)
            self.assertEqual(base64.b64decode(field['raw_value_base64']), value.encode('ascii', 'surrogateescape'))
        self.assertEqual(result['fields'][2]['occurrence_index'], 1)
        self.assertEqual(result['fields'][2]['normalized_name'], 'x-trace')
        self.assertEqual(result['fields'][3]['parsed_value'], 'one\ttwo')
        self.assertEqual(result['fields'][4]['parsed_value'], 'café')
        self.assertEqual(result['duplicate_occurrence_count'], 1)
        self.assertEqual(result['distinct_name_count'], 4)

    def test_high_bytes_survive_json_as_octets(self):
        result = self.inventory(b'X-Trace: raw \xff\xfe\r\n\r\nbody')
        serialized = json.dumps(result, ensure_ascii=False).encode('utf-8')
        field = json.loads(serialized)['fields'][0]
        self.assertEqual(base64.b64decode(field['raw_value_base64']), b'raw \xff\xfe')
        self.assertEqual(field['raw_status'], 'captured')
        self.assertEqual(field['parsed_status'], 'partial')
        self.assertIn('non_ascii_parser_source_octets', field['issues'])

    def test_header_looking_body_and_nested_message_are_excluded(self):
        raw = (b'Content-Type: multipart/mixed; boundary=b\r\nX-Outer: outer\r\n\r\n'
               b'--b\r\nContent-Type: message/rfc822\r\n\r\nX-Inner: inner\r\n\r\n'
               b'X-Body: body\r\n--b--\r\n')
        result = self.inventory(raw)
        self.assertEqual([f['name'] for f in result['fields']], ['Content-Type', 'X-Outer'])
        plain = self.inventory(b'X-Outer: outer\r\n\r\nX-Body: body')
        self.assertEqual(plain['total_field_count'], 1)

    def test_malformed_termination_reports_parser_defects(self):
        result = self.inventory(b'X-Outer: outer\r\nnot a header\r\nX-Late: body\r\n')
        self.assertEqual(result['total_field_count'], 1)
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(result['message_defects'])

    def test_field_count_limit_is_explicit(self):
        result = self.inventory(b'X-A: 1\r\nX-A: 2\r\nX-B: 3\r\n\r\n', max_fields=2)
        self.assertEqual(result['total_field_count'], 3)
        self.assertEqual(result['omitted_field_count'], 1)
        self.assertEqual(len(result['fields']), 2)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('field_count_limit', result['issues'])

    def test_value_limit_keeps_position_and_later_short_values(self):
        result = self.inventory(b'X-A: abcdef\r\nX-A: ok\r\n\r\n', max_value_bytes=3)
        first, second = result['fields']
        self.assertEqual(first['raw_status'], 'limited')
        self.assertIsNone(first['raw_value_base64'])
        self.assertIsNone(first['parsed_value'])
        self.assertEqual(second['occurrence_index'], 1)
        self.assertEqual(base64.b64decode(second['raw_value_base64']), b'ok')
        self.assertEqual(result['limited_field_count'], 1)
        self.assertEqual(result['status'], 'partial')

    def test_total_budget_includes_names_and_does_not_emit_truncated_values(self):
        result = self.inventory(b'X-A: one\r\nX-B: two\r\n\r\n', max_raw_bytes=6)
        self.assertEqual(result['captured_raw_bytes'], 6)
        self.assertEqual(result['fields'][1]['raw_status'], 'limited')
        self.assertIsNone(result['fields'][1]['raw_value_base64'])
        self.assertEqual(result['status'], 'partial')

    def test_oversized_name_is_bounded_and_explicit(self):
        result = self.inventory(b'X-Long-Name: one\r\nX-A: two\r\n\r\n', max_name_bytes=4)
        self.assertIsNone(result['fields'][0]['name'])
        self.assertEqual(result['fields'][0]['raw_status'], 'limited')
        self.assertEqual(result['fields'][1]['name'], 'X-A')
        self.assertEqual(result['status'], 'partial')

    def test_semantic_failure_does_not_erase_raw_observation(self):
        raw = b'Date: not a date\r\n\r\n'
        result = self.inventory(raw)
        self.assertEqual(base64.b64decode(result['fields'][0]['raw_value_base64']), b'not a date')
        self.assertEqual(result['fields'][0]['parsed_status'], 'partial')
        self.assertEqual(result['status'], 'partial')

    def test_each_duplicate_has_its_own_derived_view_without_mutating_message(self):
        raw = b'To: first@example.invalid\r\ntO: second@example.invalid\r\n\r\n'
        message = parse_message_bytes(raw)
        before = list(message.raw_items())
        result = inventory_headers(message, raw)
        self.assertEqual([f['parsed_value'] for f in result['fields']],
            ['first@example.invalid','second@example.invalid'])
        self.assertEqual(list(message.raw_items()), before)

    def test_derived_parser_exception_keeps_raw_field_and_continues(self):
        def reject(name, value):
            raise ValueError('Constructed unsupported header factory')
        raw = b'X-A: one\r\nX-B: two\r\n\r\n'
        message = parse_message_bytes(raw)
        message.policy = policy.default.clone(header_factory=reject)
        result = inventory_headers(message, raw)
        self.assertEqual(result['total_field_count'], 2)
        for field in result['fields']:
            self.assertEqual(field['raw_status'], 'captured')
            self.assertEqual(field['parsed_status'], 'unavailable')
            self.assertIn('field_parse_error:ValueError', field['issues'])
        self.assertEqual(result['status'], 'partial')

    def test_programmatic_unicode_is_not_claimed_as_source_octets(self):
        message = EmailMessage()
        message['X-Example'] = 'café'
        result = inventory_headers(message, b'original')
        self.assertEqual(result['fields'][0]['raw_status'], 'unavailable')
        self.assertIsNone(result['fields'][0]['raw_value_base64'])
        self.assertEqual(result['status'], 'partial')

    def test_positive_limits_required(self):
        for field in ('max_fields', 'max_name_bytes', 'max_value_bytes', 'max_raw_bytes'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.inventory(b'X-A: one\r\n\r\n', **{field:0})


if __name__ == '__main__':
    unittest.main()
