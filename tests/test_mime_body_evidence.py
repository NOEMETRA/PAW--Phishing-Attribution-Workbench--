"""MIME body-byte provenance; constructed inputs are not accuracy labels."""
from email import policy
from email.message import EmailMessage
import binascii
import hashlib
from pathlib import Path
import tempfile
import unittest

from paw.core.mime_analysis import analyze_mime
from paw.core.attach import scan_attachments
from paw.core.mime_body_evidence import preserve_body_parts
from paw.core.parser_mail import parse_message_bytes


class MimeBodyEvidenceTests(unittest.TestCase):
    @staticmethod
    def identity_fixtures():
        # RFC 2045 domains, including the absent-header 7bit default. Expected
        # status is specified from the wire bytes, not PAW's validator.
        fixtures = []
        for cte in (None, b'7bit', b'7BIT', b'8bit', b'8BIT'):
            seven_bit = cte in (None, b'7bit', b'7BIT')
            fixtures.extend((cte, payload, valid) for payload, valid in (
                (b'', True), (b'hello=3Dworld', True),
                (b'a'*998+b'\r\n'+b'b'*998, True),
                (b'\t\v\f\x01\x7f \r\n', True),
                (b'Caf\xe9\r\n', not seven_bit),
                (b'a\x00b', False), (b'a'*999, False),
                (b'a\nb', False), (b'a\rb', False),
                (b'a\r\n\nb', False), (b'a\r\r\nb', False)))
        for payload in (b'', bytes(range(256)), b'a'*999+b'\n\x00\xff\r'):
            fixtures.append((b'BiNaRy', payload, True))
        return fixtures

    def test_identity_transfer_domains_preserve_body_bytes_and_charset_view(self):
        for cte, payload, valid in self.identity_fixtures():
            declaration = b'' if cte is None else b'Content-Transfer-Encoding: '+cte+b'\r\n'
            raw = b'Content-Type: text/plain; charset=iso-8859-1\r\n'+declaration+b'\r\n'+payload
            with self.subTest(cte=cte, payload=payload[:20], size=len(payload)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), payload)
                self.assertEqual((root/field['text_path']).read_bytes(), payload.decode('iso-8859-1').encode('utf-8'))
                self.assertEqual(field['decoding']['status'], 'completed')
                status = 'completed' if valid else 'partial'
                self.assertEqual(field['status'], status)
                self.assertEqual(inventory['status'], status)
                self.assertEqual(result['metadata']['status'], status)
                self.assertEqual(field['byte_source'], 'transfer_decoded_bytes' if valid else 'identity_bytes_invalid_transfer_domain')
                if valid:
                    self.assertNotIn('transfer_decoding', field)
                else:
                    self.assertEqual(field['transfer_decoding']['status'], 'partial')
                    self.assertEqual(field['transfer_decoding']['declared_encodings'], [] if cte is None else [cte.decode()])

    def test_identity_transfer_domains_reach_attachment_inventory(self):
        for cte, payload, valid in self.identity_fixtures():
            declaration = b'' if cte is None else b'Content-Transfer-Encoding: '+cte+b'\r\n'
            raw = (b'Content-Type: application/octet-stream\r\n'
                   b'Content-Disposition: attachment; filename="a.bin"\r\n'+declaration+b'\r\n'+payload)
            with self.subTest(cte=cte, payload=payload[:20], size=len(payload)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = analyze_mime(parse_message_bytes(raw))
                field, = scan_attachments(None, result, root/'attachments')
                self.assertEqual((root/field['evidence_path']).read_bytes(), payload)
                self.assertEqual(field['status'], 'metadata_only' if valid else 'partial')
                self.assertEqual(result['metadata']['status'], 'completed' if valid else 'partial')
                if valid:
                    self.assertNotIn('transfer_decoding', field)
                else:
                    self.assertEqual(field['byte_source'], 'identity_bytes_invalid_transfer_domain')
                    self.assertEqual(field['transfer_decoding']['status'], 'partial')

    def preserve(self, raw, directory):
        result = analyze_mime(parse_message_bytes(raw))
        return result, preserve_body_parts(result, raw, directory)

    def test_charset_preserves_octets_and_separate_utf8_text(self):
        raw = b'Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCaf\xe9\r\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, inventory = self.preserve(raw, root/'mime_body')
            field, = inventory['parts']
            self.assertEqual((root/field['payload_path']).read_bytes(), b'Caf\xe9\r\n')
            self.assertEqual((root/field['text_path']).read_bytes(), 'Café\r\n'.encode('utf-8'))
            self.assertEqual(field['sha256'], result['metadata']['parts'][0]['sha256'])
            self.assertEqual(field['decoding']['used_charset'], 'iso-8859-1')
            self.assertEqual(inventory['source']['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(inventory['status'], 'completed')

    def test_unknown_charset_retains_invalid_octets_before_replacement(self):
        raw = b'Content-Type: text/html; charset=unknown-charset\r\n\r\n<b>a\xffb</b>'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, inventory = self.preserve(raw, root/'mime_body')
            field, = inventory['parts']
            self.assertEqual((root/field['payload_path']).read_bytes(), b'<b>a\xffb</b>')
            self.assertEqual((root/field['text_path']).read_text(encoding='utf-8'), '<b>a\ufffdb</b>')
            self.assertTrue(field['decoding']['replacement_used'])
            self.assertEqual(inventory['status'], 'partial')

    def test_alternatives_inline_binary_and_text_attachment_remain_separate(self):
        message = EmailMessage(policy=policy.SMTP)
        message.set_content('Outer')
        message.add_alternative('<b>HTML one</b>', subtype='html')
        message.add_alternative('<b>HTML two</b>', subtype='html')
        message.add_attachment('Attachment text', filename='../letter.txt')
        message.add_attachment(b'PNG', maintype='image', subtype='png', disposition='inline')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, inventory = self.preserve(message.as_bytes(), root/'mime_body')
            self.assertEqual(len(inventory['parts']), 3)
            self.assertEqual(len(result['attachments']), 2)
            self.assertEqual([p['part_id'] for p in inventory['parts']], ['0.0.0','0.0.1','0.0.2'])
            texts = [(root/p['text_path']).read_text(encoding='utf-8') for p in inventory['parts']]
            self.assertTrue(any('HTML one' in text for text in texts))
            self.assertTrue(any('HTML two' in text for text in texts))
            self.assertFalse(any('Attachment text' in text for text in texts))

    def test_transfer_decoding_defects_do_not_erase_decoded_payload(self):
        raw = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, inventory = self.preserve(raw, root/'mime_body')
            field, = inventory['parts']
            self.assertEqual((root/field['payload_path']).read_bytes(), b'Hello')
            self.assertIn('InvalidBase64PaddingDefect', field['defects'])
            self.assertEqual(field['byte_source'], 'transfer_decoded_bytes')
            self.assertEqual(inventory['status'], 'partial')

    def test_unsupported_transfer_encoding_is_preserved_and_partial(self):
        for cte in (b'x-foo', b''):
            raw = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: '+cte+b'\r\n\r\nhello=3Dworld'
            with self.subTest(cte=cte), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), b'hello=3Dworld')
                self.assertEqual((root/field['text_path']).read_bytes(), b'hello=3Dworld')
                self.assertEqual(field['byte_source'], 'undecoded_unsupported_transfer_encoding')
                self.assertEqual(field['transfer_decoding']['status'], 'partial')
                self.assertEqual(field['decoding']['status'], 'completed')
                self.assertEqual(field['status'], 'partial')
                self.assertEqual(result['metadata']['status'], 'partial')
                self.assertEqual(inventory['status'], 'partial')

    def test_failed_transfer_decoders_do_not_claim_decoded_bytes(self):
        for cte, payload in ((b'base64', b'A'), (b'x-uue', b'hello=3Dworld')):
            raw = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: '+cte+b'\r\n\r\n'+payload
            with self.subTest(cte=cte), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), payload)
                self.assertEqual(field['byte_source'], 'undecoded_failed_transfer_encoding')
                self.assertEqual(field['status'], 'partial')
                self.assertEqual(result['metadata']['status'], 'partial')

    def test_duplicate_transfer_headers_report_first_header_interpretation(self):
        raw = (b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n'
               b'Content-Transfer-Encoding: quoted-printable\r\n\r\nSGVsbG8=')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, inventory = self.preserve(raw, root/'mime_body')
            field, = inventory['parts']
            self.assertEqual((root/field['payload_path']).read_bytes(), b'Hello')
            self.assertEqual(field['byte_source'], 'derived_first_transfer_encoding')
            self.assertEqual(field['transfer_decoding']['declared_encodings'], ['base64','quoted-printable'])
            self.assertEqual(field['status'], 'partial')
            self.assertEqual(result['metadata']['status'], 'partial')

    def test_known_transfer_encodings_keep_successful_behavior(self):
        fixtures = [(b'7bit',b'hello=3Dworld',b'hello=3Dworld'),
            (b'8bit',b'hello',b'hello'), (b'binary',b'hello',b'hello'),
            (b'BASE64',b'SGVsbG8=',b'Hello'),
            (b'quoted-printable',b'hello=3Dworld',b'hello=world')]
        for cte in (b'uuencode',b'x-uuencode',b'uue',b'x-uue'):
            fixtures.append((cte,b'begin 644 fixture\r\n'+binascii.b2a_uu(b'Hello')+b' \r\nend\r\n',b'Hello'))
        for cte, payload, expected in fixtures:
            raw = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: '+cte+b'\r\n\r\n'+payload
            with self.subTest(cte=cte), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), expected)
                self.assertEqual(field['byte_source'], 'transfer_decoded_bytes')
                self.assertEqual(field['status'], 'completed')
                self.assertNotIn('transfer_decoding', field)

    def test_truncated_uuencode_preserves_recovered_body_bytes_as_partial(self):
        data_line = binascii.b2a_uu(b'Hello')
        payloads = [b'begin 644 fixture\n'+data_line,
            b'begin 644 fixture\r\n'+data_line+b' \r\n',
            b'begin 644 fixture\r\n',
            b'end\r\nbegin 644 fixture\r\n'+data_line,
            b'begin invalid ignored\r\nend\r\nbegin 644 fixture\r\n'+data_line]
        for cte in (b'uuencode', b'x-uuencode', b'uue', b'x-uue'):
            for index, payload in enumerate(payloads):
                raw = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: '+cte+b'\r\n\r\n'+payload
                with self.subTest(cte=cte, fixture=index), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    result, inventory = self.preserve(raw, root/'mime_body')
                    field, = inventory['parts']
                    expected = b'' if index == 2 else b'Hello'
                    self.assertEqual((root/field['payload_path']).read_bytes(), expected)
                    self.assertEqual((root/field['text_path']).read_bytes(), expected)
                    self.assertEqual(field['byte_source'], 'transfer_decoded_incomplete_framing')
                    self.assertEqual(field['transfer_decoding']['status'], 'partial')
                    self.assertEqual(field['decoding']['status'], 'completed')
                    self.assertEqual(field['defects'], [])
                    self.assertEqual(field['status'], 'partial')
                    self.assertEqual(inventory['status'], 'partial')
                    self.assertEqual(result['metadata']['status'], 'partial')

    def test_truncated_uuencode_attachment_and_complete_terminators(self):
        payload = b'begin 644 fixture\r\n'+binascii.b2a_uu(b'Hello')
        for tail in (b'', b'end', b' \r\nend\r\n', b'\tend \t\r\n'):
            raw = (b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\n'
                   b'Content-Transfer-Encoding: x-uue\r\n\r\n'+payload+tail)
            with self.subTest(tail=tail), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result = analyze_mime(parse_message_bytes(raw))
                field, = scan_attachments(None, result, root/'attachments')
                self.assertEqual((root/field['evidence_path']).read_bytes(), b'Hello')
                if tail:
                    self.assertEqual(field['byte_source'], 'transfer_decoded_bytes')
                    self.assertEqual(field['status'], 'metadata_only')
                    self.assertEqual(result['metadata']['status'], 'completed')
                    self.assertNotIn('transfer_decoding', field)
                else:
                    self.assertEqual(field['byte_source'], 'transfer_decoded_incomplete_framing')
                    self.assertEqual(field['transfer_decoding']['status'], 'partial')
                    self.assertEqual(field['status'], 'partial')
                    self.assertEqual(result['metadata']['status'], 'partial')

    def test_quoted_printable_recovery_is_explicitly_partial(self):
        fixtures = [(b'hello=',b'hello'), (b'hello=A',b'hello=A'),
            (b'hello=G1',b'hello=G1'), (b'hello=\r',b'hello'),
            (b'hello=\rX',b'hello'), (b'hello=\nworld',b'helloworld'),
            (b'hello=3dworld',b'hello=world'),
            (b'hello= \r\nworld',b'hello= \r\nworld'),
            (b'hello \r\n',b'hello \r\n'), (b'hello\t',b'hello\t'),
            (b'a'*77,b'a'*77), (b'a\x01b',b'a\x01b'), (b'a\xffb',b'a\xffb')]
        for encoded, expected in fixtures:
            raw = (b'Content-Type: text/plain; charset=iso-8859-1\r\n'
                b'Content-Transfer-Encoding: quoted-printable\r\n\r\n'+encoded)
            with self.subTest(encoded=encoded), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                result, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), expected)
                self.assertEqual((root/field['text_path']).read_bytes(), expected.decode('iso-8859-1').encode('utf-8'))
                self.assertEqual(field['byte_source'], 'transfer_decoded_partial_syntax')
                self.assertEqual(field['transfer_decoding']['status'], 'partial')
                self.assertEqual(field['decoding']['status'], 'completed')
                self.assertEqual(field['defects'], [])
                self.assertEqual(field['status'], 'partial')
                self.assertEqual(inventory['status'], 'partial')
                self.assertEqual(result['metadata']['status'], 'partial')

    def test_valid_quoted_printable_escapes_and_soft_breaks_keep_bytes(self):
        fixtures = [(b'',b''), (b'a'*76,b'a'*76),
            (b'Caf=E9=3D',b'Caf\xe9='), (b'hello=\r\nworld',b'helloworld'),
            (b'a'*75+b'=\r\nworld',b'a'*75+b'world'), (b'hello=\r\n',b'hello'),
            (b'hello\t world\r\nnext',b'hello\t world\r\nnext'),
            (b'=00=09=20=7F=FF',b'\x00\t \x7f\xff')]
        for encoded, expected in fixtures:
            raw = (b'Content-Type: text/plain; charset=iso-8859-1\r\n'
                b'Content-Transfer-Encoding: QUOTED-PRINTABLE\r\n\r\n'+encoded)
            with self.subTest(encoded=encoded), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), expected)
                self.assertEqual(field['byte_source'], 'transfer_decoded_bytes')
                self.assertEqual(field['status'], 'completed')
                self.assertNotIn('transfer_decoding', field)

    def test_partial_quoted_printable_provenance_reaches_attachments(self):
        raw = (b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\n'
               b'Content-Transfer-Encoding: quoted-printable\r\n\r\nhello=')
        result = analyze_mime(parse_message_bytes(raw))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            field, = scan_attachments(None, result, root/'attachments')
            self.assertEqual((root/field['evidence_path']).read_bytes(), b'hello')
            self.assertEqual(field['byte_source'], 'transfer_decoded_partial_syntax')
            self.assertEqual(field['transfer_decoding']['status'], 'partial')
            self.assertEqual(field['status'], 'partial')

    def test_transfer_partial_provenance_reaches_attachment_metadata(self):
        raw = (b'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a.bin"\r\n'
               b'Content-Transfer-Encoding: x-foo\r\n\r\nhello=3Dworld')
        result = analyze_mime(parse_message_bytes(raw))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            field, = scan_attachments(None, result, root/'attachments')
            self.assertEqual((root/field['evidence_path']).read_bytes(), b'hello=3Dworld')
            self.assertEqual(field['byte_source'], 'undecoded_unsupported_transfer_encoding')
            self.assertEqual(field['transfer_decoding']['status'], 'partial')
            self.assertEqual(field['status'], 'partial')

    def test_attached_email_and_calendar_do_not_become_outer_body(self):
        message = EmailMessage(policy=policy.SMTP)
        message.set_content('Outer')
        inner = EmailMessage(); inner.set_content('Inner')
        message.add_attachment(inner, filename='forward.eml')
        message.add_attachment('Calendar', subtype='calendar')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, inventory = self.preserve(message.as_bytes(), root/'mime_body')
            self.assertEqual(len(inventory['parts']), 1)
            self.assertEqual(len(result['attachments']), 2)
            self.assertEqual(inventory['parts'][0]['declared_mime'], 'text/plain')

    def test_empty_body_and_javascript_source_are_preserved_without_execution(self):
        for content_type, payload in ((b'text/plain',b''), (b'text/javascript',b'throw Error("fixture");')):
            raw = b'Content-Type: '+content_type+b'\r\n\r\n'+payload
            with self.subTest(content_type=content_type), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, inventory = self.preserve(raw, root/'mime_body')
                field, = inventory['parts']
                self.assertEqual((root/field['payload_path']).read_bytes(), payload)
                self.assertEqual((root/field['text_path']).read_bytes(), payload)

    def test_unsafe_or_duplicate_part_ids_fail_before_writing(self):
        result = analyze_mime(parse_message_bytes(b'Content-Type: text/plain\r\n\r\nx'))
        for identifier in ('../../escape','0/../../escape','not-a-part'):
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as temporary:
                result['body_parts'][0]['part_id'] = identifier
                destination = Path(temporary)/'mime_body'
                with self.assertRaises(ValueError): preserve_body_parts(result,b'original',destination)
                self.assertFalse(destination.exists())
        result['body_parts'][0]['part_id'] = '0'
        result['body_parts'].append(dict(result['body_parts'][0]))
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)/'mime_body'
            with self.assertRaises(ValueError): preserve_body_parts(result,b'original',destination)
            self.assertFalse(destination.exists())

    def test_existing_evidence_is_not_overwritten(self):
        raw = b'Content-Type: text/plain\r\n\r\nfirst'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, inventory = self.preserve(raw, root/'mime_body')
            field, = inventory['parts']
            with self.assertRaises(FileExistsError): preserve_body_parts(result,raw,root/'mime_body')
            self.assertEqual((root/field['payload_path']).read_bytes(), b'first')


if __name__ == '__main__': unittest.main()
