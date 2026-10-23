"""Parser-selected MIME contexts retain uncertainty without choosing alternatives."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from paw.core.attach import scan_attachments
from paw.core.mime_analysis import analyze_mime
from paw.core.mime_body_evidence import preserve_body_parts
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_message_bytes


def multipart(headers, child):
    return headers+b'\r\n\r\n--a\r\n'+child+b'\r\n--a--\r\n'


class MimeContextContracts(unittest.TestCase):
    def analyze(self, raw):
        with offline_policy():
            count = len(violations())
            message = parse_message_bytes(raw)
            result = analyze_mime(message)
            self.assertEqual(len(violations()), count)
        self.assertEqual(message._paw_source_bytes, raw)
        return message, result

    def test_duplicate_type_and_disposition_keep_first_views_but_are_partial(self):
        for headers in (
            b'Content-Type: text/plain\r\nContent-Type: text/html',
            b'Content-Type: text/plain\r\nContent-Type: text/plain',
            b'Content-Type: text/plain\r\nContent-Disposition: inline\r\nContent-Disposition: attachment',
            b'Content-Type: nonsense\r\nContent-Type: text/html'):
            with self.subTest(headers=headers):
                _, result = self.analyze(headers+b'\r\n\r\nhttps://body.invalid/\r\n')
                self.assertEqual(result['metadata']['status'], 'partial')
                context = result['metadata']['parts'][0]['mime_context']
                self.assertEqual(context['status'], 'partial')
                self.assertFalse(context['verified'])
                self.assertEqual(len(result['body_parts']), 1)
                self.assertEqual(result['urls'], ['https://body.invalid/'])
                self.assertEqual(result['metadata']['context_partial_part_count'], 1)

    def test_header_counts_and_local_positions_do_not_copy_source_values(self):
        raw = (b'X-Prefix: a\r\nContent-Type: text/plain\r\nX-Middle: b\r\n'
               b'Content-Type: text/html\r\nContent-Disposition: inline\r\n'
               b'Content-Transfer-Encoding: 7bit\r\n\r\nbody\r\n')
        _, result = self.analyze(raw)
        context = result['metadata']['parts'][0]['mime_context']
        for field, count, index in [('content-type', 2, 1), ('content-disposition', 1, 4),
                                    ('content-transfer-encoding', 1, 5)]:
            observed = context['headers'][field]
            self.assertEqual(observed['field_count'], count)
            self.assertEqual(observed['selected_header_index'], index)
            self.assertEqual(observed['selection'], 'first_occurrence')
        self.assertEqual(context['partial_ancestor_part_ids'], [])
        self.assertNotIn('text/html', json.dumps(context))

    def test_partial_ancestor_context_reaches_descendants_but_not_siblings(self):
        child = multipart(b'Content-Type: multipart/mixed; boundary=a\r\nContent-Type: text/plain',
                          b'Content-Type: text/plain\r\n\r\ninside\r\n')
        raw = (b'Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n'+child
               +b'\r\n--outer\r\nContent-Type: text/plain\r\n\r\nsibling\r\n--outer--\r\n')
        _, result = self.analyze(raw)
        parts = {p['part_id']: p for p in result['metadata']['parts']}
        self.assertEqual(parts['0.0']['mime_context']['status'], 'partial')
        self.assertEqual(parts['0.0.0']['mime_context']['partial_ancestor_part_ids'], ['0.0'])
        self.assertEqual(parts['0.1']['mime_context']['status'], 'completed')
        self.assertEqual(result['metadata']['context_partial_part_count'], 2)
        self.assertEqual(result['metadata']['context_inherited_part_count'], 1)

    def test_selected_parameter_defects_and_duplicate_transfer_are_explicit(self):
        for headers in (
            b'Content-Type: text/plain; charset=us-ascii; charset=utf-8',
            b'Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: 8bit'):
            with self.subTest(headers=headers):
                _, result = self.analyze(headers+b'\r\n\r\nbody\r\n')
                context = result['metadata']['parts'][0]['mime_context']
                self.assertEqual(context['status'], 'partial')
                self.assertEqual(result['body_parts'][0]['payload'], b'body\r\n')

    def test_body_and_attachment_consumers_retain_context_and_byte_identity(self):
        for disposition in (b'inline', b'attachment'):
            raw = (b'Content-Type: text/plain\r\nContent-Type: text/html\r\n'
                   b'Content-Disposition: '+disposition+b'\r\n\r\nbody\r\n')
            with self.subTest(disposition=disposition), tempfile.TemporaryDirectory() as temporary:
                message, result = self.analyze(raw)
                root = Path(temporary)
                if disposition == b'inline':
                    inventory = preserve_body_parts(result, raw, root/'mime_body')
                    item, = inventory['parts']
                    self.assertEqual(inventory['status'], 'partial')
                    path = root/item['payload_path']
                else:
                    item, = scan_attachments(message, result, root/'attachments')
                    path = root/item['evidence_path']
                self.assertEqual(item['status'], 'partial')
                self.assertEqual(item['mime_context'], result['metadata']['parts'][0]['mime_context'])
                self.assertEqual(path.read_bytes(), b'body\r\n')
                self.assertEqual(item['sha256'], hashlib.sha256(b'body\r\n').hexdigest())

    def test_defaults_and_embedded_headers_do_not_create_outer_ambiguity(self):
        for raw in (b'\r\nbody\r\n', b'Content-Type: text/plain\r\n\r\nbody\r\n',
                    b'Content-Type: message/rfc822\r\n\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\n\r\nbody\r\n'):
            with self.subTest(raw=raw):
                _, result = self.analyze(raw)
                context = result['metadata']['parts'][0]['mime_context']
                self.assertEqual(context['status'], 'completed')
                self.assertEqual(result['metadata']['context_partial_part_count'], 0)
                self.assertEqual(context['headers']['content-disposition']['selection'], 'parser_default')
                self.assertIsNone(context['headers']['content-disposition']['selected_header_index'])

    def test_many_declarations_keep_counts_and_constant_sized_context(self):
        raw = b'Content-Type: text/plain\r\n'*1500+b'\r\nbody\r\n'
        _, result = self.analyze(raw)
        context = result['metadata']['parts'][0]['mime_context']
        self.assertEqual(context['headers']['content-type']['field_count'], 1500)
        self.assertLess(len(json.dumps(context)), 2000)
        self.assertEqual(result['body_parts'][0]['payload'], b'body\r\n')

    def test_parser_structure_uncertainty_reaches_body_and_attachment_children(self):
        for transfer in (b'', b'Content-Transfer-Encoding: base64\r\n'):
            for disposition in (b'', b'Content-Disposition: attachment\r\n'):
                raw = (b'Content-Type: multipart/mixed; boundary=a\r\n'+transfer
                       +b'\r\n--a\r\nContent-Type: text/plain\r\n'+disposition
                       +b'\r\nbody\r\n')  # Missing closing boundary is parser-observed.
                with self.subTest(transfer=transfer, disposition=disposition):
                    message, result = self.analyze(raw)
                    root, child = result['metadata']['parts']
                    self.assertEqual(root['mime_context']['status'], 'partial')
                    self.assertEqual(root['mime_context']['parser_structure_defect_count'], len(message.defects))
                    self.assertEqual(child['mime_context']['status'], 'partial')
                    self.assertEqual(child['mime_context']['partial_ancestor_part_ids'], ['0'])
                    payloads = result['attachments'] if disposition else result['body_parts']
                    # The stdlib drops the final separator CRLF in this
                    # malformed multipart view; exact wire remains in raw.
                    self.assertEqual(payloads[0]['payload'], b'body')


if __name__ == '__main__':
    unittest.main()
