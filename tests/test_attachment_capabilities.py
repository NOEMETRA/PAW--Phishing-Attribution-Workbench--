"""Preserved attachment bytes and honest content/report scope, not accuracy labels."""
import copy
from email import policy
from email.message import EmailMessage
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from markdown_it import MarkdownIt
from paw.core.attach import scan_attachments, attachment_coverage, attachment_report_view
from paw.core.mime_analysis import analyze_mime
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_message_bytes
from paw.core.reporting import markdown_json


UNEVALUATED = ['document_text', 'url_extraction', 'resource_resolution',
               'embedded_message_body', 'archive_member_content', 'decryption']


def message():
    msg = EmailMessage(policy=policy.SMTP)
    msg.set_content('Outer body')
    return msg


def zip_bytes(count):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for i in range(count): archive.writestr(f'{i}.html', b'https://member-only.invalid/a')
    return stream.getvalue()


def scan(msg, evidence_dir=None):
    raw = msg.as_bytes()
    mime = analyze_mime(parse_message_bytes(raw))
    return scan_attachments(None, mime_result=mime, evidence_dir=evidence_dir), mime


class AttachmentCapabilities(unittest.TestCase):
    def test_opaque_declared_types_preserve_bytes_and_do_not_imply_content_support(self):
        msg = message()
        rows = [('text', 'html', b'<a href="https://inner.invalid/a">x</a>'),
                ('text', 'css', b'url(https://inner.invalid/b)'),
                ('application', 'pdf', b'%PDF inert bytes'),
                ('application', 'msword', b'VBA Project is only supplied text'),
                ('application', 'vnd.rar', b'Rar! inert bytes'),
                ('application', 'octet-stream', b'')]
        for index, (main, sub, data) in enumerate(rows):
            msg.add_attachment(data, maintype=main, subtype=sub, filename=f'{index}.bin')
        before = len(violations())
        with offline_policy(), tempfile.TemporaryDirectory() as temp:
            items, mime = scan(msg, Path(temp)/'attachments')
            self.assertEqual(mime['urls'], [])
            self.assertEqual(len(items), len(rows))
            for item, (_, _, payload) in zip(items, rows):
                self.assertEqual((Path(temp)/item['evidence_path']).read_bytes(), payload)
                self.assertEqual(item['sha256'], hashlib.sha256(payload).hexdigest())
                self.assertEqual(item['content_analysis']['status'], 'not_evaluated')
                self.assertEqual(item['content_analysis']['not_evaluated'], UNEVALUATED)
                self.assertIsNone(item['detected_mime'])
                self.assertIsNone(item['risk_score'])
        self.assertEqual(len(violations()), before)

    def test_inline_filename_and_unhandled_css_remain_outside_outer_body(self):
        msg = message()
        msg.add_attachment(b'<img src="https://inline.invalid/a">', maintype='text',
                           subtype='html', disposition='inline', filename='inline.html')
        msg.add_attachment(b'url(https://inline.invalid/b)', maintype='text', subtype='css')
        items, mime = scan(msg)
        self.assertEqual(len(items), 2)
        self.assertEqual(mime['html_parts'], [])
        self.assertEqual(mime['urls'], [])
        self.assertTrue(all(i['content_analysis']['status'] == 'not_evaluated' for i in items))

    def test_embedded_wire_preservation_is_not_inner_document_analysis(self):
        inner = message()
        inner.set_content('<a href="https://embedded.invalid/a">inner</a>', subtype='html')
        outer = message(); outer.add_attachment(inner, filename='inner.eml')
        items, mime = scan(outer)
        self.assertEqual(mime['urls'], [])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['original_wire']['status'], 'captured')
        self.assertIn('embedded_message_body', items[0]['content_analysis']['not_evaluated'])
        self.assertEqual(items[0]['byte_source'], 'derived_embedded_message_serialization')

    def test_current_metadata_completion_keeps_content_type_macro_and_malware_unassessed(self):
        msg = message()
        msg.add_attachment(b'Inert bytes', maintype='image', subtype='png', filename='claimed.png')
        items, _ = scan(msg)
        coverage = attachment_coverage(items)
        self.assertEqual(coverage['status'], 'completed')
        self.assertEqual(coverage['count'], 1)
        self.assertEqual(coverage['content_analysis']['status'], 'not_evaluated')
        self.assertEqual(coverage['content_analysis']['not_evaluated'], UNEVALUATED)
        for key in ('mime_detection', 'macro_analysis', 'malware_analysis'):
            self.assertEqual(coverage[key], 'not_evaluated')
        empty, _ = scan(message())
        empty_coverage = attachment_coverage(empty)
        self.assertEqual((empty_coverage['status'], empty_coverage['count']), ('completed', 0))
        self.assertEqual(empty_coverage['content_analysis']['status'], 'not_evaluated')

    def test_partial_zip_metadata_and_unknown_reader_counts_survive_the_report_view(self):
        msg = message()
        for data in (b'PK\x03\x04broken', zip_bytes(1001), zip_bytes(1)):
            msg.add_attachment(data, maintype='application', subtype='zip', filename='archive.zip')
        with offline_policy(), patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('No member read')):
            items, _ = scan(msg)
        coverage = attachment_coverage(items)
        before = copy.deepcopy((items, coverage))
        view = attachment_report_view(items, coverage)
        self.assertEqual((items, coverage), before)
        self.assertEqual(coverage['status'], 'partial')
        self.assertEqual(coverage['count'], 3)
        archives = [i['archive'] for i in view['attachments']]
        self.assertEqual([a['status'] for a in archives], ['error', 'limited', 'metadata_only'])
        self.assertNotIn('entry_count', archives[0])
        self.assertNotIn('omitted_entry_count', archives[0])
        self.assertEqual(archives[1]['entry_count'], 1001)
        self.assertEqual(archives[1]['inventoried_entry_count'], 1000)
        self.assertEqual(archives[1]['omitted_entry_count'], 1)
        self.assertTrue(all('entries' not in a for a in archives))
        # Member count/name budgets do not cause a large duplicate report inventory.
        self.assertLess(len(json.dumps(view)), 8000)

    def test_report_view_keeps_failed_stage_and_does_not_invent_historical_fields(self):
        failed = {'status':'failed', 'reason':'PermissionError: source unavailable'}
        view = attachment_report_view([], failed)
        self.assertEqual(view, {'coverage':failed, 'attachments':[]})
        self.assertNotIn('count', view['coverage'])
        legacy = {'part_id':'0.1', 'sha256':'a'*64, 'archive':{'status':'not_evaluated', 'reason':'Legacy'}}
        row = attachment_report_view([legacy], {'status':'not_recorded'})['attachments'][0]
        self.assertNotIn('content_analysis', row)
        self.assertNotIn('entry_count', row['archive'])

    def test_report_data_remains_literal_parseable_json(self):
        msg = message()
        msg.add_attachment(b'Inert', maintype='application', subtype='octet-stream', filename='``|name')
        items, _ = scan(msg)
        coverage = attachment_coverage(items)
        coverage['reason'] = '\n```\n![image](https://inert.invalid/) <img src="x">\u202e'
        value = attachment_report_view(items, coverage)
        tokens = MarkdownIt('commonmark').parse(markdown_json(value))
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0].type, 'fence')
        self.assertEqual(json.loads(tokens[0].content), value)


if __name__ == '__main__':
    unittest.main()
