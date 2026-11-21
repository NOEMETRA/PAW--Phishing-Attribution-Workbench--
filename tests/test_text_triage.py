"""Regression checks for the offline model's saved-case admission."""
from hashlib import sha256
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from paw.core import text_triage
from paw.core.evidence import seal_case
from paw.core.network_policy import EgressDenied


class CaseTextTriage(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.case = self.root/'cases/case-fixture'
        (self.case/'mime_body').mkdir(parents=True)
        self.model = self.root/'model'
        self.model.mkdir()
        self.write('manifest.json', {'case_id': 'fixture'})
        self.write('execution.json', {'status': 'completed'})
        self.write('headers.json', {'subject': 'Subject'})
        (self.case/'input.eml').write_bytes(b'From: fixture@example.invalid\r\n\r\nBody\r\n')
        self.body_text = '<p>Text-only fixture</p><script>ignored()</script>'
        self.text_path = self.case/'mime_body/part-0.txt'
        self.text_path.write_bytes(self.body_text.encode())
        self.part = {'declared_mime': 'text/html', 'part_id': '0', 'text_path': 'mime_body/part-0.txt',
                     'text_sha256': sha256(self.body_text.encode()).hexdigest(), 'status': 'partial'}
        self.write('mime_body_evidence.json', {'status': 'partial', 'parts': [self.part]})
        seal_case(self.case)

    def write(self, filename, value):
        (self.case/filename).write_text(json.dumps(value), encoding='utf-8')

    def test_scores_link_to_seal_and_runs_under_offline_policy(self):
        def infer(text, directory):
            self.assertEqual(text, 'Subject\nText-only fixture')
            self.assertEqual(directory, self.model.resolve())
            with self.assertRaises(EgressDenied):
                socket.socket().close()
            return {'legitimate': 0.2, 'spam': 0.1, 'fraud': 0.7}, 9, True, 'fixture'

        snapshot = {path: path.read_bytes() for path in self.case.rglob('*') if path.is_file()}
        with patch.object(text_triage, '_infer', side_effect=infer):
            result = text_triage.assess_case(self.case, self.model)
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['calibrated'])
        self.assertTrue(result['truncated'])
        self.assertEqual(result['evidence']['text_parts_before_token_limit'], [
            {'part_id': '0', 'path': self.part['text_path'], 'sha256': self.part['text_sha256'],
             'source_status': 'partial'},
        ])
        self.assertEqual(result['evidence']['merkle_root_blake3'],
                         (self.case/'evidence/merkle_root.bin').read_text())
        self.assertEqual(snapshot, {path: path.read_bytes() for path in self.case.rglob('*') if path.is_file()})

    def test_invalid_seal_and_changed_mime_metadata_refused_before_inference(self):
        self.text_path.write_text('Edited text', encoding='utf-8')
        with patch.object(text_triage, '_infer') as infer:
            with self.assertRaisesRegex(ValueError, 'seal failed'):
                text_triage.assess_case(self.case, self.model)
            seal_case(self.case)
            with self.assertRaisesRegex(ValueError, 'MIME text hash mismatch'):
                text_triage.assess_case(self.case, self.model)
            infer.assert_not_called()

    def test_incomplete_or_currently_owned_case_refused_before_inference(self):
        self.write('execution.json', {'status': 'interrupted'})
        seal_case(self.case)
        with patch.object(text_triage, '_infer') as infer:
            with self.assertRaisesRegex(ValueError, 'completed, sealed'):
                text_triage.assess_case(self.case, self.model)
            self.write('manifest.json', {'analysis_job': 'analysis_fixture'})
            jobs = self.root/'jobs'
            (jobs/'analysis_fixture').mkdir(parents=True)
            (jobs/'analysis_fixture.json').write_text('{"status":"running"}', encoding='utf-8')
            seal_case(self.case)
            with self.assertRaisesRegex(RuntimeError, 'shutdown not confirmed'):
                text_triage.assess_case(self.case, self.model)
            infer.assert_not_called()

    def test_empty_text_explicitly_not_evaluated(self):
        self.write('headers.json', {'subject': ''})
        self.write('mime_body_evidence.json', {'status': 'completed', 'parts': []})
        seal_case(self.case)
        with patch.object(text_triage, '_infer') as infer:
            result = text_triage.assess_case(self.case, self.model)
        infer.assert_not_called()
        self.assertEqual(result['status'], 'not_evaluated')
        self.assertIsNone(result['scores'])

    def test_html_line_and_cell_boundaries_preserve_inline_words(self):
        text = ('Your<br>account<br/>has<table><tr><td>been</td>'
                '<td>sus<strong>pend</strong>ed</td></tr></table>today')
        self.text_path.write_bytes(text.encode())
        self.part['text_sha256'] = sha256(text.encode()).hexdigest()
        self.write('mime_body_evidence.json', {'status': 'partial', 'parts': [self.part]})
        seal_case(self.case)
        scores = {'legitimate': 0.1, 'spam': 0.2, 'fraud': 0.7}
        with patch.object(text_triage, '_infer', return_value=(scores, 9, False, 'fixture')) as infer:
            text_triage.assess_case(self.case, self.model)
        infer.assert_called_once_with('Subject\nYour account has been suspended today', self.model.resolve())

    def test_model_loader_checks_exact_bytes_even_at_expected_size(self):
        (self.model/'tokenizer.json').write_bytes(b'inert')
        digest = sha256(b'other').hexdigest()
        with self.assertRaisesRegex(ValueError, 'approved Horizon Labs revision'):
            text_triage._model_bytes(self.model, 'tokenizer.json', 5, digest)


if __name__ == '__main__':
    unittest.main()
