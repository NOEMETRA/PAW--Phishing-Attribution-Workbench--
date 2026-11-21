"""Metrics and custody contracts using synthetic saved decisions."""
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from paw.core import text_triage
from paw.core.evidence import seal_case


evaluator = runpy.run_path(str(Path(__file__).resolve().parents[1]/'tools/evaluate_mail_corpus.py'))


class CorpusEvaluation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cases = self.root/'cases'
        self.labels = []
        for i, (label, decision) in enumerate([
            ('legitimate', 'Suspicious or compromised account'),
            ('phishing', 'Inconclusive'), ('unresolved', 'Likely malicious infrastructure')]):
            case = self.cases/f'case-{i}'
            (case/'report').mkdir(parents=True)
            original = f'Subject: fixture {i}\r\n\r\n'.encode()
            (case/'input.eml').write_bytes(original)
            (case/'execution.json').write_text('{"status":"completed"}')
            (case/'report/score.json').write_text(json.dumps({'profile':'strict','decision':decision}))
            seal_case(case)
            self.labels.append({'sha256':hashlib.sha256(original).hexdigest(), 'split':'holdout',
                                'group':str(i), 'label':label, 'label_basis':'constructed fixture'})

    def evaluate(self, *, static_triage=False, text_assessor=None):
        file = self.root/'labels.json'
        file.write_text(json.dumps(self.labels))
        return evaluator['evaluate'](evaluator['read_labels'](file), self.cases, 'strict', 'holdout',
                                     static_triage=static_triage, text_assessor=text_assessor)

    def text_assessor(self):
        for index, subject in enumerate(('fixture 0', '', 'fixture 2')):
            case = self.cases/f'case-{index}'
            (case/'manifest.json').write_text(json.dumps({'case_id': str(index)}))
            (case/'headers.json').write_text(json.dumps({'subject': subject}))
            (case/'mime_body_evidence.json').write_text('{"status":"completed","parts":[]}')
            seal_case(case)
        return text_triage.TextCaseAssessor(self.root)

    def test_denominators_exclude_unresolved_and_abstention_stays_visible(self):
        result = self.evaluate()
        for key in ('false_referrals', 'missed_referrals'):
            self.assertEqual(result[key], {'count':1,'denominator':1,'rate':1.0})
        self.assertEqual(result['decisions_by_independent_label']['phishing']['Inconclusive'], 1)
        self.labels[0]['label'] = 'unresolved'
        self.assertIsNone(self.evaluate()['false_referrals']['rate'])

    def test_static_triage_keeps_its_own_outcomes(self):
        with self.assertRaisesRegex(ValueError, 'requires a saved mail_triage'):
            self.evaluate(static_triage=True)
        for index, status in enumerate(('no_supported_signal','review','not_evaluated')):
            case = self.cases/f'case-{index}'
            (case/'mail_triage.json').write_text(json.dumps({'schema_version':1,'referral_status':status}))
            seal_case(case)
        result = self.evaluate(static_triage=True)
        self.assertEqual(result['referral_rule'], 'static_mail_triage')
        self.assertEqual(result['false_referrals']['count'], 0)
        self.assertEqual(result['missed_referrals']['count'], 0)
        self.assertEqual(result['decisions_by_independent_label']['unresolved']['not_evaluated'], 1)
        self.assertEqual(self.evaluate()['missed_referrals']['count'], 1)

    def test_group_leakage_and_unsealed_scores_refused(self):
        self.labels[0].update(group='1', split='development')
        with self.assertRaisesRegex(ValueError, 'shared across'):
            self.evaluate()
        self.labels[0].update(group='0', split='holdout')
        case = self.cases/'case-2'
        (case/'report/score.json').write_text('{"profile":"strict","decision":"Inconclusive"}')
        with self.assertRaisesRegex(ValueError, 'verification failed'):
            self.evaluate()
        (case/'evidence/inventory_scope.json').unlink()
        with self.assertRaisesRegex(ValueError, 'Complete inventory'):
            self.evaluate()

    def test_text_referral_thresholds_reuse_model_and_count_abstentions(self):
        assessor = self.text_assessor()
        with patch.object(text_triage, '_load_model') as load:
            load.return_value.return_value = {'legitimate': 0.4, 'spam': 0.1, 'fraud': 0.5}, 3, False, 'fixture'
            result = self.evaluate(text_assessor=assessor)
        load.assert_called_once_with(self.root.resolve())
        self.assertEqual([call.args for call in load.return_value.call_args_list],
                         [('fixture 0',), ('fixture 2',)])
        self.assertEqual(result['referral_rule'], 'horizon_fraud_score')
        self.assertEqual(result['model']['sha256'], text_triage.MODEL_SHA256)
        primary, secondary = (result['thresholds'][threshold] for threshold in ('0.5','0.9'))
        self.assertEqual(primary['false_referrals'], {'count':1,'denominator':1,'rate':1.0})
        self.assertEqual(secondary['false_referrals']['count'], 0)
        self.assertEqual(primary['missed_referrals']['count'], 1)
        self.assertEqual(primary['decisions_by_independent_label']['phishing']['not_evaluated'], 1)
        self.assertEqual(secondary['decisions_by_independent_label']['unresolved']['below_threshold'], 1)

    def test_text_refuses_result_for_another_original(self):
        assessor = self.text_assessor()
        case = self.cases/'case-0'
        with patch.object(text_triage, '_load_model') as load:
            load.return_value.return_value = {'legitimate': 0.4, 'spam': 0.1, 'fraud': 0.5}, 3, False, 'fixture'
            assessment = assessor.assess(case)
        assessment['evidence']['original_blake3'] = '0'*64
        with patch.object(assessor, 'assess', return_value=assessment):
            with self.assertRaisesRegex(ValueError, 'labelled case seal and original'):
                self.evaluate(text_assessor=assessor)
