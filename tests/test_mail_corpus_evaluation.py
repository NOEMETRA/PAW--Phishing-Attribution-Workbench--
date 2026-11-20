"""Metrics and custody contracts using synthetic saved decisions."""
import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import unittest

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

    def evaluate(self):
        file = self.root/'labels.json'
        file.write_text(json.dumps(self.labels))
        return evaluator['evaluate'](evaluator['read_labels'](file), self.cases, 'strict', 'holdout')

    def test_denominators_exclude_unresolved_and_abstention_stays_visible(self):
        result = self.evaluate()
        for key in ('false_referrals', 'missed_referrals'):
            self.assertEqual(result[key], {'count':1,'denominator':1,'rate':1.0})
        self.assertEqual(result['decisions_by_independent_label']['phishing']['Inconclusive'], 1)
        self.labels[0]['label'] = 'unresolved'
        self.assertIsNone(self.evaluate()['false_referrals']['rate'])

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
