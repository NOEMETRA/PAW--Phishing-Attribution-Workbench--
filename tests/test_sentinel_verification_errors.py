"""Actual seal outcomes distinguish verification exceptions from mismatches."""
import builtins
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paw.core.evidence import seal_case
from paw.core.network_policy import offline_policy, violations
from paw.sentinel.file_monitor import FileMonitor
from test_sentinel_hash_failures import failing_open


class SentinelVerificationErrors(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
        self.cases=self.root/'cases'; self.cases.mkdir()
        self.policy=offline_policy(); self.policy.__enter__()
        self.before_violations=len(violations())

    def tearDown(self):
        blocked=violations()[self.before_violations:]
        self.policy.__exit__(None,None,None)
        self.temporary.cleanup()
        self.assertEqual(blocked,[])

    def source(self,name='case-sealed'):
        case=self.cases/name; case.mkdir()
        (case/'input.eml').write_bytes(b'Original saved bytes\n')
        seal_case(case)
        return case

    def test_valid_mismatch_and_missing_seal_outcomes_remain_distinct(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        self.assertIs(monitor.verify_merkle_integrity(case.name)[0],True)
        (case/'input.eml').write_bytes(b'Actual changed bytes\n')
        self.assertIs(monitor.verify_merkle_integrity(case.name)[0],False)
        (self.cases/'case-unsealed').mkdir()
        report=monitor.generate_integrity_report()
        self.assertEqual(report['integrity_summary'],{'ok':0,'compromised':1,'unknown':1})

    def test_verification_open_and_midread_failures_are_unavailable_not_mismatches(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        targets=((case/'evidence/merkle_index.json','denied'),
                 (case/'evidence/merkle_index.json','missing'),(case/'input.eml','stream'))
        for target,kind in targets:
            with self.subTest(target=target,kind=kind):
                with patch('builtins.open',failing_open(builtins.open,target,kind)):
                    outcome,message=monitor.verify_merkle_integrity(case.name)
                    self.assertIsNone(outcome)
                    self.assertIn('Error verifying Merkle integrity:',message)
                    self.assertIn('Explicit',message)
                self.assertIs(monitor.verify_merkle_integrity(case.name)[0],True)

    def test_unreadable_verification_does_not_inflate_compromised_report_count(self):
        case=self.source(); self.source('case-neighbor')
        monitor=FileMonitor(self.cases)
        target=case/'evidence/merkle_index.json'
        with patch('builtins.open',failing_open(builtins.open,target,'denied')):
            report=monitor.generate_integrity_report()
        self.assertEqual(report['integrity_summary'],{'ok':1,'compromised':0,'unknown':1})
        selected=next(c for c in report['cases'] if c['case_id']==case.name)
        self.assertEqual(selected['integrity_status'],'unknown')
        self.assertIn('Explicit source read-denial',selected['integrity_message'])
        self.assertGreater(selected['file_count'],0)

    def test_malformed_index_is_unknown_and_literal_file_modification_is_retained(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        monitor.check_file_changes(case.name)
        target=case/'evidence/merkle_index.json'
        before=target.read_bytes()
        for invalid in (b'{invalid JSON',b'\x80',b'17'):
            with self.subTest(source=invalid):
                target.write_bytes(invalid)
                outcome,message=monitor.verify_merkle_integrity(case.name)
                self.assertIsNone(outcome)
                self.assertIn('Error verifying Merkle integrity:',message)
                changes=monitor.check_file_changes(case.name)
                self.assertEqual(changes['integrity_status'],'unknown')
                self.assertIn(str(target),[r['path'] for r in changes['modified_files']])
                self.assertEqual(target.read_bytes(),invalid)
        target.write_bytes(before)
        self.assertIs(monitor.verify_merkle_integrity(case.name)[0],True)

    def test_file_hash_read_errors_still_abort_scans_without_advancing_baseline(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        with redirect_stdout(io.StringIO()): monitor.monitor_all_cases()
        baseline=dict(monitor._baseline_hashes)
        target=case/'evidence/merkle_index.json'
        with patch('builtins.open',failing_open(builtins.open,target,'denied')):
            with self.assertRaises(PermissionError): monitor.monitor_all_cases()
        self.assertEqual(monitor._baseline_hashes,baseline)

    def test_owner_admission_failure_is_not_swallowed_as_unknown_verification(self):
        case=self.source()
        (case/'manifest.json').write_text(json.dumps({'analysis_job':'analysis_owned'}),encoding='utf-8')
        jobs=self.root/'jobs'; (jobs/'analysis_owned').mkdir(parents=True)
        (jobs/'analysis_owned.json').write_text('{"status":"running"}',encoding='utf-8')
        (jobs/'analysis_owned/supervisor.json').write_text('{"tree_stopped":false}',encoding='utf-8')
        monitor=FileMonitor(self.cases)
        for read in (lambda:monitor.verify_merkle_integrity(case.name),monitor.generate_integrity_report):
            with self.assertRaisesRegex(RuntimeError,'Worker shutdown not confirmed'): read()


if __name__=='__main__':
    unittest.main()
