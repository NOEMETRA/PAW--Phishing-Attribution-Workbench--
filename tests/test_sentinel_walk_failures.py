"""Actual directory inventories with explicit scandir open/iteration failures."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.file_monitor import FileMonitor


def failing_scandir(original,target,kind):
    """Fail a selected real directory; iteration returns one real entry first."""
    selected=os.path.normcase(os.path.abspath(target))
    def scanning(path):
        if not isinstance(path,(str,os.PathLike)) or os.path.normcase(os.path.abspath(path))!=selected:
            return original(path)
        if kind=='denied': raise PermissionError('Explicit directory read-denial fixture')
        iterator=original(path)
        class InterruptedScan:
            def __enter__(self):
                iterator.__enter__()
                self.read_once=False
                return self
            def __exit__(self,*error): return iterator.__exit__(*error)
            def __iter__(self): return self
            def __next__(self):
                if self.read_once: raise OSError('Explicit directory iteration interruption fixture')
                self.read_once=True
                return next(iterator)
        return InterruptedScan()
    return scanning


class SentinelWalkFailures(unittest.TestCase):
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

    def source(self,name='case-stored'):
        case=self.cases/name; (case/'nested').mkdir(parents=True)
        (case/'root.txt').write_bytes(b'Original root bytes')
        (case/'nested/artifact.txt').write_bytes(b'Original nested bytes')
        return case

    def faults(self,case):
        for target in (case,case/'nested'):
            for kind,error in (('denied',PermissionError),('iterator',OSError)):
                yield target,kind,error

    def test_listing_errors_propagate_instead_of_empty_or_prefix_inventory(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        expected=monitor.get_case_files(case.name)
        for target,kind,error in self.faults(case):
            with self.subTest(target=target,kind=kind):
                with patch('os.scandir',failing_scandir(os.scandir,target,kind)):
                    with self.assertRaises(error): monitor.get_case_files(case.name)
                self.assertEqual(monitor.get_case_files(case.name),expected)
        self.assertEqual((case/'root.txt').read_bytes(),b'Original root bytes')
        self.assertEqual((case/'nested/artifact.txt').read_bytes(),b'Original nested bytes')

    def test_established_case_baseline_survives_and_recovery_has_no_false_changes(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        monitor.check_file_changes(case.name)
        baseline=dict(monitor._baseline_hashes)
        for target,kind,error in self.faults(case):
            with self.subTest(target=target,kind=kind):
                with patch('os.scandir',failing_scandir(os.scandir,target,kind)):
                    with self.assertRaises(error): monitor.check_file_changes(case.name)
                self.assertEqual(monitor._baseline_hashes,baseline)
                recovered=monitor.check_file_changes(case.name)
                self.assertFalse(any(recovered[k] for k in ('new_files','modified_files','deleted_files')))

    def test_failed_first_case_scan_never_commits_successfully_listed_prefix(self):
        case=self.source()
        for target,kind,error in self.faults(case):
            monitor=FileMonitor(self.cases)
            with self.subTest(target=target,kind=kind):
                with patch('os.scandir',failing_scandir(os.scandir,target,kind)):
                    with self.assertRaises(error): monitor.check_file_changes(case.name)
                self.assertEqual(monitor._baseline_hashes,{})
                self.assertEqual(len(monitor.check_file_changes(case.name)['new_files']),2)

    def test_all_case_failure_preserves_neighbor_baseline_and_defers_records(self):
        early=self.source('case-a-earlier'); late=self.source('case-z-later')
        monitor=FileMonitor(self.cases)
        with redirect_stdout(io.StringIO()): monitor.monitor_all_cases()
        baseline=dict(monitor._baseline_hashes)
        (early/'root.txt').write_bytes(b'Actual earlier modification')
        for target,kind,error in self.faults(late):
            printed=io.StringIO()
            with self.subTest(target=target,kind=kind):
                with redirect_stdout(printed),patch('os.scandir',failing_scandir(os.scandir,target,kind)):
                    with self.assertRaises(error): monitor.monitor_all_cases()
                self.assertEqual(monitor._baseline_hashes,baseline)
                self.assertNotIn('[file_monitor] Case ',printed.getvalue())
        with redirect_stdout(io.StringIO()): recovered=monitor.monitor_all_cases()
        by_case={r['case_id']:r for r in recovered}
        self.assertEqual(len(by_case[early.name]['modified_files']),1)
        self.assertEqual(by_case[late.name]['new_files'],[])
        self.assertEqual(by_case[late.name]['deleted_files'],[])

    def test_integrity_report_cannot_publish_counts_from_failed_listing(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        for target,kind,error in self.faults(case):
            with self.subTest(target=target,kind=kind):
                with patch('os.scandir',failing_scandir(os.scandir,target,kind)):
                    with self.assertRaises(error): monitor.generate_integrity_report()
        self.assertEqual(monitor.generate_integrity_report()['cases'][0]['file_count'],2)

    def test_valid_empty_missing_and_existing_exclusions_keep_their_behavior(self):
        case=self.source(); monitor=FileMonitor(self.cases)
        expected=monitor.get_case_files(case.name)
        (case/'.hidden').write_bytes(b'Existing excluded name')
        (case/'module.pyc').write_bytes(b'Existing excluded suffix')
        self.assertEqual(monitor.get_case_files(case.name),expected)
        (self.cases/'case-empty').mkdir()
        self.assertEqual(monitor.get_case_files('case-empty'),[])
        self.assertEqual(monitor.get_case_files('case-missing'),[])


if __name__=='__main__':
    unittest.main()
