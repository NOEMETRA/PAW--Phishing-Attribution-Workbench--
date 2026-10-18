"""Actual file digests/baselines with explicit open and mid-read failure injection."""
import builtins
from contextlib import redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.file_monitor import FileMonitor


def failing_open(original, target, kind):
    """Inject only a selected source failure; all successful reads use real files."""
    selected=os.path.normcase(os.path.abspath(target))
    def opening(path,*args,**kwargs):
        if not isinstance(path,(str,os.PathLike)) or os.path.normcase(os.path.abspath(path))!=selected:
            return original(path,*args,**kwargs)
        if kind=='denied': raise PermissionError('Explicit source read-denial fixture')
        if kind=='missing': raise FileNotFoundError('Explicit source disappearance fixture')
        handle=original(path,*args,**kwargs)
        class InterruptedRead:
            def __enter__(self):
                handle.__enter__()
                self.read_once=False
                return self
            def __exit__(self,*error): return handle.__exit__(*error)
            def read(self,*args,**kwargs):
                if self.read_once: raise OSError('Explicit mid-read interruption fixture')
                self.read_once=True
                return handle.read(*args,**kwargs)
        return InterruptedRead()
    return opening


class SentinelHashFailures(unittest.TestCase):
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

    def source(self,name='case-stored',content=b'Original saved bytes'):
        case=self.cases/name; case.mkdir()
        target=case/'input.eml'; target.write_bytes(content)
        return case,target

    def test_direct_hash_errors_propagate_and_empty_file_is_a_real_digest(self):
        case,target=self.source(content=b'')
        monitor=FileMonitor(self.cases)
        self.assertEqual(monitor.calculate_file_hash(target),hashlib.sha256(b'').hexdigest())
        with self.assertRaises(FileNotFoundError): monitor.calculate_file_hash(case/'absent')
        target.write_bytes(b'Actual nonempty bytes before the injected read interruption')
        for kind,error in (('denied',PermissionError),('missing',FileNotFoundError),('stream',OSError)):
            with self.subTest(kind=kind),patch('builtins.open',failing_open(builtins.open,target,kind)):
                with self.assertRaises(error): monitor.calculate_file_hash(target)

    def test_failed_hash_never_becomes_deletion_or_a_recovered_new_file(self):
        case,target=self.source(content=b'Original stream bytes\n'*(128*1024))
        monitor=FileMonitor(self.cases)
        monitor.check_file_changes(case.name)
        baseline=dict(monitor._baseline_hashes)
        original=target.read_bytes()
        for kind,error in (('denied',PermissionError),('missing',FileNotFoundError),('stream',OSError)):
            with self.subTest(kind=kind):
                with patch('builtins.open',failing_open(builtins.open,target,kind)):
                    with self.assertRaises(error): monitor.check_file_changes(case.name)
                self.assertEqual(monitor._baseline_hashes,baseline)
                recovered=monitor.check_file_changes(case.name)
                for key in ('new_files','modified_files','deleted_files'): self.assertEqual(recovered[key],[])
                self.assertEqual(target.read_bytes(),original)

    def test_incomplete_first_case_scan_cannot_commit_earlier_successful_hashes(self):
        case,target=self.source()
        (case/'aaa-readable.txt').write_bytes(b'Actual earlier readable file')
        monitor=FileMonitor(self.cases)
        with patch('builtins.open',failing_open(builtins.open,target,'denied')):
            with self.assertRaises(PermissionError): monitor.check_file_changes(case.name)
        self.assertEqual(monitor._baseline_hashes,{})
        self.assertEqual(len(monitor.check_file_changes(case.name)['new_files']),2)

    def test_all_case_failure_restores_prior_baseline_and_defers_check_records(self):
        early,first=self.source('case-a-earlier')
        late,last=self.source('case-z-later')
        monitor=FileMonitor(self.cases)
        with redirect_stdout(io.StringIO()): monitor.monitor_all_cases()
        baseline=dict(monitor._baseline_hashes)
        first.write_bytes(b'Earlier real modification')
        last.write_bytes(b'Later real modification')
        for kind,error in (('denied',PermissionError),('missing',FileNotFoundError),('stream',OSError)):
            printed=io.StringIO()
            with self.subTest(kind=kind):
                with redirect_stdout(printed),patch('builtins.open',failing_open(builtins.open,last,kind)):
                    with self.assertRaises(error): monitor.monitor_all_cases()
                self.assertEqual(monitor._baseline_hashes,baseline)
                self.assertNotIn('[file_monitor] Case ',printed.getvalue())
        with redirect_stdout(io.StringIO()): recovered=monitor.monitor_all_cases()
        selected={r['case_id']:r for r in recovered}
        for case,target in ((early,first),(late,last)):
            self.assertEqual(selected[case.name]['new_files'],[])
            self.assertEqual(selected[case.name]['deleted_files'],[])
            self.assertEqual(selected[case.name]['modified_files'],[{'path':str(target),
                'old_hash':baseline[str(target)],'new_hash':hashlib.sha256(target.read_bytes()).hexdigest()}])
        last.unlink()
        self.assertEqual(monitor.check_file_changes(late.name)['deleted_files'],[{
            'path':str(last),'last_hash':hashlib.sha256(b'Later real modification').hexdigest()}])

    def test_failed_first_all_case_scan_does_not_commit_neighbor_or_record_results(self):
        self.source('case-a-earlier')
        _,target=self.source('case-z-later')
        monitor=FileMonitor(self.cases)
        printed=io.StringIO()
        with redirect_stdout(printed),patch('builtins.open',failing_open(builtins.open,target,'denied')):
            with self.assertRaises(PermissionError): monitor.monitor_all_cases()
        self.assertEqual(monitor._baseline_hashes,{})
        self.assertNotIn('[file_monitor] Case ',printed.getvalue())
        with redirect_stdout(io.StringIO()): recovered=monitor.monitor_all_cases()
        self.assertEqual([len(r['new_files']) for r in recovered],[1,1])


if __name__=='__main__':
    unittest.main()
