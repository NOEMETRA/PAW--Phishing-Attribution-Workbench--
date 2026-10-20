"""Local campaign effects and bounded file observations share honest failure semantics."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout
import builtins
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.file_monitor import FileMonitor
from paw.sentinel.monitor import SentinelMonitor


class SentinelStorageFamily(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.database = self.root/'saved.db'; self.db = CampaignDatabase(str(self.database))
        self.cases = self.root/'cases'; self.cases.mkdir()
        self.policy = offline_policy(); self.policy.__enter__(); self.before = len(violations())

    def tearDown(self):
        blocked = violations()[self.before:]; self.policy.__exit__(None,None,None)
        self.temp.cleanup(); self.assertEqual(blocked, [])

    def case(self, name='case-saved'):
        case = self.cases/name; case.mkdir(); (case/'input.eml').write_bytes(b'original')
        return case

    def monitor(self):
        return SentinelMonitor(database=self.db)

    def test_remove_api_reports_only_an_actual_active_row_transition(self):
        identifier = self.db.add_campaign('source','https://example.invalid/stored',{'source':'literal'})
        monitor = self.monitor()
        self.assertFalse(monitor.remove_campaign('absent'))
        self.assertTrue(monitor.remove_campaign(identifier))
        before = self.database.read_bytes()
        self.assertFalse(monitor.remove_campaign(identifier))
        self.assertEqual(self.database.read_bytes(),before)
        self.assertEqual(self.db.get_campaign(identifier)['metadata'],{'source':'literal'})

    def test_remove_api_cannot_acknowledge_a_deleted_selection(self):
        identifier = self.db.add_campaign('source','https://example.invalid/stored')
        original = self.db.get_campaign
        def deleted(key):
            record = original(key)
            with closing(sqlite3.connect(self.database)) as conn,conn:
                conn.execute('DELETE FROM campaigns WHERE id=?',(key,))
            return record
        # Old API reads, then acknowledges an UPDATE affecting zero rows.
        with patch.object(self.db,'get_campaign',deleted):
            result = self.monitor().remove_campaign(identifier)
        if result:
            self.assertIsNotNone(self.db.get_campaign(identifier),'Removal success without an affected row')

    def test_campaign_api_admission_preserves_storage_for_invalid_inputs(self):
        for case,url,metadata in (('', 'https://example.invalid/',None),(' ', 'literal',None),
                ('source','\t',None),(7,'literal',None),('source',None,None),
                ('source','literal',[]),('source','literal',{'number':float('nan')}),
                ('source','literal',{'number':float('inf')})):
            with self.subTest(case=case,url=url,metadata=metadata):
                before = self.database.read_bytes()
                with self.assertRaises((ValueError,TypeError)): self.db.add_campaign(case,url,metadata)
                self.assertEqual(self.database.read_bytes(),before)

    def test_legacy_duplicate_case_insertion_is_rejected_without_unique_constraint(self):
        self.db.add_campaign('source','literal')
        with closing(sqlite3.connect(self.database)) as conn,conn:
            conn.execute('CREATE TABLE saved AS SELECT * FROM campaigns')
            conn.execute('DROP TABLE campaigns'); conn.execute('ALTER TABLE saved RENAME TO campaigns')
        before = self.database.read_bytes()
        with self.assertRaises((ValueError,sqlite3.IntegrityError)): self.db.add_campaign('source','replacement')
        self.assertEqual(self.database.read_bytes(),before)

    def test_case_bound_removal_rejects_ambiguity_and_rolls_back(self):
        identifier = self.db.add_campaign('source','literal')
        with closing(sqlite3.connect(self.database)) as conn,conn:
            conn.execute('CREATE TABLE saved AS SELECT * FROM campaigns')
            conn.execute('DROP TABLE campaigns'); conn.execute('ALTER TABLE saved RENAME TO campaigns')
            conn.execute('INSERT INTO campaigns SELECT * FROM campaigns')
        before = self.database.read_bytes()
        with self.assertRaisesRegex(ValueError,'Multiple'): self.db.remove_campaign(identifier,case_id='source')
        self.assertEqual(self.database.read_bytes(),before)

    def test_concurrent_removers_have_one_winner_and_failed_trigger_rolls_back(self):
        identifier = self.db.add_campaign('source','literal')
        barrier = threading.Barrier(2)
        def remove():
            barrier.wait(timeout=5); return self.db.remove_campaign(identifier)
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks=[pool.submit(remove) for _ in range(2)]
            self.assertEqual(sorted(task.result(timeout=10) for task in tasks),[False,True])
        self.db.update_campaign_status(identifier,'active')
        with closing(sqlite3.connect(self.database)) as conn,conn:
            conn.execute("CREATE TRIGGER fail_remove AFTER UPDATE ON campaigns BEGIN SELECT RAISE(ABORT,'injected'); END")
        before = self.database.read_bytes()
        with self.assertRaises(sqlite3.IntegrityError): self.db.remove_campaign(identifier)
        self.assertEqual(self.database.read_bytes(),before)
        with closing(sqlite3.connect(self.database)) as conn,conn:
            conn.execute('DROP TRIGGER fail_remove')
            conn.execute("CREATE TRIGGER undo_remove AFTER UPDATE ON campaigns BEGIN UPDATE campaigns SET status='active' WHERE id=NEW.id; END")
        before=self.database.read_bytes()
        with self.assertRaisesRegex(RuntimeError,'rolled back'): self.db.remove_campaign(identifier)
        self.assertEqual(self.database.read_bytes(),before)

    def test_file_api_rejects_parent_and_absolute_case_paths(self):
        outside=self.root/'outside'; outside.mkdir(); (outside/'retained.txt').write_bytes(b'outside')
        monitor=FileMonitor(self.cases)
        for name in ('../outside',str(outside),'','..','child/../case-saved'):
            for method in (monitor.get_case_files,monitor.check_file_changes,monitor.verify_merkle_integrity):
                with self.subTest(name=name,method=method.__name__), self.assertRaises(ValueError): method(name)
        self.assertEqual(monitor._baseline_hashes,{})

    def test_relative_root_remains_bound_to_its_original_source(self):
        self.case()
        neighbor=self.root/'neighbor'; (neighbor/'cases/case-saved').mkdir(parents=True)
        (neighbor/'cases/case-saved/input.eml').write_bytes(b'unrelated source')
        previous=Path.cwd()
        try:
            os.chdir(self.root); monitor=FileMonitor('cases')
            monitor.check_file_changes('case-saved'); baseline=dict(monitor._baseline_hashes)
            os.chdir(neighbor); result=monitor.check_file_changes('case-saved')
            self.assertFalse(any(result[key] for key in ('new_files','modified_files','deleted_files')))
            self.assertEqual(monitor._baseline_hashes,baseline)
            self.assertEqual(monitor.get_case_files('case-saved'),[str(self.cases/'case-saved/input.eml')])
        finally: os.chdir(previous)

    def test_concurrent_adds_to_legacy_table_have_one_winner(self):
        with closing(sqlite3.connect(self.database)) as conn,conn:
            conn.execute('CREATE TABLE saved AS SELECT * FROM campaigns')
            conn.execute('DROP TABLE campaigns'); conn.execute('ALTER TABLE saved RENAME TO campaigns')
        barrier=threading.Barrier(2)
        def add():
            barrier.wait(timeout=5)
            try: self.db.add_campaign('source','literal',{'original':True}); return True
            except ValueError: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks=[pool.submit(add) for _ in range(2)]
            self.assertEqual(sorted(task.result(timeout=10) for task in tasks),[False,True])
        self.assertEqual(len(self.db.get_active_campaigns()),1)

    def test_case_bound_removal_preserves_neighbor_and_inactive_rows(self):
        first=self.db.add_campaign('first','literal',{'first':True})
        second=self.db.add_campaign('second','literal',{'second':True})
        before=self.database.read_bytes()
        self.assertFalse(self.db.remove_campaign(first,case_id='second'))
        self.assertEqual(self.database.read_bytes(),before)
        self.assertTrue(self.db.remove_campaign(first,case_id='first'))
        self.assertEqual(self.db.get_campaign(second)['status'],'active')
        self.assertFalse(self.db.remove_campaign(first,case_id='first'))

    def test_changed_file_during_read_cannot_commit_a_mixed_digest(self):
        case=self.case(); target=case/'input.eml'; monitor=FileMonitor(self.cases)
        monitor.check_file_changes(case.name); baseline=dict(monitor._baseline_hashes)
        original=builtins.open
        def opening(path,*args,**kwargs):
            handle=original(path,*args,**kwargs)
            if Path(path)!=target: return handle
            class ChangingRead:
                def __enter__(self): handle.__enter__(); self.changed=False; return self
                def __exit__(self,*error): return handle.__exit__(*error)
                def __getattr__(self,key): return getattr(handle,key)
                def read(self,*args,**kwargs):
                    data=handle.read(*args,**kwargs)
                    if not self.changed:
                        self.changed=True
                        with original(target,'ab') as writer: writer.write(b'changed-during-read')
                    return data
            return ChangingRead()
        with patch('builtins.open',opening), self.assertRaisesRegex(OSError,'changed'): monitor.check_file_changes(case.name)
        self.assertEqual(monitor._baseline_hashes,baseline)

    def test_budget_failures_preserve_baseline_and_defer_all_case_records(self):
        first=self.case('case-a'); second=self.case('case-b')
        monitor=FileMonitor(self.cases,max_files=1,max_bytes=100,max_file_bytes=100,max_cases=10)
        monitor.check_file_changes(first.name); baseline=dict(monitor._baseline_hashes)
        output=io.StringIO()
        with redirect_stdout(output),self.assertRaisesRegex(ValueError,'limit'): monitor.monitor_all_cases()
        self.assertEqual(monitor._baseline_hashes,baseline); self.assertNotIn('[file_monitor] Case ',output.getvalue())
        for limits in ({'max_bytes':6},{'max_file_bytes':6},{'max_cases':1}):
            limited=FileMonitor(self.cases,**limits)
            with self.subTest(limits=limits),self.assertRaisesRegex(ValueError,'limit'): limited.generate_integrity_report()
            self.assertEqual(limited._baseline_hashes,{})

    def test_oversized_file_is_rejected_before_hashing(self):
        case=self.case(); monitor=FileMonitor(self.cases,max_file_bytes=6)
        with self.assertRaisesRegex(ValueError,'limit'): monitor.calculate_file_hash(case/'input.eml')
        self.assertEqual(monitor._baseline_hashes,{})

    def test_inventory_change_during_scan_is_not_committed(self):
        case=self.case(); monitor=FileMonitor(self.cases)
        monitor.check_file_changes(case.name); baseline=dict(monitor._baseline_hashes)
        original=monitor.calculate_file_hash
        def changed(path):
            digest=original(path); (case/'new-artifact').write_bytes(b'added after hash'); return digest
        with patch.object(monitor,'calculate_file_hash',changed),self.assertRaisesRegex(OSError,'changed'):
            monitor.check_file_changes(case.name)
        self.assertEqual(monitor._baseline_hashes,baseline)

    def test_same_instance_baseline_scans_are_serialized(self):
        case=self.case(); monitor=FileMonitor(self.cases)
        paused=threading.Event(); release=threading.Event(); started=threading.Event(); overlapped=threading.Event()
        original=monitor.calculate_file_hash
        def reading(path):
            if threading.current_thread().name=='first':
                paused.set(); self.assertTrue(release.wait(5))
            else: overlapped.set()
            return original(path)
        errors=[]
        def scan():
            try: monitor.check_file_changes(case.name)
            except BaseException as error: errors.append(error)
        def second(): started.set(); scan()
        with patch.object(monitor,'calculate_file_hash',reading):
            first=threading.Thread(target=scan,name='first'); later=threading.Thread(target=second,name='second')
            first.start()
            try:
                self.assertTrue(paused.wait(5)); later.start(); self.assertTrue(started.wait(5))
                self.assertFalse(overlapped.wait(0.1),'Two scans entered one instance baseline concurrently')
            finally:
                release.set(); first.join(5)
                if later.ident is not None: later.join(5)
            self.assertFalse(first.is_alive() or later.is_alive())
        self.assertEqual(errors,[])
        self.assertEqual(monitor._baseline_hashes[str(case/'input.eml')],hashlib.sha256(b'original').hexdigest())

    def test_invalid_resource_limits_do_not_access_sources(self):
        for key in ('max_files','max_bytes','max_file_bytes','max_cases'):
            for value in (0,-1,True,1.5,None):
                with self.subTest(key=key,value=value),self.assertRaises(ValueError): FileMonitor(self.cases,**{key:value})

    def test_links_cannot_admit_outside_case_or_nested_directory(self):
        outside=self.root/'outside'; outside.mkdir(); (outside/'retained.txt').write_bytes(b'outside')
        link=self.cases/'case-link'
        try: link.symlink_to(outside,target_is_directory=True)
        except OSError as error: self.skipTest('Directory symlink privilege unavailable: '+str(error))
        monitor=FileMonitor(self.cases)
        try:
            for method in (monitor.scan_cases_directory,monitor.monitor_all_cases,monitor.generate_integrity_report):
                with self.assertRaises(ValueError): method()
            with self.assertRaises(ValueError): monitor.get_case_files(link.name)
            link.unlink(); case=self.case(); (case/'nested-link').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(ValueError): monitor.get_case_files(case.name)
        finally:
            if link.is_symlink(): link.unlink()

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX special-file fixture')
    def test_fifo_is_rejected_before_open(self):
        case=self.case(); fifo=case/'pending-stream'; os.mkfifo(fifo)
        monitor=FileMonitor(self.cases)
        try:
            with self.assertRaises(ValueError): monitor.get_case_files(case.name)
            with self.assertRaises(ValueError): monitor.calculate_file_hash(fifo)
        finally: fifo.unlink()


if __name__=='__main__': unittest.main()
