"""Real SQLite/ownership fixtures; query admission is not evidence authentication."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from paw.core import index
from paw.core.runtime import atomic_json


class QueryReadContracts(unittest.TestCase):
    def setUp(self):
        self.previous_cwd, self.previous_db = Path.cwd(), index._db
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chdir(self.root)
        index._db = None

    def tearDown(self):
        if index._db is not None: index._db.close()
        index._db = self.previous_db
        os.chdir(self.previous_cwd)
        self.temporary.cleanup()

    def seed(self, identifiers=('historical',)):
        (self.root/'cases').mkdir(exist_ok=True)
        self.database = self.root/'cases/index.db'
        with closing(sqlite3.connect(self.database)) as connection:
            # Historical schema deliberately has no SimHash version columns.
            connection.execute('CREATE TABLE cases (id TEXT PRIMARY KEY, created_utc TEXT, score REAL, simhash TEXT)')
            connection.execute('CREATE TABLE indicators (case_id TEXT, type TEXT, value TEXT)')
            for identifier in identifiers:
                connection.execute("INSERT INTO cases VALUES (?,datetime('now'),0.2,'0123456789abcdef')",(identifier,))
                connection.execute("INSERT INTO indicators VALUES (?,'domain','fixture.invalid')",(identifier,))
            connection.commit()

    def query(self):
        return index.query_recent('domain','fixture.invalid')

    def owner(self, identifier, status='running', stopped=False):
        directory = self.root/'cases'/('case-'+identifier)
        directory.mkdir(exist_ok=True)
        job_id = 'analysis_'+identifier
        control = self.root/'jobs'/job_id
        control.mkdir(parents=True,exist_ok=True)
        atomic_json(directory/'manifest.json',{'analysis_job':job_id})
        atomic_json(directory/'execution.json',{'status':'completed'})
        atomic_json(control.parent/(job_id+'.json'),{'origin':'cli','status':status,
            'case_ids':[directory.name]})
        atomic_json(control/'supervisor.json',{'tree_stopped':stopped})
        return directory,control

    def test_missing_index_does_not_create_any_storage(self):
        self.assertEqual(self.query(),[])
        self.assertEqual(list(self.root.iterdir()),[])
        self.assertIsNone(index._db)

    def test_legacy_reader_preserves_schema_bytes_and_closes_connection(self):
        self.seed()
        before = self.database.read_bytes()
        rows = self.query()
        self.assertEqual(rows[0]['simhash'],'0123456789abcdef')
        self.assertEqual(rows[0]['simhash_method'],'legacy_md5_prefix_64')
        self.assertEqual(self.database.read_bytes(),before)
        self.assertIsNone(index._db)
        # Windows will reject the rename if the query reader leaked its handle.
        renamed = self.database.with_suffix('.saved')
        self.database.rename(renamed); renamed.rename(self.database)

    def test_query_reads_committed_snapshot_while_writer_holds_transaction(self):
        self.seed()
        with closing(sqlite3.connect(self.database)) as writer:
            writer.execute('BEGIN IMMEDIATE')
            writer.execute('UPDATE cases SET score=0.9')
            self.assertEqual(self.query()[0]['score'],0.2)
            writer.rollback()
        self.assertIsNone(index._db)

    def test_active_and_unconfirmed_owners_hidden_stopped_owners_readable(self):
        self.seed(('running','queued','blocked','nostop','missing','wrongtype','finished','partial'))
        for identifier,status,stopped in (
                ('running','running',True),('queued','queued',True),
                ('blocked','recovery_blocked',True),('nostop','completed',False),
                ('missing','completed',True),('wrongtype','completed','true'),
                ('finished','completed',True),('partial','interrupted',True)):
            directory,control = self.owner(identifier,status,stopped)
            if identifier=='missing': (control/'supervisor.json').unlink()
        before = {str(path.relative_to(self.root)):hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual({row['id'] for row in self.query()},{'finished','partial'})
        after = {str(path.relative_to(self.root)):hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(after,before)

    def test_missing_or_invalid_job_state_and_progress_fallback_fail_closed(self):
        self.seed(('missing','invalid','progress'))
        directory,control = self.owner('missing','completed',True)
        (control.parent/'analysis_missing.json').unlink()
        control.rename(control.with_name('removed'))  # No owner control or state.
        directory,control = self.owner('invalid','completed',True)
        atomic_json(directory/'manifest.json',{'analysis_job':'../invalid'})
        directory,control = self.owner('progress')
        (directory/'manifest.json').write_text('{',encoding='utf-8')
        atomic_json(control/'progress.json',{'case_ids':[directory.name]})
        self.assertEqual(self.query(),[])

    def test_legacy_control_remains_hidden_until_confirmed_stop(self):
        self.seed(('legacy',))
        directory = self.root/'cases/case-legacy'; directory.mkdir()
        control = self.root/'.paw-jobs/legacy'; control.mkdir(parents=True)
        atomic_json(control/'progress.json',{'case_ids':[directory.name]})
        self.assertEqual(self.query(),[])
        atomic_json(control/'supervisor.json',{'tree_stopped':True,'status':'exited','returncode':0})
        atomic_json(control/'result.json',{'status':'completed','case_ids':[directory.name]})
        self.assertEqual([row['id'] for row in self.query()],['legacy'])
        self.assertFalse((self.root/'jobs').exists())

    def test_unowned_unstable_execution_and_unsafe_case_identifier_hidden(self):
        self.seed(('historical','running','queued','blocked','../outside'))
        for identifier,status in (('running','running'),('queued','queued'),('blocked','recovery_blocked')):
            directory = self.root/'cases'/('case-'+identifier); directory.mkdir()
            atomic_json(directory/'execution.json',{'status':status})
        self.assertEqual([row['id'] for row in self.query()],['historical'])


if __name__=='__main__': unittest.main()
