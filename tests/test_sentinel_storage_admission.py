"""Configured Sentinel source identity, failure preservation and initialization effects."""
from contextlib import closing
import builtins
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.config import SentinelConfig
from paw.sentinel.database import CampaignDatabase


class SentinelStorageAdmission(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.policy=offline_policy(); self.policy.__enter__(); self.before=len(violations())

    def tearDown(self):
        blocked=violations()[self.before:]; self.policy.__exit__(None,None,None)
        self.temp.cleanup(); self.assertEqual(blocked,[])

    def snapshot(self):
        return {p.relative_to(self.root).as_posix():p.read_bytes() if p.is_file() else None for p in self.root.rglob('*')}

    def test_invalid_or_ambiguous_present_config_never_falls_back(self):
        path=self.root/'config.json'
        for source in ('null','false','0','[]','""','{"storage":1}',
                '{"storage":{"database_path":""}}','{"storage":{"database_path":3}}',
                '{"storage":{"database_path":"first.db","database_path":"other.db"}}',
                '{"number":NaN}','{"number":1e999}'):
            path.write_text(source,encoding='utf-8'); before=self.snapshot()
            with self.subTest(source=source),self.assertRaises(ValueError): SentinelConfig(str(path))
            self.assertEqual(self.snapshot(),before)
        path.write_text('{}'); config=SentinelConfig(str(path))
        self.assertTrue(config.get('storage.database_path').endswith('sentinel.db'))

    def test_unreadable_present_config_propagates_instead_of_defaults(self):
        path=self.root/'config.json'; path.write_text('{"storage":{"database_path":"chosen.db"}}')
        original=builtins.open
        def denied(target,*args,**kwargs):
            if Path(target)==path: raise PermissionError('declared unreadable config')
            return original(target,*args,**kwargs)
        before=self.snapshot()
        with patch('builtins.open',denied),self.assertRaises(PermissionError): SentinelConfig(str(path))
        self.assertEqual(self.snapshot(),before)

    def test_config_size_is_bounded_before_decoding(self):
        path=self.root/'config.json'; path.write_bytes(b' '+b' '*(1024**2)+b'{}')
        with self.assertRaisesRegex(ValueError,'limit'): SentinelConfig(str(path))

    def test_config_and_configured_database_paths_remain_bound_after_chdir(self):
        work=self.root/'work'; neighbor=self.root/'neighbor'; work.mkdir(); neighbor.mkdir()
        (work/'sentinel_config.json').write_text('{"storage":{"database_path":"chosen.db"}}')
        (neighbor/'sentinel_config.json').write_text('{"retained":"neighbor"}')
        previous=Path.cwd()
        try:
            os.chdir(work); config=SentinelConfig()
            os.chdir(neighbor)
            self.assertEqual(Path(config.get('storage.database_path')),work/'chosen.db')
            config.set('storage.retention_days',7)
            self.assertEqual(json.loads((work/'sentinel_config.json').read_text())['storage']['retention_days'],7)
            self.assertEqual(json.loads((neighbor/'sentinel_config.json').read_text()),{'retained':'neighbor'})
        finally: os.chdir(previous)

    def test_failed_config_encoding_or_publication_preserves_source_and_memory(self):
        path=self.root/'config.json'; path.write_text('{"storage":{"database_path":"chosen.db"}}')
        config=SentinelConfig(str(path)); before=self.snapshot()
        with self.assertRaises((ValueError,TypeError)): config.set('new_field',object())
        self.assertIsNone(config.get('new_field')); self.assertEqual(self.snapshot(),before)
        with patch('os.replace',side_effect=OSError('declared failed publication')):
            with self.assertRaises(OSError): config.set('storage.retention_days',7)
        self.assertIsNone(config.get('storage.retention_days')); self.assertEqual(self.snapshot(),before)

    def test_config_save_cannot_overwrite_a_replacement_source(self):
        path=self.root/'config.json'; path.write_text('{}')
        config=SentinelConfig(str(path)); path.rename(self.root/'retained.json')
        path.write_text('{"retained":"replacement"}')
        before=self.snapshot()
        with self.assertRaises((ValueError,OSError)): config.reset_to_defaults()
        self.assertEqual(self.snapshot(),before)

    def test_writer_root_is_bound_and_later_missing_targets_are_not_created(self):
        first=self.root/'first'; second=self.root/'second'; first.mkdir(); second.mkdir()
        previous=Path.cwd()
        try:
            os.chdir(first); database=CampaignDatabase('saved.db'); identifier=database.add_campaign('first','literal')
            os.chdir(second)
            self.assertIsNotNone(database.get_campaign(identifier))
            self.assertFalse((second/'saved.db').exists())
            (first/'saved.db').unlink()
            with self.assertRaises(FileNotFoundError): database.get_active_campaigns()
            self.assertFalse((first/'saved.db').exists())
        finally: os.chdir(previous)

    def test_reader_and_writer_reject_replaced_storage(self):
        for read_only in (False,True):
            path=self.root/('source-'+str(read_only)+'.db')
            writer=CampaignDatabase(str(path)); writer.add_campaign('original','literal')
            selected=CampaignDatabase(str(path),read_only=read_only)
            path.rename(path.with_suffix('.retained'))
            CampaignDatabase(str(path)).add_campaign('replacement','literal')
            before=self.snapshot()
            with self.subTest(read_only=read_only),self.assertRaises((ValueError,OSError)): selected.get_active_campaigns()
            self.assertEqual(self.snapshot(),before)

    def test_rejected_passive_path_never_gets_a_following_directory_probe(self):
        with patch('paw.sentinel.database._admit_storage_path',side_effect=ValueError('rejected path')), \
                patch.object(Path,'is_dir',side_effect=AssertionError('Rejected path followed')):
            with self.assertRaises(ValueError): CampaignDatabase(str(self.root/'rejected.db'),read_only=True)

    def test_failed_schema_initialization_rolls_back_existing_ddl(self):
        for name in ('campaigns','checks','alerts','victim_intelligence'):
            with self.subTest(name=name):
                path=self.root/(name+'-view.db')
                with closing(sqlite3.connect(path)) as conn,conn:
                    conn.execute('CREATE TABLE original (value TEXT)'); conn.execute("INSERT INTO original VALUES ('retained')")
                    conn.execute('CREATE VIEW '+name+' AS SELECT * FROM original')
                before=self.snapshot()
                with self.assertRaises(sqlite3.DatabaseError): CampaignDatabase(str(path))
                self.assertEqual(self.snapshot(),before)

    def test_nonempty_unrecognized_database_is_not_converted_to_sentinel(self):
        path=self.root/'unrelated.db'
        with closing(sqlite3.connect(path)) as conn,conn:
            conn.execute('CREATE TABLE sqliteX_saved_index (original BLOB)')
            conn.execute('INSERT INTO sqliteX_saved_index VALUES (?)',(b'original unrelated bytes',))
        before=self.snapshot()
        with self.assertRaises(sqlite3.DatabaseError): CampaignDatabase(str(path))
        self.assertEqual(self.snapshot(),before)

    def test_failed_new_initialization_preserves_its_uninitialized_target(self):
        path=self.root/'new.db'
        with patch.object(CampaignDatabase,'_migrate_database',side_effect=OSError('declared migration failure')):
            with self.assertRaises(OSError): CampaignDatabase(str(path))
        self.assertTrue(path.exists())
        self.assertEqual(self.snapshot(),{'new.db':b''})

    def test_new_database_creation_cannot_adopt_a_replacement_file(self):
        target=self.root/'new.db'; replacement=self.root/'replacement.db'
        with closing(sqlite3.connect(replacement)) as conn,conn:
            conn.execute('CREATE TABLE retained (value TEXT)'); conn.execute("INSERT INTO retained VALUES ('original')")
        original=replacement.read_bytes(); close=os.close; replaced=False
        def changed(descriptor):
            nonlocal replaced
            close(descriptor)
            if target.exists() and not replaced:
                replaced=True; target.rename(self.root/'owned-empty.retained'); replacement.rename(target)
        with patch('os.close',changed),self.assertRaisesRegex(ValueError,'replaced'): CampaignDatabase(str(target))
        self.assertEqual(target.read_bytes(),original)

    def test_missing_empty_and_saved_config_roundtrip_remain_explicit(self):
        path=self.root/'new-config.json'; config=SentinelConfig(str(path))
        self.assertFalse(path.exists())
        config.set('stored',{'zero':0,'false':False,'null':None,'text':'Ω'})
        saved=SentinelConfig(str(path))
        self.assertEqual(saved.get('stored'),{'zero':0,'false':False,'null':None,'text':'Ω'})
        self.assertEqual(saved.get_storage_config()['database_path'],saved.get('storage.database_path'))
        os.chmod(path,0o444)
        try: self.assertEqual(SentinelConfig(str(path)).get('stored'),saved.get('stored'))
        finally: os.chmod(path,0o666)
        saved=SentinelConfig(str(path))
        saved.reset_to_defaults(); self.assertIsNone(SentinelConfig(str(path)).get('stored'))

    def test_migration_failure_restores_earlier_alter_and_created_tables(self):
        path=self.root/'saved.db'
        with closing(sqlite3.connect(path)) as conn,conn:
            conn.execute('CREATE TABLE victim_intelligence (id INTEGER, original TEXT)')
            conn.execute("INSERT INTO victim_intelligence VALUES (1,'retained')")
        before=self.snapshot()
        def failed(self,conn):
            conn.execute('ALTER TABLE victim_intelligence ADD COLUMN test_added TEXT')
            raise OSError('declared mid-migration failure')
        with patch.object(CampaignDatabase,'_migrate_database',failed),self.assertRaises(OSError): CampaignDatabase(str(path))
        self.assertEqual(self.snapshot(),before)

    def test_existing_writer_constructor_rejects_pending_journal_and_wal(self):
        path=self.root/'saved.db'; CampaignDatabase(str(path))
        sidecar=Path(str(path)+'-journal'); sidecar.write_bytes(b'pending original source')
        before=self.snapshot()
        with self.assertRaises(ValueError): CampaignDatabase(str(path))
        self.assertEqual(self.snapshot(),before); sidecar.unlink()
        with closing(sqlite3.connect(path)) as conn: conn.execute('PRAGMA journal_mode=WAL')
        before=self.snapshot()
        with self.assertRaises(ValueError): CampaignDatabase(str(path))
        self.assertEqual(self.snapshot(),before)

    def test_literal_sqlite_special_characters_and_committed_rows_are_preserved(self):
        path=self.root/'saved # Ω % mode=rw.db'
        writer=CampaignDatabase(str(path)); identifier=writer.add_campaign('source','literal',{'original':True})
        reader=CampaignDatabase(str(path),read_only=True); before=self.snapshot()
        self.assertEqual(reader.get_campaign(identifier)['metadata'],{'original':True})
        self.assertEqual(self.snapshot(),before)

    def test_hard_link_aliases_cannot_bypass_storage_journal_admission(self):
        path=self.root/'source.db'; CampaignDatabase(str(path))
        alias=self.root/'alias.db'
        try: os.link(path,alias)
        except OSError as error: self.skipTest('Hard link fixture unavailable: '+str(error))
        before=self.snapshot()
        for selected in (path,alias):
            for mode in (False,True):
                with self.subTest(path=selected,mode=mode),self.assertRaises(ValueError): CampaignDatabase(str(selected),read_only=mode)
        config=self.root/'config.json'; config.write_text('{}'); os.link(config,self.root/'config-alias.json')
        with self.assertRaises(ValueError): SentinelConfig(str(config))
        self.assertEqual({k:v for k,v in self.snapshot().items() if k in before},before)

    def test_links_to_database_config_and_parent_are_rejected(self):
        outside=self.root/'outside'; outside.mkdir()
        source=outside/'saved.db'; CampaignDatabase(str(source))
        config=outside/'config.json'; config.write_text('{}')
        link=self.root/'linked.db'
        try: link.symlink_to(source)
        except OSError as error: self.skipTest('Symlink privilege unavailable: '+str(error))
        try:
            for mode in (False,True):
                with self.assertRaises(ValueError): CampaignDatabase(str(link),read_only=mode)
            link.unlink(); link.symlink_to(config)
            with self.assertRaises(ValueError): SentinelConfig(str(link))
            link.unlink(); link.symlink_to(outside,target_is_directory=True)
            with self.assertRaises(ValueError): CampaignDatabase(str(link/'new.db'))
            self.assertFalse((outside/'new.db').exists())
        finally:
            if link.is_symlink(): link.unlink()

    def test_ephemeral_uri_network_and_blank_paths_fail_before_filesystem_access(self):
        for path in ('', ' ', ':memory:', 'file:unexpected?mode=rwc', '\\\\server\\share\\saved.db', '//server/share/db'):
            with self.subTest(path=path),patch.object(Path,'lstat',side_effect=AssertionError('Filesystem accessed')), \
                    patch('os.makedirs',side_effect=AssertionError('Directory creation attempted')), \
                    patch('sqlite3.connect',side_effect=AssertionError('SQLite access attempted')):
                with self.assertRaises(ValueError): CampaignDatabase(path)

    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO admission fixture')
    def test_special_storage_is_rejected_before_sqlite_or_body_open(self):
        path=self.root/'pending-stream'; os.mkfifo(path)
        try:
            with patch('builtins.open',side_effect=AssertionError('FIFO opened')), \
                    patch('sqlite3.connect',side_effect=AssertionError('SQLite attempted FIFO')):
                for mode in (False,True):
                    with self.assertRaises(ValueError): CampaignDatabase(str(path),read_only=mode)
                with self.assertRaises(ValueError): SentinelConfig(str(path))
        finally: path.unlink()


if __name__=='__main__': unittest.main()
