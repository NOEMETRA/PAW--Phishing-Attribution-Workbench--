"""Stored campaign fields must correspond to named SQLite columns."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase


COLUMNS = ('id', 'case_id', 'created_at', 'last_check', 'status', 'url',
           'domain', 'title', 'description', 'risk_level', 'metadata')
LAYOUTS = ('fresh', 'reversed', 'extra-first', 'rotated')
SOURCE = dict(zip(COLUMNS, ('saved-id', 'saved-case', 'stored creation', 'stored check',
    'active', 'https://example.invalid/never-visit', 'stored domain', 'Stored Ω title',
    'literal description', 'unverified label', ' {"Ω": [1, false], "claim": "stored"} \n')))


def campaign_database(path, layout):
    """Actual schema fixture; preserve current named column constraints/defaults."""
    writer = CampaignDatabase(str(path))
    if layout == 'fresh':
        return writer
    with writer.connection() as connection:
        fields = connection.execute('PRAGMA table_info(campaigns)').fetchall()
        definitions = {}
        for _, name, kind, required, default, primary in fields:
            definitions[name] = '"'+name+'" '+kind
            if primary: definitions[name] += ' PRIMARY KEY'
            if required: definitions[name] += ' NOT NULL'
            if default is not None: definitions[name] += ' DEFAULT '+default
        names = list(COLUMNS)
        if layout == 'reversed': names.reverse()
        elif layout == 'rotated': names = names[3:]+names[:3]
        elif layout == 'extra-first':
            names.insert(0, 'extension_note')
            definitions['extension_note'] = 'extension_note BLOB'
        else: raise ValueError(layout)
        connection.execute('DROP TABLE campaigns')
        connection.execute('CREATE TABLE campaigns ('+', '.join(definitions[n] for n in names)
                           +', UNIQUE(case_id))')
    return writer


def seed_campaign(writer, **overrides):
    row = dict(SOURCE, **overrides)
    with writer.connection() as connection:
        connection.execute('INSERT INTO campaigns ('+', '.join(COLUMNS)+') VALUES ('
                           +', '.join('?' for _ in COLUMNS)+')', tuple(row[n] for n in COLUMNS))
    return row


class SentinelCampaignColumns(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = offline_policy(); self.policy.__enter__()
        self.before = len(violations())

    def tearDown(self):
        blocked = violations()[self.before:]
        self.policy.__exit__(None, None, None)
        self.temporary.cleanup()
        self.assertEqual(blocked, [])

    def test_both_readers_bind_all_known_fields_to_independent_named_sql(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                writer = campaign_database(self.root/(layout+'.db'), layout)
                seed_campaign(writer)
                reader = CampaignDatabase(writer.db_path, read_only=True)
                before = Path(writer.db_path).read_bytes()
                with closing(sqlite3.connect(writer.db_path)) as connection:
                    stored = dict(zip(COLUMNS, connection.execute(
                        'SELECT '+', '.join(COLUMNS)+' FROM campaigns').fetchone()))
                for record in (writer.get_campaign(SOURCE['id']), reader.get_campaign(SOURCE['id']),
                               *writer.get_active_campaigns(), *reader.get_active_campaigns()):
                    self.assertEqual({n: record[n] for n in COLUMNS if n != 'metadata'},
                                     {n: stored[n] for n in COLUMNS if n != 'metadata'})
                    self.assertEqual(record['metadata'], {'Ω': [1, False], 'claim': 'stored'})
                    self.assertEqual(record['json_evidence']['fields']['metadata']['raw_storage'],
                                     {'type': 'text', 'value': stored['metadata']})
                self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_metadata_source_and_decode_status_follow_metadata_not_its_old_offset(self):
        values = ((None, 'sql_null', 'null'), ('', 'empty', 'text'),
                  ('null', 'decoded', 'text'), ('{broken', 'invalid_json', 'text'),
                  (b'{"stored":true}', 'decoded', 'blob'), (17, 'decoded', 'text'))
        for layout in LAYOUTS:
            writer = campaign_database(self.root/(layout+'.db'), layout)
            seed_campaign(writer)
            reader = CampaignDatabase(writer.db_path, read_only=True)
            for raw, status, kind in values:
                with self.subTest(layout=layout, raw=raw):
                    # The existing metadata column has TEXT affinity, including for 17.
                    with writer.connection() as connection:
                        connection.execute('UPDATE campaigns SET metadata=?', (raw,))
                    for record in (reader.get_campaign(SOURCE['id']), *reader.get_active_campaigns()):
                        evidence = record['json_evidence']['fields']['metadata']
                        self.assertEqual(evidence['status'], status)
                        self.assertEqual(evidence['raw_storage']['type'], kind)
                        if isinstance(raw, str) or raw is None:
                            self.assertEqual(evidence['raw_storage']['value'], raw)
                        self.assertFalse(evidence['verified'])

    def test_id_selection_active_filter_and_missing_results_keep_their_contract(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                writer = campaign_database(self.root/(layout+'.db'), layout)
                seed_campaign(writer)
                seed_campaign(writer, id='removed-id', case_id='removed-case', status='removed')
                reader = CampaignDatabase(writer.db_path, read_only=True)
                self.assertEqual([r['id'] for r in reader.get_active_campaigns()], ['saved-id'])
                self.assertEqual(reader.get_campaign('removed-id')['status'], 'removed')
                self.assertIsNone(reader.get_campaign('missing'))
                writer.update_campaign_status('saved-id', 'removed')
                self.assertEqual(reader.get_active_campaigns(), [])

    def test_named_writer_and_status_update_remain_readable_in_every_layout(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                writer = campaign_database(self.root/(layout+'.db'), layout)
                identifier = writer.add_campaign('new-case', 'https://example.invalid/stored', {'Ω': 1})
                record = writer.get_campaign(identifier)
                self.assertEqual((record['id'], record['case_id'], record['url'], record['metadata']),
                    (identifier, 'new-case', 'https://example.invalid/stored', {'Ω': 1}))
                writer.update_campaign_status(identifier, 'removed')
                self.assertEqual(writer.get_campaign(identifier)['status'], 'removed')

    def test_missing_required_column_fails_instead_of_using_a_neighbor_cell(self):
        writer = campaign_database(self.root/'missing.db', 'extra-first')
        seed_campaign(writer)
        with writer.connection() as connection:
            connection.execute('ALTER TABLE campaigns DROP COLUMN metadata')
        reader = CampaignDatabase(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        for read in (lambda: reader.get_campaign(SOURCE['id']), reader.get_active_campaigns):
            with self.assertRaises(sqlite3.OperationalError): read()
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_other_connection_rows_counts_and_related_records_are_unchanged(self):
        writer = campaign_database(self.root/'related.db', 'reversed')
        seed_campaign(writer)
        writer.record_check(SOURCE['id'], 'stored status')
        writer.record_alert(SOURCE['id'], 'stored type', 'literal message')
        reader = CampaignDatabase(writer.db_path, read_only=True)
        self.assertEqual(reader.get_monitor_statistics(),
                         {'total_campaigns': 1, 'active_campaigns': 1, 'unacknowledged_alerts': 1})
        self.assertEqual(reader.get_recent_checks(SOURCE['id'])[0]['status'], 'stored status')
        self.assertEqual(reader.get_unacknowledged_alerts()[0]['message'], 'literal message')
        with reader.connection() as connection:
            self.assertIsInstance(connection.execute('SELECT 1').fetchone(), tuple)


if __name__ == '__main__':
    unittest.main()
