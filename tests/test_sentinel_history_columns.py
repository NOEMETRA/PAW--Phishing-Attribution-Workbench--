"""Actual stored check/alert columns stay bound to their named source cells."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase
from test_sentinel_campaign_columns import LAYOUTS


COLUMNS = {
    'checks': ('id', 'campaign_id', 'check_time', 'status', 'response_time', 'http_status',
               'content_hash', 'screenshot_path', 'error_message', 'metadata'),
    'alerts': ('id', 'campaign_id', 'alert_time', 'alert_type', 'severity', 'message',
               'metadata', 'acknowledged'),
}
SOURCES = {
    'checks': dict(zip(COLUMNS['checks'], (1, 'saved-campaign', '2026-01-01T01:00:00Z',
        'stored status', 0.0, 403, 'stored digest', 'stored Ω path', 'literal error', ' {"Ω": true} \n'))),
    'alerts': dict(zip(COLUMNS['alerts'], (1, 'saved-campaign', '2026-01-01T01:00:00Z',
        'stored type', 'supplied severity', 'literal Ω message', ' {"Ω": true} \n', 0))),
}


def history_database(path, layout):
    writer = CampaignDatabase(str(path))
    if layout == 'fresh': return writer
    with writer.connection() as connection:
        for table, columns in COLUMNS.items():
            definitions = {}
            for _, name, kind, required, default, primary in connection.execute('PRAGMA table_info('+table+')'):
                definition = '"'+name+'" '+kind
                if primary: definition += ' PRIMARY KEY AUTOINCREMENT'
                if required: definition += ' NOT NULL'
                if default is not None: definition += ' DEFAULT '+default
                definitions[name] = definition
            names = list(columns)
            if layout == 'reversed': names.reverse()
            elif layout == 'rotated': names = names[3:]+names[:3]
            elif layout == 'extra-first':
                names.insert(0, 'extension_note'); definitions['extension_note'] = 'extension_note BLOB'
            else: raise ValueError(layout)
            connection.execute('DROP TABLE '+table)
            connection.execute('CREATE TABLE '+table+' ('+', '.join(definitions[n] for n in names)
                +', FOREIGN KEY(campaign_id) REFERENCES campaigns(id))')
    return writer


def seed_history(writer, table, **overrides):
    row = dict(SOURCES[table], **overrides)
    columns = COLUMNS[table]
    with writer.connection() as connection:
        connection.execute('INSERT INTO '+table+' ('+', '.join(columns)+') VALUES ('
                           +', '.join('?' for _ in columns)+')', tuple(row[n] for n in columns))
    return row


def read_history(reader, table):
    return reader.get_recent_checks('saved-campaign') if table == 'checks' else reader.get_unacknowledged_alerts()


class SentinelHistoryColumns(unittest.TestCase):
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

    def test_every_field_matches_independent_named_sql_in_both_reader_modes(self):
        for layout in LAYOUTS:
            writer = history_database(self.root/(layout+'.db'), layout)
            reader = CampaignDatabase(writer.db_path, read_only=True)
            for table in COLUMNS: seed_history(writer, table)
            before = Path(writer.db_path).read_bytes()
            for table in COLUMNS:
                with self.subTest(layout=layout, table=table):
                    with closing(sqlite3.connect(writer.db_path)) as connection:
                        connection.row_factory = sqlite3.Row
                        named = dict(connection.execute('SELECT * FROM '+table).fetchone())
                    for source in (writer, reader):
                        record, = read_history(source, table)
                        self.assertEqual({n: record[n] for n in COLUMNS[table] if n != 'metadata'},
                                         {n: named[n] for n in COLUMNS[table] if n != 'metadata'})
                        self.assertEqual(record['metadata'], {'Ω': True})
                        self.assertEqual(record['json_evidence']['fields']['metadata']['raw_storage'],
                                         {'type': 'text', 'value': named['metadata']})
            self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_recent_check_campaign_filter_time_order_and_limits_are_retained(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                writer = history_database(self.root/(layout+'.db'), layout)
                for day in range(1, 13):
                    seed_history(writer, 'checks', id=day, check_time=f'2026-01-{day:02d}T00:00:00Z')
                seed_history(writer, 'checks', id=99, campaign_id='neighbor', check_time='2099-01-01')
                reader = CampaignDatabase(writer.db_path, read_only=True)
                self.assertEqual([r['id'] for r in reader.get_recent_checks('saved-campaign')], list(range(12, 2, -1)))
                self.assertEqual([r['id'] for r in reader.get_recent_checks('saved-campaign', 2)], [12, 11])
                self.assertEqual(reader.get_recent_checks('saved-campaign', 0), [])
                self.assertEqual(reader.get_recent_checks('missing'), [])

    def test_alert_filter_order_and_boolean_acknowledgment_are_retained(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                writer = history_database(self.root/(layout+'.db'), layout)
                seed_history(writer, 'alerts')
                seed_history(writer, 'alerts', id=2, acknowledged=1, alert_time='2099-01-01')
                seed_history(writer, 'alerts', id=3, campaign_id='neighbor', alert_time='2026-01-02')
                reader = CampaignDatabase(writer.db_path, read_only=True)
                rows = reader.get_unacknowledged_alerts()
                self.assertEqual([r['id'] for r in rows], [3, 1])
                self.assertTrue(all(r['acknowledged'] is False for r in rows))
                writer.acknowledge_alert(3)
                self.assertEqual([r['id'] for r in reader.get_unacknowledged_alerts()], [1])

    def test_metadata_source_and_decode_status_do_not_follow_another_column(self):
        for layout in LAYOUTS:
            writer = history_database(self.root/(layout+'.db'), layout)
            reader = CampaignDatabase(writer.db_path, read_only=True)
            for table in COLUMNS: seed_history(writer, table)
            for raw, status, kind in ((None, 'sql_null', 'null'), ('', 'empty', 'text'),
                    ('{broken', 'invalid_json', 'text'), ('NaN', 'non_finite_number', 'text'),
                    (b'{"stored":true}', 'decoded', 'blob')):
                for table in COLUMNS:
                    with self.subTest(layout=layout, table=table, raw=raw):
                        with writer.connection() as connection:
                            connection.execute('UPDATE '+table+' SET metadata=?', (raw,))
                        row, = read_history(reader, table)
                        evidence = row['json_evidence']['fields']['metadata']
                        self.assertEqual(evidence['status'], status)
                        self.assertEqual(evidence['raw_storage']['type'], kind)
                        if isinstance(raw, str) or raw is None:
                            self.assertEqual(evidence['raw_storage']['value'], raw)
                        self.assertFalse(evidence['verified'])

    def test_named_writers_and_acknowledgment_change_only_expected_rows(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                writer = history_database(self.root/(layout+'.db'), layout)
                campaign = writer.add_campaign('source-case', 'https://example.invalid/never-visit')
                writer.record_check(campaign, 'stored result', http_status=418, metadata={'check': True})
                writer.record_alert(campaign, 'stored type', 'literal message', metadata={'alert': True})
                check, = writer.get_recent_checks(campaign)
                self.assertEqual((check['campaign_id'], check['status'], check['http_status'], check['metadata']),
                                 (campaign, 'stored result', 418, {'check': True}))
                alert, = writer.get_unacknowledged_alerts()
                self.assertEqual((alert['campaign_id'], alert['message'], alert['metadata'], alert['acknowledged']),
                                 (campaign, 'literal message', {'alert': True}, False))
                writer.acknowledge_alert(alert['id'])
                self.assertEqual(writer.get_unacknowledged_alerts(), [])
                self.assertEqual(writer.get_recent_checks(campaign), [check])

    def test_missing_required_columns_fail_without_neighbor_substitution_or_writes(self):
        for table in COLUMNS:
            with self.subTest(table=table):
                writer = history_database(self.root/(table+'.db'), 'extra-first')
                seed_history(writer, table)
                with writer.connection() as connection:
                    connection.execute('ALTER TABLE '+table+' DROP COLUMN metadata')
                reader = CampaignDatabase(writer.db_path, read_only=True)
                before = Path(writer.db_path).read_bytes()
                with self.assertRaises(sqlite3.OperationalError): read_history(reader, table)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
