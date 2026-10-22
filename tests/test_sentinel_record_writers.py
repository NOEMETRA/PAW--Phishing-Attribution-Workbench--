"""Actual SQLite JSON writer admission and acknowledged row effects; no collection."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase


class SentinelRecordWriters(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root/'saved # Ω %.db'
        self.db = CampaignDatabase(str(self.path))
        self.campaign = self.db.add_campaign('selected', 'https://example.invalid/stored')
        self.victim = self.db.add_victim_intelligence('192.0.2.1', None, 'literal URL', case_id='selected')
        self.policy = offline_policy(); self.policy.__enter__()
        self.blocked = len(violations())

    def tearDown(self):
        blocked = violations()[self.blocked:]
        self.policy.__exit__(None, None, None)
        self.temp.cleanup()
        self.assertEqual(blocked, [])

    def source(self):
        return {p.name: p.read_bytes() for p in self.root.iterdir()}

    def metadata_writers(self, metadata):
        return {
            'campaigns': lambda: self.db.add_campaign('new', 'literal', metadata),
            'checks': lambda: self.db.record_check(self.campaign, 'literal status', metadata=metadata),
            'alerts': lambda: self.db.record_alert(self.campaign, 'literal type', 'literal message', metadata=metadata),
            'victim_intelligence': lambda: self.db.add_victim_intelligence('192.0.2.2', 'UA', 'literal', metadata=metadata)}

    def rejected_before_connection(self, operation):
        before = self.source()
        with patch.object(self.db, 'connection', side_effect=AssertionError('Database accessed before admission')):
            with self.assertRaises((ValueError, TypeError)):
                operation()
        self.assertEqual(self.source(), before)

    def test_all_metadata_writers_reject_falsy_wrong_shapes_before_storage(self):
        for value in (False, 0, '', [], (), 'stored text'):
            for name, operation in self.metadata_writers(value).items():
                with self.subTest(writer=name, value=repr(value)):
                    self.rejected_before_connection(operation)

    def test_all_metadata_writers_reject_lossy_or_nonfinite_nested_values(self):
        cycle = {}; cycle['cycle'] = cycle
        for value in ({'n': float('nan')}, {'n': float('inf')}, {1: 'number', '1': 'text'},
                      {'nested': {None: 'key'}}, {'tuple': (1, 2)}, {'bytes': b'raw'}, cycle):
            for name, operation in self.metadata_writers(value).items():
                with self.subTest(writer=name, value=repr(value)):
                    self.rejected_before_connection(operation)

    def test_all_metadata_writers_apply_encoded_byte_depth_and_node_limits(self):
        deep = {}; node = deep
        for _ in range(65): node['next'] = {}; node = node['next']
        for value in ({'text': 'Ω' * (1024**2//6)}, deep, {'items': [None]*100_001}):
            for name, operation in self.metadata_writers(value).items():
                with self.subTest(writer=name, kind=type(value).__name__):
                    self.rejected_before_connection(operation)

    def test_metadata_round_trips_without_coercion_and_none_alone_means_empty_object(self):
        payload = {'Ω': [False, 0, '', None, {'claim': 'unverified', 'n': 1.25}]}
        for metadata in (None, {}, payload):
            # Avoid a duplicate case while exercising the same four writer APIs.
            with self.db.connection() as conn: conn.execute("DELETE FROM campaigns WHERE case_id='new'")
            for operation in self.metadata_writers(metadata).values(): operation()
            with closing(sqlite3.connect(self.path)) as conn:
                for table in ('campaigns', 'checks', 'alerts', 'victim_intelligence'):
                    raw, = conn.execute(f'SELECT metadata FROM {table} ORDER BY rowid DESC LIMIT 1').fetchone()
                    self.assertEqual(json.loads(raw), {} if metadata is None else metadata)
            row = self.db.get_recent_checks(self.campaign)[0]
            self.assertEqual(row['json_evidence']['fields']['metadata']['status'], 'decoded')
            self.assertFalse(row['json_evidence']['fields']['metadata']['verified'])

    def test_analysis_json_fields_reject_wrong_shapes_before_storage(self):
        for field in ('geolocation_data', 'whois_data', 'attacker_correlation'):
            for value in (False, 0, '', [], 'text'):
                with self.subTest(field=field, value=value):
                    self.rejected_before_connection(lambda: self.db.update_victim_analysis(self.victim, **{field: value}))
        for field in ('related_ips', 'interaction_indicators'):
            for value in ({}, '', (), [1], [None], [['nested']]):
                with self.subTest(field=field, value=value):
                    self.rejected_before_connection(lambda: self.db.update_victim_analysis(self.victim, **{field: value}))

    def test_analysis_json_fields_share_strict_serialization_and_limits(self):
        for field in ('geolocation_data', 'whois_data', 'attacker_correlation'):
            for value in ({'n': float('-inf')}, {False: 'coerced'}, {'tuple': ()}, {'text': 'x'*(1024**2)}):
                with self.subTest(field=field):
                    self.rejected_before_connection(lambda: self.db.update_victim_analysis(self.victim, **{field: value}))
        for field in ('related_ips', 'interaction_indicators'):
            self.rejected_before_connection(lambda: self.db.update_victim_analysis(self.victim, **{field: ['Ω'*(1024**2//6+1)]}))

    def test_analysis_none_is_noop_but_empty_values_and_zero_are_persisted(self):
        before = self.source()
        self.assertFalse(self.db.update_victim_analysis(self.victim))
        self.assertEqual(self.source(), before)
        values = dict(geolocation_data={}, whois_data={}, attacker_correlation={}, related_ips=[],
                      interaction_indicators=[], risk_score=0, interaction_confidence=0.0,
                      analyzed_status='literal status', interaction_type='literal label')
        self.assertTrue(self.db.update_victim_analysis(self.victim, **values))
        row = self.db.get_victim_intelligence(victim_id=self.victim)[0]
        self.assertEqual({name: row[name] for name in values}, values)
        for evidence in row['json_evidence']['fields'].values(): self.assertFalse(evidence['verified'])

    def test_analysis_missing_row_returns_false_without_timestamp_or_storage_changes(self):
        before = self.source()
        self.assertFalse(self.db.update_victim_analysis(98765, geolocation_data={'source': 'supplied'}))
        self.assertEqual(self.source(), before)

    def test_analysis_identifier_admission_prevents_bool_float_and_text_aliases(self):
        for identifier in (True, False, 1.0, str(self.victim), None, 0, -1):
            with self.subTest(identifier=identifier):
                self.rejected_before_connection(lambda: self.db.update_victim_analysis(identifier, risk_score=0))

    def test_scalar_admission_prevents_nan_null_and_infinite_stored_values(self):
        for field in ('risk_score', 'interaction_confidence'):
            for value in (float('nan'), float('inf'), True, '0'):
                with self.subTest(field=field, value=value):
                    self.rejected_before_connection(lambda: self.db.update_victim_analysis(self.victim, **{field: value}))
        for value in (float('nan'), float('inf'), -1, True, '1'):
            self.rejected_before_connection(lambda: self.db.record_check(self.campaign, 'stored', response_time=value))
        for value in (True, 200.0, '200', 99, 600):
            self.rejected_before_connection(lambda: self.db.record_check(self.campaign, 'stored', http_status=value))

    def test_missing_parent_cannot_acquire_orphan_check_or_alert(self):
        for operation in (lambda: self.db.record_check('absent', 'stored'),
                          lambda: self.db.record_alert('absent', 'stored', 'message')):
            before = self.source()
            with self.assertRaises(ValueError): operation()
            self.assertEqual(self.source(), before)

    def test_check_and_campaign_use_one_persisted_timestamp(self):
        with patch('paw.sentinel.database.utc_now_iso', side_effect=['first timestamp', 'second timestamp']):
            self.db.record_check(self.campaign, 'literal', metadata={'unverified': True})
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(conn.execute('SELECT last_check FROM campaigns WHERE id=?', (self.campaign,)).fetchone(),
                             conn.execute('SELECT check_time FROM checks').fetchone())

    def test_alert_insert_cannot_commit_after_its_parent_disappears(self):
        with self.db.connection() as conn:
            conn.execute('CREATE TRIGGER removed AFTER INSERT ON alerts BEGIN DELETE FROM campaigns WHERE id=NEW.campaign_id; END')
        before = self.source()
        with self.assertRaises(ValueError): self.db.record_alert(self.campaign, 'literal', 'message')
        self.assertEqual(self.source(), before)

    def test_check_parent_update_failure_rolls_back_insert(self):
        with self.db.connection() as conn:
            conn.execute("CREATE TRIGGER fail_check BEFORE UPDATE OF last_check ON campaigns BEGIN SELECT RAISE(ABORT,'declared failure'); END")
        before = self.source()
        with self.assertRaises(sqlite3.IntegrityError): self.db.record_check(self.campaign, 'stored')
        self.assertEqual(self.source(), before)

    def test_parent_trigger_cannot_erase_or_rewrite_an_acknowledged_check(self):
        for statement in ('DELETE FROM checks', "UPDATE checks SET metadata='{}'"):
            with self.subTest(statement=statement):
                with self.db.connection() as conn:
                    conn.execute(f'CREATE TRIGGER altered AFTER UPDATE OF last_check ON campaigns BEGIN {statement}; END')
                before = self.source()
                with self.assertRaises(RuntimeError): self.db.record_check(self.campaign, 'stored', metadata={'source': 'literal'})
                self.assertEqual(self.source(), before)
                with self.db.connection() as conn: conn.execute('DROP TRIGGER altered')

    def test_ignored_or_reverted_parent_timestamp_rolls_back_check(self):
        triggers = ('BEFORE UPDATE OF last_check ON campaigns BEGIN SELECT RAISE(IGNORE); END',
                    'AFTER UPDATE OF last_check ON campaigns BEGIN UPDATE campaigns SET last_check=OLD.last_check WHERE id=NEW.id; END')
        for trigger in triggers:
            with self.subTest(trigger=trigger):
                with self.db.connection() as conn: conn.execute('CREATE TRIGGER altered '+trigger)
                before = self.source()
                with self.assertRaises(RuntimeError): self.db.record_check(self.campaign, 'stored')
                self.assertEqual(self.source(), before)
                with self.db.connection() as conn: conn.execute('DROP TRIGGER altered')

    def test_exact_encoded_byte_boundary_is_admitted_but_next_character_is_not(self):
        value = ['Ω'*(1024**2//6)]
        self.assertEqual(len(json.dumps(value).encode('ascii')), 1024**2)
        self.assertTrue(self.db.update_victim_analysis(self.victim, related_ips=value))
        self.rejected_before_connection(lambda: self.db.update_victim_analysis(self.victim, related_ips=[value[0]+'x']))

    def test_duplicate_analysis_ids_fail_without_changing_either_row(self):
        with self.db.connection() as conn:
            conn.execute('ALTER TABLE victim_intelligence RENAME TO saved_original')
            conn.execute('CREATE TABLE victim_intelligence AS SELECT * FROM saved_original')
            conn.execute('INSERT INTO victim_intelligence SELECT * FROM saved_original')
        before = self.source()
        with self.assertRaises(RuntimeError): self.db.update_victim_analysis(self.victim, risk_score=7)
        self.assertEqual(self.source(), before)

    def test_literal_fields_reject_native_scalar_coercion_before_storage(self):
        operations = [lambda: self.db.record_check(True, 'stored'),
            lambda: self.db.record_check(self.campaign, 0),
            lambda: self.db.record_alert(self.campaign, 'stored', 42),
            lambda: self.db.record_alert(self.campaign, 'stored', 'text', severity=False),
            lambda: self.db.add_victim_intelligence(123, 'UA', 'literal'),
            lambda: self.db.add_victim_intelligence('192.0.2.1', b'UA', 'literal'),
            lambda: self.db.add_victim_intelligence('192.0.2.1', None, 'literal', case_id=False),
            lambda: self.db.update_victim_analysis(self.victim, analyzed_status=1),
            lambda: self.db.update_victim_analysis(self.victim, interaction_type=False),
            lambda: self.db.update_victim_analysis(self.victim, interaction_confidence=-0.1),
            lambda: self.db.update_victim_analysis(self.victim, interaction_confidence=1.1)]
        for operation in operations: self.rejected_before_connection(operation)

    def test_ignored_inserts_cannot_be_acknowledged_as_recorded(self):
        for table in self.metadata_writers({}):
            with self.subTest(table=table):
                with self.db.connection() as conn:
                    conn.execute(f'CREATE TRIGGER ignored BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END')
                before = self.source()
                with self.assertRaises(RuntimeError): self.metadata_writers({})[table]()
                self.assertEqual(self.source(), before)
                with self.db.connection() as conn: conn.execute('DROP TRIGGER ignored')

    def test_altered_insert_values_fail_and_roll_back_the_transaction(self):
        for table in self.metadata_writers({}):
            with self.subTest(table=table):
                with self.db.connection() as conn:
                    conn.execute(f"CREATE TRIGGER altered AFTER INSERT ON {table} BEGIN UPDATE {table} SET metadata='{{\"changed\":true}}' WHERE rowid=NEW.rowid; END")
                before = self.source()
                with self.assertRaises(RuntimeError): self.metadata_writers({'selected': True})[table]()
                self.assertEqual(self.source(), before)
                with self.db.connection() as conn: conn.execute('DROP TRIGGER altered')

    def test_ignored_analysis_update_returns_false_and_preserves_prior_rows(self):
        with self.db.connection() as conn:
            conn.execute("CREATE TRIGGER ignored BEFORE UPDATE OF risk_score ON victim_intelligence BEGIN UPDATE victim_intelligence SET metadata='{\"side_effect\":true}' WHERE id=NEW.id; SELECT RAISE(IGNORE); END")
        before = self.source()
        self.assertFalse(self.db.update_victim_analysis(self.victim, risk_score=7))
        self.assertEqual(self.source(), before)

    def test_reverted_analysis_update_cannot_report_success(self):
        with self.db.connection() as conn:
            conn.execute('CREATE TRIGGER reverted AFTER UPDATE OF risk_score ON victim_intelligence BEGIN UPDATE victim_intelligence SET risk_score=OLD.risk_score WHERE id=NEW.id; END')
        before = self.source()
        with self.assertRaises(RuntimeError): self.db.update_victim_analysis(self.victim, risk_score=7)
        self.assertEqual(self.source(), before)

    def test_read_only_writer_operations_still_fail_without_source_changes(self):
        self.db = CampaignDatabase(str(self.path), read_only=True)
        operations = list(self.metadata_writers({'source': 'literal'}).values())
        operations.append(lambda: self.db.update_victim_analysis(self.victim, geolocation_data={}))
        before = self.source()
        for operation in operations:
            with self.assertRaises(sqlite3.OperationalError): operation()
        self.assertEqual(self.source(), before)


if __name__ == '__main__': unittest.main()
