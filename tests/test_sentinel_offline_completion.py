"""Offline module contracts: real SQLite views, bounded consumers and mutations."""
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer


class SentinelOfflineCompletion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.path = self.root/'saved # Ω %.db'; self.db = CampaignDatabase(str(self.path))
        self.campaign = self.db.add_campaign('selected', 'literal')
        self.other = self.db.add_campaign('neighbor', 'literal neighbor')
        self.db.record_alert(self.campaign, 'supplied', 'message')
        self.db.record_check(self.campaign, 'supplied')
        self.victim = self.db.add_victim_intelligence('192.0.2.1', None, 'literal', case_id='selected')
        self.policy = offline_policy(); self.policy.__enter__(); self.blocked = len(violations())

    def tearDown(self):
        blocked = violations()[self.blocked:]; self.policy.__exit__(None, None, None)
        self.temp.cleanup(); self.assertEqual(blocked, [])

    def source(self): return {p.name: p.read_bytes() for p in self.root.iterdir()}

    def test_mutator_results_mean_one_actual_transition(self):
        self.assertFalse(self.db.update_campaign_status('missing', 'paused'))
        self.assertTrue(self.db.update_campaign_status(self.campaign, 'paused'))
        before = self.source()
        self.assertFalse(self.db.update_campaign_status(self.campaign, 'paused'))
        self.assertEqual(self.source(), before)
        self.assertFalse(self.db.acknowledge_alert(99999))
        self.assertTrue(self.db.acknowledge_alert(1))
        before = self.source()
        self.assertFalse(self.db.acknowledge_alert(1)); self.assertEqual(self.source(), before)
        self.assertEqual(self.db.get_campaign(self.other)['status'], 'active')

    def test_mutator_admission_precedes_database_access(self):
        operations = [lambda: self.db.update_campaign_status(True, 'paused'),
            lambda: self.db.update_campaign_status(self.campaign, ''),
            lambda: self.db.acknowledge_alert(True), lambda: self.db.acknowledge_alert('1'),
            lambda: self.db.cleanup_old_data(-1), lambda: self.db.cleanup_old_data(True),
            lambda: self.db.cleanup_old_data(1.5), lambda: self.db.cleanup_old_data(10**12)]
        for operation in operations:
            with self.subTest(operation=operation), patch.object(self.db, 'connection', side_effect=AssertionError('Early access')):
                with self.assertRaises(ValueError): operation()

    def test_mutation_postconditions_roll_back_reverted_or_ignored_updates(self):
        for table, trigger, operation in (
            ('campaigns', 'AFTER UPDATE OF status ON campaigns BEGIN UPDATE campaigns SET status=OLD.status WHERE id=NEW.id; END',
             lambda: self.db.update_campaign_status(self.campaign, 'paused')),
            ('alerts', 'AFTER UPDATE OF acknowledged ON alerts BEGIN UPDATE alerts SET acknowledged=OLD.acknowledged WHERE id=NEW.id; END',
             lambda: self.db.acknowledge_alert(1))):
            with self.subTest(table=table):
                with self.db.connection() as conn: conn.execute('CREATE TRIGGER reverted '+trigger)
                before = self.source()
                with self.assertRaises(RuntimeError): operation()
                self.assertEqual(self.source(), before)
                with self.db.connection() as conn: conn.execute('DROP TRIGGER reverted')

    def test_retention_interprets_only_aware_timestamps_and_reports_omissions(self):
        times = ('2026-10-01T00:00:00Z', '2026-10-23T01:00:00+02:00',
                 '2026-10-23T00:00:00-12:00', '2020-01-01', 'garbage',
                 '2026-10-23T00:00:00Z', '2026-10-23T00:00:00')
        with self.db.connection() as conn:
            conn.execute('DELETE FROM checks'); conn.execute('DELETE FROM alerts')
            for identifier, value in enumerate(times, 1):
                conn.execute('INSERT INTO checks(id,campaign_id,check_time,status) VALUES (?,?,?,?)',
                             (identifier, self.campaign, value, 'supplied'))
                conn.execute('INSERT INTO alerts(id,campaign_id,alert_time,alert_type,message) VALUES (?,?,?,?,?)',
                             (identifier, self.campaign, value, 'supplied', 'literal'))
        with patch('paw.sentinel.database.utc_now_iso', return_value='2026-10-23T00:00:00Z'):
            result = self.db.cleanup_old_data(0)
        self.assertEqual(result['deleted'], {'checks': 2, 'alerts': 2})
        self.assertEqual(result['retained_uninterpretable'], {'checks': [4,5,7], 'alerts': [4,5,7]})
        with closing(sqlite3.connect(self.path)) as conn:
            for table in ('checks','alerts'):
                self.assertEqual(conn.execute('SELECT id FROM '+table+' ORDER BY id').fetchall(), [(3,),(4,),(5,),(6,),(7,)])
        self.assertTrue(result['complete']); self.assertEqual(result['cutoff_utc'], '2026-10-23T00:00:00Z')

    def test_failed_retention_rolls_back_both_tables(self):
        with self.db.connection() as conn:
            conn.execute("UPDATE checks SET check_time='2000-01-01T00:00:00Z'")
            conn.execute("UPDATE alerts SET alert_time='2000-01-01T00:00:00Z'")
            conn.execute("CREATE TRIGGER failed BEFORE DELETE ON alerts BEGIN SELECT RAISE(ABORT,'declared fault'); END")
        before = self.source()
        with self.assertRaises(sqlite3.IntegrityError): self.db.cleanup_old_data(1)
        self.assertEqual(self.source(), before)

    def test_ignored_retention_cannot_return_a_successful_partial_cleanup(self):
        with self.db.connection() as conn:
            conn.execute("UPDATE checks SET check_time='2000-01-01T00:00:00Z'")
            conn.execute("CREATE TRIGGER ignored BEFORE DELETE ON checks BEGIN SELECT RAISE(IGNORE); END")
        before = self.source()
        with self.assertRaises(RuntimeError): self.db.cleanup_old_data(1)
        self.assertEqual(self.source(), before)

    def test_read_limits_are_validated_before_opening_sqlite(self):
        for limits in ({'max_rows':0}, {'max_rows':True}, {'unknown':1}, [], {'max_output_bytes':-1}):
            with self.subTest(limits=limits), patch('paw.sentinel.database.sqlite3.connect', side_effect=AssertionError('SQLite opened')):
                with self.assertRaises(ValueError): CampaignDatabase(str(self.path), read_only=True, limits=limits)

    def test_read_only_mode_and_campaign_selectors_reject_implicit_aliases_before_io(self):
        for value in (None,0,1,'false',[]):
            with self.subTest(mode=value), patch('paw.sentinel.database.sqlite3.connect',side_effect=AssertionError('Early SQLite access')):
                with self.assertRaises(ValueError): CampaignDatabase(str(self.path),read_only=value)
        with self.db.connection() as conn:
            conn.execute("INSERT INTO campaigns(id,case_id,created_at,url) VALUES ('1','legacy','literal','literal')")
        for value in (True,1,1.0,None):
            for operation in (lambda:self.db.get_campaign(value),lambda:self.db.remove_campaign(value),
                              lambda:self.db.get_recent_checks(value)):
                with patch.object(self.db,'connection',side_effect=AssertionError('Early database access')):
                    with self.assertRaises(ValueError): operation()
        self.assertEqual(self.db.get_campaign('1')['case_id'],'legacy')

    def test_selected_row_budget_fails_whole_read_without_affecting_other_selections(self):
        self.db.add_victim_intelligence('192.0.2.2', None, 'literal', case_id='selected')
        self.db.add_victim_intelligence('192.0.2.3', None, 'literal', case_id='neighbor')
        before = self.source()
        reader = CampaignDatabase(str(self.path), read_only=True, limits={'max_rows':1})
        with self.assertRaises(ValueError): reader.get_forensic_victim_intelligence('selected')
        self.assertEqual(len(reader.get_forensic_victim_intelligence('neighbor')),1)
        self.assertEqual(reader.get_forensic_victim_intelligence('absent'),[])
        self.assertEqual(self.source(), before)

    def test_row_and_total_payload_budgets_fail_without_partial_decoding(self):
        with self.db.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET metadata=?', (json.dumps({'raw':'x'*2000}),))
        before = self.source()
        for limits, error in (({'max_row_bytes':512}, sqlite3.DataError),
                              ({'max_result_bytes':512}, ValueError)):
            with self.subTest(limits=limits):
                with self.assertRaises(error):
                    reader = CampaignDatabase(str(self.path), read_only=True, limits=limits)
                    reader.get_forensic_victim_intelligence()
        self.assertEqual(self.source(),before)

    def test_sql_work_budget_interrupts_an_actual_expensive_statement(self):
        reader = CampaignDatabase(str(self.path), read_only=True, limits={'max_sql_steps':1000})
        with reader.connection() as conn:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT sum(x) FROM n').fetchone()

    def test_legacy_json_depth_limit_preserves_raw_source_and_explicit_status(self):
        raw = '['*70+'0'+']'*70
        with self.db.connection() as conn: conn.execute('UPDATE victim_intelligence SET metadata=?',(raw,))
        before = self.source(); row = self.db.get_forensic_victim_intelligence()[0]
        evidence = row['json_evidence']['fields']['metadata']
        self.assertEqual(evidence['status'],'resource_limit')
        self.assertEqual(evidence['raw_storage'],{'type':'text','value':raw})
        self.assertTrue(evidence['default_applied']); self.assertFalse(evidence['verified'])
        self.assertEqual(self.source(),before)

    def test_read_connection_keeps_one_sqlite_snapshot_until_exit(self):
        reader = CampaignDatabase(str(self.path),read_only=True)
        with reader.connection() as conn:
            first = conn.execute('SELECT status FROM campaigns WHERE id=?',(self.campaign,)).fetchone()
            with closing(sqlite3.connect(self.path,timeout=0.05)) as writer:
                with self.assertRaises(sqlite3.OperationalError):
                    with writer: writer.execute("UPDATE campaigns SET status='changed' WHERE id=?",(self.campaign,))
            self.assertEqual(conn.execute('SELECT status FROM campaigns WHERE id=?',(self.campaign,)).fetchone(),first)
        self.assertEqual(reader.get_campaign(self.campaign)['status'],'active')

    def test_literal_empty_ip_and_explicit_identifiers_do_not_expand_selection(self):
        self.assertEqual(self.db.get_victim_intelligence(victim_ip=''),[])
        self.assertEqual(self.db.get_victim_intelligence(victim_id=0),[])
        for operation in (lambda:self.db.get_victim_intelligence(victim_id=True),
                          lambda:self.db.get_victim_intelligence(victim_id=1,victim_ip='192.0.2.1'),
                          lambda:self.db.get_recent_checks(self.campaign,-1),
                          lambda:self.db.get_unanalyzed_victims(True)):
            with self.assertRaises(ValueError): operation()

    def test_all_passive_report_consumers_apply_output_budget(self):
        self.db.update_victim_analysis(self.victim, interaction_type='potential_attacker', interaction_confidence=0.8)
        analyzer = IntelligenceAnalyzer(str(self.path),read_only=True,limits={'max_output_bytes':100})
        before = self.source()
        for method in (analyzer.generate_intelligence_report, analyzer.export_forensic_data,
                       analyzer.get_interaction_statistics, analyzer.get_potential_attacker_interactions,
                       analyzer.get_geographic_statistics, analyzer.db.get_victim_statistics):
            with self.subTest(method=method):
                with self.assertRaises(ValueError): method()
        self.assertEqual(self.source(),before)

    def test_json_byte_and_shared_node_budgets_preserve_sources_and_reset_per_read(self):
        with self.db.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET geolocation_data=?,whois_data=?,metadata=?',
                         ('{"country":"x"}','{"raw":"y"}','{"more":[1,2,3]}'))
        before=self.source()
        reader=CampaignDatabase(str(self.path),read_only=True,limits={'max_json_nodes':5})
        fields=reader.get_forensic_victim_intelligence()[0]['json_evidence']['fields']
        self.assertEqual(fields['geolocation_data']['status'],'decoded')
        self.assertEqual(fields['whois_data']['status'],'resource_limit')
        self.assertEqual(fields['metadata']['raw_storage']['value'],'{"more":[1,2,3]}')
        self.assertEqual(fields['metadata']['status'],'resource_limit')
        self.assertEqual(reader._decode_json_field('{}',{})[1]['status'],'decoded')
        tiny=CampaignDatabase(str(self.path),read_only=True,limits={'max_json_bytes':1})
        self.assertEqual(tiny.get_forensic_victim_intelligence()[0]['json_evidence']['fields']['metadata']['status'],'resource_limit')
        self.assertEqual(self.source(),before)

    def test_parallel_readers_have_independent_json_budgets(self):
        reader=CampaignDatabase(str(self.path),read_only=True,limits={'max_json_nodes':1})
        original=reader._decode_json_field; barrier=threading.Barrier(2)
        def together(raw,default):
            if raw=='{}': barrier.wait(timeout=10)
            return original(raw,default)
        with patch.object(reader,'_decode_json_field',together), ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(reader.get_forensic_victim_intelligence) for _ in range(2)]
            rows=[future.result(timeout=15)[0] for future in futures]
        self.assertEqual([row['json_evidence']['fields']['metadata']['status'] for row in rows],['decoded','decoded'])

    def test_resource_profile_is_immutable_and_admits_exact_empty_list_output(self):
        reader=CampaignDatabase(str(self.path),read_only=True,limits={'max_rows':1})
        with self.assertRaises(TypeError): reader.limits['max_rows']=100
        analyzer=IntelligenceAnalyzer(str(self.path),read_only=True,limits={'max_output_bytes':2})
        self.assertEqual(analyzer.get_potential_attacker_interactions(),[])

    def test_stored_history_ties_use_id_to_keep_newest_insertions_first(self):
        with patch('paw.sentinel.database.utc_now_iso',return_value='2099-01-01T00:00:00Z'):
            for _ in range(2):
                self.db.record_check(self.campaign,'stored')
                self.db.record_alert(self.campaign,'stored','message')
                self.db.add_victim_intelligence('192.0.2.2',None,'literal')
        self.assertEqual([row['id'] for row in self.db.get_recent_checks(self.campaign,2)],[3,2])
        self.assertEqual([row['id'] for row in self.db.get_unacknowledged_alerts()[:2]],[3,2])
        self.assertEqual([row['id'] for row in self.db.get_victim_intelligence()[:2]],[3,2])
        self.assertEqual([row['id'] for row in self.db.get_victim_intelligence(victim_ip='192.0.2.2')],[3,2])
        self.assertEqual([row['id'] for row in self.db.get_unanalyzed_victims(2)],[3,2])

    def test_country_selection_cannot_mask_resource_refusal_as_no_matches(self):
        with self.db.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET geolocation_data=?',('{"country":"US"}',))
        before=self.source()
        reader=CampaignDatabase(str(self.path),read_only=True,limits={'max_json_nodes':1})
        with self.assertRaises(ValueError): reader.get_victims_by_country('US')
        self.assertEqual(self.source(),before)


if __name__ == '__main__': unittest.main()
