"""Sentinel lifecycle, atomic observations and unavailable inference boundaries."""
import inspect
from contextlib import contextmanager
import json
import os
import sys
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy
from paw.sentinel.config import SentinelConfig
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.ip_analyzer import IPAnalyzer
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
from paw.sentinel.monitor import SentinelMonitor


class SentinelModuleAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.config = SentinelConfig(str(self.root/'missing.json'))
        self.db = CampaignDatabase(str(self.root/'saved.db'))
        self.campaign = self.db.add_campaign('case-owned','http://127.0.0.1:9/owned')
        self.monitor = SentinelMonitor(self.config,self.db)

    def tearDown(self): self.temp.cleanup()

    def result(self, status='up', code=200, digest='a'*64):
        return {'campaign_id':self.campaign,'url':'http://127.0.0.1:9/owned',
            'status':status,'http_status':code,'content_hash':digest,'metadata':{'declared_fixture':True}}

    def test_internal_active_paths_refuse_before_argument_access(self):
        with offline_policy():
            with self.assertRaises(RuntimeError):
                with self.monitor._publication_commit(): pass
            for name in ('_monitor_loop','_handle_check_result','_check_for_alerts','_trigger_alert'):
                method = getattr(self.monitor,name)
                kwargs = {key:object() for key,p in inspect.signature(method).parameters.items()
                          if p.default is inspect.Parameter.empty}
                with self.subTest(name=name),self.assertRaises(RuntimeError): method(**kwargs)
        self.assertEqual(self.db.get_recent_checks(self.campaign),[])

    def test_stop_interrupts_interval_and_confirms_thread_shutdown(self):
        self.assertIn('timeout',inspect.signature(self.monitor.stop).parameters)
        self.config._config['monitoring']['check_interval_minutes'] = 525600
        checked = threading.Event()
        with patch.object(self.monitor,'_perform_checks',side_effect=checked.set):
            try:
                self.monitor.start(); self.assertTrue(checked.wait(2))
                self.assertTrue(self.monitor.stop(timeout=2))
                self.assertFalse(self.monitor.is_running())
                self.assertFalse(self.monitor._thread.is_alive())
            finally: self.monitor.stop(timeout=2)

    def test_transitions_compare_prior_row_and_dispatch_registered_events(self):
        down,up,changed = [],[],[]
        self.monitor.on_campaign_down(down.append); self.monitor.on_campaign_up(up.append)
        self.monitor.on_content_changed(changed.append)
        self.config._config['alerts']['alert_on_up'] = True
        self.monitor._handle_check_result(self.result())
        self.monitor._handle_check_result(self.result('down',503,'b'*64))
        self.monitor._handle_check_result(self.result('up',200,'b'*64))
        self.assertEqual((len(down),len(up),len(changed)),(1,1,1))
        self.assertEqual(len(self.db.get_unacknowledged_alerts()),3)

    def test_transport_failure_is_not_a_down_transition(self):
        self.monitor._handle_check_result(self.result())
        self.monitor._handle_check_result(self.result('error',None,None))
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_alert_disable_and_callback_copies_preserve_observation(self):
        self.config._config['alerts']['enabled'] = False
        second = []
        def mutate(value): value['metadata']['declared_fixture'] = 'changed by callback'
        self.monitor.on_check_complete(mutate); self.monitor.on_check_complete(second.append)
        original = self.result(); self.monitor._handle_check_result(original)
        self.monitor._handle_check_result(self.result('down',503,'b'*64))
        self.assertEqual(second[0]['metadata']['declared_fixture'],True)
        self.assertEqual(original['metadata']['declared_fixture'],True)
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_invalid_runtime_configuration_is_rejected_without_publication(self):
        for key,value in (('monitoring.max_concurrent_checks',True),('monitoring.max_concurrent_checks',0),
                          ('monitoring.timeout_seconds',-1),('monitoring.check_interval_minutes',0),
                          ('analysis.enable_screenshots','false'),('alerts.enabled',1)):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError): self.config.set(key,value)
        self.assertFalse((self.root/'missing.json').exists())

    def test_unvalidated_risk_and_automatic_publication_are_unavailable(self):
        analyzer = IntelligenceAnalyzer(str(self.root/'saved.db'))
        for operation in (lambda:self.db.calculate_risk_score([],{},{}),
                          lambda:IPAnalyzer().analyze_risk_indicators({}),
                          lambda:analyzer.analyze_unanalyzed_victims(),
                          lambda:analyzer._update_attacker_correlations()):
            with self.subTest(operation=operation),self.assertRaises(NotImplementedError): operation()
        classification = analyzer.classify_interaction_type({})
        self.assertEqual(classification['type'],'unknown')
        self.assertIsNone(classification['confidence'])

    def test_screenshot_boundary_does_not_launch_unisolated_browser(self):
        armed = [False]
        def refuse_effects(event,args):
            if not armed[0]: return
            write = (event=='open' and (any(c in (args[1] or '') for c in 'wax+') or
                     bool(args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))))
            if (write or event.startswith('socket.') or event in ('subprocess.Popen','_winapi.CreateProcess',
                    'os.system','os.posix_spawn','os.spawn','os.mkdir','os.remove','os.rename')):
                raise AssertionError('Unsupported screenshot attempted '+event)
        sys.addaudithook(refuse_effects); armed[0] = True
        try:
            self.assertIn('NotImplementedError',inspect.getsource(self.monitor._take_screenshot))
            with self.assertRaises(NotImplementedError): self.monitor._take_screenshot(object(),object())
        finally: armed[0] = False

    def test_ip_prefix_groups_are_descriptive_not_attacker_ranges(self):
        ip = IPAnalyzer()
        info = ip.get_network_info('2001:db8:1::1')
        self.assertEqual(info['network'],'2001:db8:1::/64')
        self.assertFalse(info['verified'])
        result = ip.correlate_ips(['192.0.2.1']*3)
        self.assertEqual(result['potential_attacker_ranges'],[])
        self.assertEqual(result['common_networks'],{})

    def test_ip_admission_precedes_provider_and_thread_access(self):
        ip = IPAnalyzer()
        with patch.object(ip,'reverse_dns_lookup',side_effect=AssertionError('early network')):
            for value in (True,123,'192.0.2.1/24','192.0.2.1/path','fe80::1%interface'):
                with self.subTest(value=value),self.assertRaises(ValueError): ip.analyze_ip(value)
        for value in (True,0,10000):
            with self.subTest(workers=value),self.assertRaises(ValueError): ip.batch_analyze_ips([],value)

    def test_alert_write_failure_rolls_back_check_parent_and_callbacks(self):
        self.monitor._handle_check_result(self.result())
        before = self.db.get_campaign(self.campaign)
        published = []; self.monitor.on_check_complete(published.append)
        with self.db.connection() as conn:
            conn.execute("CREATE TRIGGER reject_alert BEFORE INSERT ON alerts BEGIN SELECT RAISE(IGNORE); END")
            conn.commit()
        with self.assertRaises(RuntimeError):
            self.monitor._handle_check_result(self.result('down',503,'b'*64))
        self.assertEqual(self.db.get_campaign(self.campaign),before)
        self.assertEqual(len(self.db.get_recent_checks(self.campaign)),1)
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])
        self.assertEqual(published,[])

    def test_removed_campaign_cannot_receive_collected_result(self):
        result = self.result(); self.db.remove_campaign(self.campaign)
        with self.assertRaises(RuntimeError): self.monitor._handle_check_result(result)
        self.assertEqual(self.db.get_recent_checks(self.campaign),[])

    def test_callbacks_run_after_commit_and_errors_do_not_undo_source(self):
        observed = []
        def inspect_commit(value):
            with self.db.connection() as conn:
                observed.append(conn.execute('SELECT id FROM checks').fetchall())
                conn.execute("UPDATE campaigns SET case_id='callback-observed-commit' WHERE id=?",(self.campaign,))
                conn.commit()
            raise ValueError('Declared callback failure')
        self.monitor.on_check_complete(inspect_commit)
        self.monitor._handle_check_result(self.result())
        self.assertEqual(len(observed[0]),1)
        self.assertEqual(self.db.get_campaign(self.campaign)['case_id'],'callback-observed-commit')
        self.assertEqual(self.monitor.get_runtime_state()['callback_errors'][0]['error'],'ValueError')

    def test_unknown_prior_status_does_not_invent_transition(self):
        self.db.record_check(self.campaign,'up',http_status=None,content_hash='a'*64)
        self.monitor._handle_check_result(self.result('down',503,'a'*64))
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_arbitrary_stored_timestamp_cannot_pin_prior_observation(self):
        self.monitor._handle_check_result(self.result('down',503,'a'*64))
        with self.db.connection() as conn:
            conn.execute("UPDATE checks SET check_time='9999-unverified-timestamp'"); conn.commit()
        self.monitor._handle_check_result(self.result('up',200,'a'*64))
        self.monitor._handle_check_result(self.result('down',503,'a'*64))
        self.assertEqual([row['alert_type'] for row in self.db.get_unacknowledged_alerts()],['down'])

    def test_parent_change_during_insert_rolls_back_complete_monitor_transaction(self):
        with self.db.connection() as conn:
            conn.execute("CREATE TRIGGER change_parent AFTER INSERT ON checks BEGIN UPDATE campaigns SET url='changed' WHERE id=NEW.campaign_id; END")
            conn.commit()
        with self.assertRaises(RuntimeError): self.monitor._handle_check_result(self.result())
        self.assertEqual(self.db.get_recent_checks(self.campaign),[])
        self.assertEqual(self.db.get_campaign(self.campaign)['url'],self.result()['url'])

    def test_legacy_digest_without_source_contract_does_not_invent_content_change(self):
        self.db.record_check(self.campaign,'up',http_status=200,content_hash='a'*64)
        self.monitor._handle_check_result(self.result('down',503,'b'*64))
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_changed_campaign_url_resets_comparison_without_rewriting_history(self):
        self.monitor._handle_check_result(self.result())
        with self.db.connection() as conn:
            conn.execute("UPDATE campaigns SET url='http://127.0.0.1:9/new' WHERE id=?",(self.campaign,)); conn.commit()
        result = self.result('down',503,'b'*64); result['url'] = 'http://127.0.0.1:9/new'
        self.monitor._handle_check_result(result)
        self.assertEqual(len(self.db.get_recent_checks(self.campaign)),2)
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_changed_digest_representation_is_not_comparable_content(self):
        self.monitor._handle_check_result(self.result())
        result = self.result(digest='b'*64)
        result['metadata']['http_observation'] = {'body_representation':'HTTP entity bytes, without content decoding'}
        self.monitor._handle_check_result(result)
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_correlation_text_echo_and_ranges_are_bounded_before_result(self):
        analyzer = IPAnalyzer()
        with self.assertRaises(ValueError): analyzer.correlate_ips(['x'*129])
        with self.assertRaises(ValueError): analyzer.correlate_ips([],['x'*65])

    def test_monitor_campaign_identity_is_literal_on_nocase_legacy_schema(self):
        with self.db.connection() as conn:
            schema = conn.execute("SELECT sql FROM sqlite_master WHERE name='campaigns'").fetchone()[0]
            self.assertIn('id TEXT PRIMARY KEY',schema)
            conn.execute('ALTER TABLE campaigns RENAME TO old_campaigns')
            conn.execute(schema.replace('id TEXT PRIMARY KEY','id TEXT PRIMARY KEY COLLATE NOCASE',1))
            conn.execute('INSERT INTO campaigns SELECT * FROM old_campaigns'); conn.commit()
        result = self.result(); result['campaign_id'] = self.campaign.swapcase()
        with self.assertRaises(RuntimeError): self.monitor._handle_check_result(result)
        with self.db.connection() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM checks').fetchone()[0],0)

    def test_comparison_source_change_during_insert_rolls_back(self):
        self.monitor._handle_check_result(self.result())
        before = self.db.get_recent_checks(self.campaign)
        with self.db.connection() as conn:
            conn.execute("CREATE TRIGGER change_previous AFTER INSERT ON checks BEGIN UPDATE checks SET content_hash='changed-source' WHERE id<NEW.id; END")
            conn.commit()
        with self.assertRaises(RuntimeError): self.monitor._handle_check_result(self.result(digest='b'*64))
        self.assertEqual(self.db.get_recent_checks(self.campaign),before)
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_boolean_comparison_schema_is_not_a_native_version_number(self):
        self.monitor._handle_check_result(self.result())
        with self.db.connection() as conn:
            payload = json.loads(conn.execute('SELECT metadata FROM checks').fetchone()[0])
            payload['monitor_comparison']['schema_version'] = True
            conn.execute('UPDATE checks SET metadata=?',(json.dumps(payload),)); conn.commit()
        self.monitor._handle_check_result(self.result('down',503,'b'*64))
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_publication_returns_committed_source_ids_and_content_comparison(self):
        first = self.monitor._handle_check_result(self.result())
        second = self.monitor._handle_check_result(self.result(digest='b'*64))
        self.assertEqual(second['previous_check_id'],first['check_id'])
        self.assertTrue(second['content_changed'])
        with self.db.connection() as conn:
            self.assertEqual(conn.execute('SELECT id FROM checks ORDER BY id').fetchall(),
                             [(first['check_id'],),(second['check_id'],)])

    def test_cancellation_between_collection_and_publication_has_no_immediate_result(self):
        def collected(campaign):
            # Declared fault-injection point: signal the real lifecycle event
            # after a supplied observation, before SQLite publication.
            self.assertFalse(self.monitor.stop(0)); return self.result()
        with patch.object(self.monitor,'_check_campaign',side_effect=collected):
            self.assertEqual(self.monitor.check_now(self.campaign),[])
        self.assertEqual(self.db.get_recent_checks(self.campaign),[])

    def test_stop_before_commit_admission_rolls_back_pending_sql_and_callbacks(self):
        entered,release = threading.Event(),threading.Event()
        returned,errors,callbacks = [],[],[]
        self.monitor.on_check_complete(callbacks.append)
        original = self.db._assert_writer_record
        def delayed(conn,table,columns,values,rowid):
            original(conn,table,columns,values,rowid)
            if table=='checks' and not entered.is_set():
                entered.set(); self.assertTrue(release.wait(3))
        def check():
            try: returned.append(self.monitor.check_now(self.campaign))
            except Exception as error: errors.append(type(error).__name__)
        with patch.object(self.monitor,'_check_campaign',return_value=self.result()),patch.object(self.db,'_assert_writer_record',side_effect=delayed):
            thread = threading.Thread(target=check); thread.start()
            try:
                self.assertTrue(entered.wait(2)); self.assertFalse(self.monitor.stop(0))
            finally: release.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors,[])
        self.assertEqual(returned,[[]]); self.assertEqual(callbacks,[])
        self.assertEqual(self.db.get_recent_checks(self.campaign),[])
        self.assertIsNone(self.db.get_campaign(self.campaign)['last_check'])
        self.assertEqual(self.db.get_unacknowledged_alerts(),[])

    def test_already_admitted_commit_may_finish_without_blocking_stop_zero(self):
        entered,release = threading.Event(),threading.Event(); returned,errors = [],[]
        original = self.monitor._publication_commit
        @contextmanager
        def delayed():
            with original():
                entered.set(); self.assertTrue(release.wait(3)); yield
        def check():
            try: returned.append(self.monitor.check_now(self.campaign))
            except Exception as error: errors.append(type(error).__name__)
        with patch.object(self.monitor,'_check_campaign',return_value=self.result()),patch.object(self.monitor,'_publication_commit',side_effect=delayed):
            thread = threading.Thread(target=check); thread.start()
            try:
                self.assertTrue(entered.wait(2)); started = time.monotonic()
                self.assertFalse(self.monitor.stop(0)); self.assertLess(time.monotonic()-started,.5)
            finally: release.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors,[])
        self.assertEqual(len(returned[0]),1)
        self.assertEqual(self.db.get_recent_checks(self.campaign)[0]['id'],returned[0][0]['check_id'])
        self.assertTrue(self.monitor.stop(2))

    def test_unavailable_methods_refuse_without_interpreting_opaque_claims(self):
        analyzer = IntelligenceAnalyzer(str(self.root/'saved.db'))
        for name,args in (('_analyze_geographic_risk',(object(),)),('_analyze_user_agent_risk',(object(),)),
                          ('_analyze_ip_reputation',(object(),object()))):
            result = getattr(analyzer,name)(*args)
            self.assertEqual(result['status'],'unavailable'); self.assertIsNone(result['confidence'])
        with self.assertRaises(NotImplementedError): analyzer._analyze_single_victim(object())
        with self.assertRaises(NotImplementedError): self.db.calculate_risk_score(object(),object(),object())

    def test_provider_endpoint_query_fragment_and_credentials_are_rejected(self):
        for suffix in ('?wrong=path','#fragment'):
            with self.assertRaises(ValueError): IPAnalyzer(provider_urls={'ip-api':'http://127.0.0.1:9/base'+suffix})
        with self.assertRaises(ValueError): IPAnalyzer(provider_urls={'ip-api':'http://user:pass@127.0.0.1:9/base'})


if __name__=='__main__': unittest.main()
