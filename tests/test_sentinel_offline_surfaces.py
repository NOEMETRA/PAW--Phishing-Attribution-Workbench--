"""Configuration, publication, local-file and active-boundary module contracts."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.config import SentinelConfig
from paw.sentinel.config import _storage_path
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.file_monitor import FileMonitor
from paw.sentinel.geographic_reports import GeographicReporter, geographic_database_path
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
from paw.sentinel.ip_analyzer import IPAnalyzer
from paw.sentinel.monitor import SentinelMonitor


class SentinelOfflineSurfaces(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.path=self.root/'saved.db'; self.db=CampaignDatabase(str(self.path))
        self.config=SentinelConfig(str(self.root/'config.json'))
        self.policy=offline_policy(); self.policy.__enter__(); self.blocked=len(violations())

    def tearDown(self):
        blocked=violations()[self.blocked:]; self.policy.__exit__(None,None,None)
        self.temp.cleanup(); self.assertEqual(blocked,[])

    def test_config_rejects_key_coercion_cycles_and_oversized_native_trees(self):
        cycle={}; cycle['loop']=cycle
        for value in ({1:'number','1':'text'},{'tuple':()},cycle,{'raw':'x'*(1024**2)}):
            before=dict(self.config._config)
            with self.assertRaises(ValueError): self.config.set('supplied',value)
            self.assertEqual(self.config._config,before)
            self.assertFalse(Path(self.config.config_file).exists())

    def test_public_config_getters_cannot_mutate_unsaved_state(self):
        self.config.get('storage')['database_path']='other'
        self.config.get_storage_config()['database_path']='other'
        self.config.get_monitoring_config()['enabled']=False
        self.config.get_alert_config()['enabled']=False
        self.config.get_analysis_config()['enable_screenshots']=False
        self.assertTrue(self.config.get('monitoring.enabled'))
        self.assertTrue(self.config.get('alerts.enabled'))
        self.assertTrue(self.config.get('analysis.enable_screenshots'))
        self.assertNotEqual(self.config.get('storage.database_path'),str(Path('other').absolute()))

    def test_known_config_sections_and_resource_profile_must_be_objects(self):
        path=self.root/'present.json'
        for value in ({'monitoring':[]},{'alerts':False},{'analysis':None},
                      {'storage':{'limits':{'max_rows':0}}}):
            path.write_text(json.dumps(value),encoding='utf-8')
            with self.assertRaises(ValueError): SentinelConfig(str(path))

    def test_explicit_null_profile_is_rejected_without_replacing_config(self):
        path=Path(self.config.config_file)
        self.config.set('storage.limits',{})
        published=path.read_bytes(); live=self.config.get_storage_config()
        with self.assertRaises(ValueError): self.config.set('storage.limits',None)
        self.assertEqual(path.read_bytes(),published)
        self.assertEqual(self.config.get_storage_config(),live)
        path.write_text('{"storage":{"limits":null}}',encoding='utf-8')
        with self.assertRaises(ValueError): SentinelConfig(str(path))
        path.write_text('{"storage":{}}',encoding='utf-8')
        self.assertIsNone(SentinelConfig(str(path)).get_database_options()['limits'])
        self.assertEqual(CampaignDatabase(str(self.path),limits=None).limits['max_rows'],10000)

    def test_set_installs_the_published_copy_without_caller_owned_containers(self):
        supplied={'nested':[{'enabled':True}]}
        self.config.set('monitoring.supplied',supplied)
        path=Path(self.config.config_file); published=path.read_bytes()
        supplied['nested'][0]['enabled']=False; supplied['nested'].append(float('nan'))
        self.assertEqual(self.config.get('monitoring.supplied'),{'nested':[{'enabled':True}]})
        self.assertEqual(path.read_bytes(),published)
        self.config.set('monitoring.enabled',False)
        self.assertEqual(json.loads(path.read_text())['monitoring']['supplied'],{'nested':[{'enabled':True}]})

    def test_html_and_json_publish_above_the_default_with_a_larger_profile(self):
        limit=192*1024**2
        database=CampaignDatabase(str(self.path),read_only=True,limits={'max_output_bytes':limit})
        reporter=GeographicReporter(database); reporter.reports_dir=self.root/'large-report'
        report=reporter._build_report()
        # Actual encoded report above the former 64 MiB HTML ceiling; no I/O stub.
        report['declared_fixture']=['x'*(1024**2)]*65
        outputs=reporter._save_report(report,'both')
        self.assertEqual(len(outputs),2)
        self.assertTrue(all(Path(name).stat().st_size>64*1024**2 for name in outputs))
        self.assertLess(sum(Path(name).stat().st_size for name in outputs),limit)
        with open(outputs[0],encoding='utf-8') as handle:
            decoded=json.load(handle)
        self.assertEqual(len(decoded['declared_fixture']),65)
        self.assertEqual(decoded['declared_fixture'][-1],'x'*(1024**2))
        with open(outputs[1],'rb') as handle:
            self.assertIn(b'Content-Security-Policy',handle.read(512))
            handle.seek(-20,2); self.assertTrue(handle.read().endswith(b'</pre></body></html>'))

    def test_all_case_directory_budget_is_shared_and_preserves_baseline(self):
        cases=self.root/'cases'
        for name in ('case-one','case-two'): (cases/name/'child/deep').mkdir(parents=True)
        monitor=FileMonitor(str(cases),max_directories=4)
        before=dict(monitor._baseline_hashes)
        for operation in (monitor.monitor_all_cases,monitor.generate_integrity_report):
            with self.subTest(operation=operation):
                with self.assertRaises(ValueError): operation()
                self.assertEqual(monitor._baseline_hashes,before)
        # A new invocation starts with a fresh budget after the failed traversal.
        monitor._limits['max_directories']=100
        self.assertEqual(monitor.generate_integrity_report()['total_cases'],2)

    def test_all_case_budget_covers_later_walks_and_rolls_back_prior_case_effects(self):
        cases=self.root/'cases'; case=cases/'case-one'; case.mkdir(parents=True)
        selected=case/'input.eml'; selected.write_bytes(b'original')
        monitor=FileMonitor(str(cases),max_directories=3)
        monitor.check_file_changes('case-one'); before=dict(monitor._baseline_hashes)
        selected.write_bytes(b'changed fixture')
        with self.assertRaises(ValueError): monitor.monitor_all_cases()
        self.assertEqual(monitor._baseline_hashes,before)
        monitor._limits['max_directories']=100
        self.assertTrue(monitor.monitor_all_cases()[0]['modified_files'])

    def test_geographic_selection_uses_the_same_config_admission_and_binding(self):
        path=self.root/'geo.json'
        for raw in ('{"storage":{"database_path":"file:unexpected?mode=rwc"}}',
                    '{"storage":{"database_path":"saved.db"},"number":NaN}',
                    json.dumps({'storage':{'database_path':'saved.db'},'raw':'x'*(1024**2)})):
            path.write_text(raw,encoding='utf-8'); before=path.read_bytes()
            with self.assertRaises(ValueError): geographic_database_path(path)
            self.assertEqual(path.read_bytes(),before)
        path.write_text(json.dumps({'storage':{'database_path':'literal # Ω %.db'}}),encoding='utf-8')
        self.assertEqual(geographic_database_path(path),str(Path('literal # Ω %.db').absolute()))

    def test_geographic_output_budget_fails_before_creating_any_directory(self):
        db=CampaignDatabase(str(self.path),read_only=True,limits={'max_output_bytes':100})
        reporter=GeographicReporter(db); reporter.reports_dir=self.root/'not-created'
        with self.assertRaises(ValueError): reporter.generate_geographic_report()
        self.assertFalse(Path(reporter.reports_dir).exists())

    def test_geographic_default_output_root_is_bound_at_construction(self):
        previous=Path.cwd(); first=self.root/'first'; second=self.root/'second'; first.mkdir(); second.mkdir()
        try:
            os.chdir(first); reporter=GeographicReporter(self.db)
            os.chdir(second); report=reporter.generate_geographic_report(output_format='json')
            self.assertEqual(Path(report['output_files'][0]).parent,first/'reports/geographic')
            self.assertFalse((second/'reports').exists())
        finally: os.chdir(previous)

    def test_relative_output_override_is_bound_when_assigned(self):
        previous=Path.cwd(); first=self.root/'first'; second=self.root/'second'; first.mkdir(); second.mkdir()
        try:
            os.chdir(first); reporter=GeographicReporter(self.db); reporter.reports_dir='chosen'
            os.chdir(second); report=reporter.generate_geographic_report(output_format='json')
            self.assertEqual(Path(report['output_files'][0]).parent,first/'chosen')
            self.assertFalse((second/'chosen').exists())
        finally: os.chdir(previous)

    def test_read_only_identity_classification_rejects_before_active_policy_or_input(self):
        analyzer=IntelligenceAnalyzer(str(self.path),read_only=True)
        with self.assertRaises(RuntimeError): analyzer.classify_interaction_type({})

    @unittest.skipUnless(os.name=='nt','Windows path namespace contract')
    def test_windows_alias_refusal_does_not_depend_on_recent_stdlib_reserved_rules(self):
        # Older Python reserved-name helpers recognize DOS names but not every
        # ADS/trailing-dot/space alias. Probe only parsing, never the filesystem.
        with patch('pathlib.PureWindowsPath.is_reserved',return_value=False), \
                patch('os.path.isreserved',return_value=False,create=True):
            for name in ('saved.db:stream','folder./saved.db','folder /saved.db'):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError): _storage_path(name)

    def test_geographic_directory_alias_is_rejected_before_output(self):
        outside=self.root/'outside'; outside.mkdir(); link=self.root/'linked'
        try: link.symlink_to(outside,target_is_directory=True)
        except OSError: self.skipTest('Directory link creation unavailable')
        reporter=GeographicReporter(self.db); reporter.reports_dir=link/'reports'
        with self.assertRaises(ValueError): reporter.generate_geographic_report()
        self.assertEqual(list(outside.iterdir()),[])

    def test_file_observations_reject_hardlink_aliases(self):
        cases=self.root/'cases'; case=cases/'case-saved'; case.mkdir(parents=True)
        outside=self.root/'outside.eml'; outside.write_bytes(b'declared source')
        try: os.link(outside,case/'input.eml')
        except OSError: self.skipTest('Hard links unavailable')
        with self.assertRaises(ValueError): FileMonitor(str(cases)).get_case_files('case-saved')
        self.assertEqual(outside.read_bytes(),b'declared source')

    def test_integrity_report_rechecks_inventory_after_verification(self):
        cases=self.root/'cases'; case=cases/'case-saved'; case.mkdir(parents=True)
        selected=case/'input.eml'; selected.write_bytes(b'original')
        monitor=FileMonitor(str(cases))
        def changed(identifier):
            selected.write_bytes(b'declared changed source'); return None,'declared fixture'
        with patch.object(monitor,'verify_merkle_integrity',changed):
            with self.assertRaises(OSError): monitor.generate_integrity_report()

    def test_file_output_budget_preserves_previous_instance_baseline(self):
        cases=self.root/'cases'; case=cases/'case-saved'; case.mkdir(parents=True)
        (case/'input.eml').write_bytes(b'original')
        monitor=FileMonitor(str(cases),max_output_bytes=10)
        with self.assertRaises(ValueError): monitor.check_file_changes('case-saved')
        self.assertEqual(monitor._baseline_hashes,{})

    def test_file_directory_and_depth_budgets_stop_real_walks(self):
        cases=self.root/'cases'; case=cases/'case-saved'; (case/'one/two').mkdir(parents=True)
        for options in ({'max_directories':1},{'max_depth':1}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError): FileMonitor(str(cases),**options).get_case_files('case-saved')

    def test_failed_file_observation_emission_restores_the_invocation_baseline(self):
        cases=self.root/'cases'; case=cases/'case-saved'; case.mkdir(parents=True)
        selected=case/'input.eml'; selected.write_bytes(b'original')
        monitor=FileMonitor(str(cases)); monitor.check_file_changes('case-saved')
        before=dict(monitor._baseline_hashes); selected.write_bytes(b'declared changed source')
        with patch.object(monitor,'_record_file_check',side_effect=OSError('Declared output failure')):
            with self.assertRaises(OSError): monitor.monitor_all_cases()
        self.assertEqual(monitor._baseline_hashes,before)
        self.assertTrue(monitor.check_file_changes('case-saved')['modified_files'])

    def test_offline_active_entrypoints_refuse_before_io_or_thread_work(self):
        monitor=SentinelMonitor(config=self.config,database=self.db)
        analyzer=IntelligenceAnalyzer(str(self.path))
        ip=IPAnalyzer()
        operations=(monitor.start,monitor.check_now,monitor._perform_checks,
            lambda:monitor._check_campaign({}),lambda:monitor._take_screenshot('literal','supplied'),
            analyzer.analyze_unanalyzed_victims,lambda:analyzer._analyze_single_victim({}),
            analyzer._update_attacker_correlations,lambda:analyzer.classify_interaction_type({}),
            lambda:ip.analyze_ip('192.0.2.1'),lambda:ip.reverse_dns_lookup('192.0.2.1'),
            lambda:ip.geolocate_ip('192.0.2.1'),lambda:ip._geolocate_ipapi('192.0.2.1'),
            lambda:ip._geolocate_ipify('192.0.2.1'),lambda:ip.whois_lookup('192.0.2.1'),
            lambda:ip.batch_analyze_ips([]),lambda:ip.correlate_ips([]),
            lambda:ip.analyze_risk_indicators({}),lambda:self.db.calculate_risk_score([],{},{}))
        before=self.path.read_bytes()
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(RuntimeError): operation()
        self.assertEqual(self.path.read_bytes(),before)
        self.assertFalse(monitor.is_running()); self.assertIsNone(monitor._thread)


if __name__=='__main__': unittest.main()
