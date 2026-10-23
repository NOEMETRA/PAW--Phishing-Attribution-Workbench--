"""Actual SQLite geographic selection, passive outputs and unsupported claims."""
from contextlib import closing
import itertools
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.database import CampaignDatabase
from paw.sentinel.geographic_reports import GeographicReporter, geographic_database_path
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
import test_sentinel_database_rows as source_rows


class SentinelGeographicReport(unittest.TestCase):
    setUp = source_rows.SentinelDatabaseRows.setUp
    tearDown = source_rows.SentinelDatabaseRows.tearDown
    database = source_rows.SentinelDatabaseRows.database

    def reporter(self, writer):
        reporter = GeographicReporter(CampaignDatabase(writer.db_path, read_only=True))
        reporter.reports_dir = str(self.root / 'output')
        return reporter

    def add(self, writer, geo=None, confidence=None, case='stored', label='attacker'):
        identifier = writer.add_victim_intelligence('192.0.2.1', 'stored UA',
            'https://example.invalid/', case_id=case)
        with writer.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET geolocation_data=?, '
                'interaction_confidence=?, interaction_type=? WHERE id=?',
                (geo, confidence, label, identifier))
        return identifier

    def assert_unverified(self, report):
        self.assertEqual(report['status'], 'success')
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['evidence_scope'], 'stored_rows_unverified')
        self.assertIsNone(report['summary']['risk_assessment']['level'])
        self.assertEqual(report['summary']['risk_assessment']['status'], 'unavailable')
        self.assertEqual(report['summary']['attacker_countries'], [])
        self.assertEqual(report['summary']['victim_countries'], [])
        self.assertEqual(report['visualizations'], {})
        self.assertTrue(report['unavailable']['identity'])
        self.assertTrue(report['unavailable']['interactive_maps'])
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)

    def test_complete_old_cases_literal_identifiers_and_no_confidence_filter_at_zero(self):
        writer = self.database()
        literal = "case' OR 1=1 --"
        cases = ['older'] * 105 + ['', None, literal] + ['newer'] * 105
        ids = {}
        with writer.connection() as conn:
            for index, case in enumerate(cases):
                cursor = conn.execute('INSERT INTO victim_intelligence '
                    '(victim_ip, click_time, phishing_url, case_id, geolocation_data, interaction_confidence) '
                    'VALUES (?,?,?,?,?,?)', ('192.0.2.1', f'{index:04}', 'https://example.invalid/',
                    case, '{"country":"Stored","lat":0,"lon":0}', None))
                ids.setdefault(case, []).append(cursor.lastrowid)
        reporter = self.reporter(writer)
        before = Path(writer.db_path).read_bytes()
        for case in (None, 'older', 'newer', '', literal, 'OLDER', 'absent'):
            report = reporter.get_statistics(case)
            expected = list(range(213, 0, -1)) if case is None else list(reversed(ids.get(case, [])))
            self.assertEqual([r['id'] for r in report['source_records']], expected)
            self.assertEqual(report['selection']['included_ids'], expected)
            self.assertEqual(report['total_records'], len(expected))
            self.assertEqual(report['total_victims'], len(expected))
            self.assertEqual(report['confidence_filter'], 'not_applied')
            self.assertEqual(len(report['geographic_stats']['coordinates']), len(expected))
            self.assertIsNone(report['attackers'])
            self.assertIsNone(report['attacker_percentage'])
            self.assert_unverified(report)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        self.assertFalse(Path(reporter.reports_dir).exists())

    def test_json_sources_remain_complete_when_no_geography_can_be_interpreted(self):
        writer = self.database()
        identifier = self.add(writer)
        reporter = self.reporter(writer)
        for raw in (None, '', 'null', '[]', '{broken', '{"country":"A","country":"B"}',
                    '{"lat":NaN}', b'\xff', '{"country":null}', '{"country":5}', '{}'):
            with self.subTest(raw=raw):
                with writer.connection() as conn:
                    conn.execute('UPDATE victim_intelligence SET geolocation_data=?', (raw,))
                before = Path(writer.db_path).read_bytes()
                report = reporter.get_statistics()
                self.assertEqual(report['source_records'], reporter.db.get_victim_intelligence(victim_id=identifier))
                self.assertEqual(report['total_records'], 1)
                self.assertEqual(report['total_victims'], 0)
                self.assertEqual(report['selection']['geography_unusable_ids'], [identifier])
                self.assertEqual(report['countries'], {})
                self.assert_unverified(report)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)
        with writer.connection() as conn:
            conn.execute("UPDATE victim_intelligence SET geolocation_data=CAST(X'80' AS TEXT)")
        evidence = reporter.get_statistics()['source_records'][0]['json_evidence']['fields']['geolocation_data']
        self.assertEqual(evidence['status'], 'invalid_encoding')
        self.assertEqual(evidence['raw_storage'], {'type': 'text', 'encoding': 'base64', 'value': 'gA=='})

    def test_confidence_threshold_has_explicit_unusable_and_below_threshold_ids(self):
        writer = self.database()
        for value in (None, 0, 0.4, 0.5, 1, -1, 2, 'bad'):
            self.add(writer, '{"country":"Stored"}', value)
        reporter = self.reporter(writer)
        self.assertEqual(reporter.get_statistics()['total_victims'], 8)
        report = reporter.get_statistics(min_confidence=0.5)
        self.assertEqual(report['selection']['included_ids'], [5, 4])
        self.assertEqual(report['selection']['confidence_unusable_ids'], [8, 7, 6, 1])
        self.assertEqual(report['selection']['confidence_below_threshold_ids'], [3, 2])
        self.assertEqual(report['countries'], {'Stored': 2})
        self.assertEqual(len(report['source_records']), 8)
        self.assert_unverified(report)

    def test_country_exclusion_precedes_every_aggregate_and_structured_region_city_keys(self):
        writer = self.database()
        for geo in ({'country': 'A', 'region': 'B - C', 'city': 'D', 'lat': 0, 'lon': 0},
                    {'country': 'A - B', 'region': 'C', 'city': 'D', 'lat': 0, 'lon': 0}):
            self.add(writer, json.dumps(geo), 0.9)
        reporter = self.reporter(writer)
        complete = reporter.get_statistics()
        self.assertEqual(len(complete['geographic_stats']['regions']), 2)
        report = reporter.generate_geographic_report(exclude_countries=['a'], output_format='json')
        self.assertEqual(report['selection']['country_excluded_ids'], [1])
        self.assertEqual(report['total_records'], 2)
        self.assertEqual(report['total_victims'], 1)
        stats = report['geographic_stats']
        self.assertEqual(stats['countries'], {'A - B': 1})
        self.assertEqual(stats['regions'], [{'country': 'A - B', 'region': 'C', 'count': 1, 'source_ids': [2]}])
        self.assertEqual(stats['cities'], [{'country': 'A - B', 'region': 'C', 'city': 'D', 'count': 1, 'source_ids': [2]}])
        self.assertEqual(stats['interaction_types'], {'attacker': {'A - B': 1}})
        self.assertEqual([p['record_id'] for p in stats['coordinates']], [2])
        self.assert_unverified(report)

    def test_zero_extreme_coordinates_wrong_shapes_and_field_omissions(self):
        writer = self.database()
        fixtures = [{'lat': 0, 'lon': 0}, {'lat': -90, 'lon': 180},
            {'country': 'Stored', 'lat': True, 'lon': 0},
            {'country': 'Stored', 'lat': 91, 'lon': 0},
            {'country': 'Stored', 'lat': '0', 'lon': '0'},
            {'country': '  ', 'region': 'Stored region'}, {'lat': 0}]
        for geo in fixtures:
            self.add(writer, json.dumps(geo), label=None)
        report = self.reporter(writer).get_statistics()
        self.assertEqual(report['selection']['included_ids'], [6, 5, 4, 3, 2, 1])
        self.assertEqual(report['selection']['geography_unusable_ids'], [7])
        stats = report['geographic_stats']
        self.assertEqual([p['record_id'] for p in stats['coordinates']], [2, 1])
        self.assertEqual(stats['field_omissions']['coordinates'], [6, 5, 4, 3])
        self.assertEqual(stats['field_omissions']['country'], [6, 2, 1])
        self.assertEqual(stats['countries'], {'Stored': 3})
        self.assertEqual(stats['interaction_types'], {})
        self.assert_unverified(report)

    def test_actual_formats_escaped_html_safe_unique_filenames_and_source_round_trip(self):
        writer = self.database()
        case = '../escape/<script>alert(1)</script>'
        raw_country = '<img src="https://example.invalid/pixel">'
        identifier = self.add(writer, json.dumps({'country': raw_country, 'lat': 0, 'lon': 0}), case=case)
        with writer.connection() as conn:
            conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT)")
        reporter = self.reporter(writer)
        before = Path(writer.db_path).read_bytes()
        paths = []
        for format_name, suffixes in (('json', {'.json'}), ('html', {'.html'}), ('both', {'.json', '.html'})):
            report = reporter.generate_geographic_report(case, output_format=format_name)
            self.assert_unverified(report)
            self.assertEqual({Path(p).suffix for p in report['output_files']}, suffixes)
            body = {k: v for k, v in report.items() if k != 'output_files'}
            for filename in report['output_files']:
                path = Path(filename)
                self.assertEqual(path.parent, Path(reporter.reports_dir))
                self.assertRegex(path.stem, r'^geographic_report_[0-9a-f]{32}$')
                self.assertNotIn(path, paths)
                paths.append(path)
                text = path.read_text(encoding='utf-8')
                if path.suffix == '.json':
                    self.assertEqual(json.loads(text), body)
                    self.assertEqual(json.loads(text)['source_records'], reporter.db.get_victim_intelligence(victim_id=identifier))
                else:
                    self.assertNotIn('<script', text.lower())
                    self.assertNotIn('<img', text.lower())
                    self.assertNotIn('<iframe', text.lower())
                    self.assertIn('&lt;img', text)
                    self.assertIn('Content-Security-Policy', text)
        self.assertEqual(len(paths), 4)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_invalid_options_and_output_failures_are_explicit_and_create_no_false_success(self):
        writer = self.database()
        self.add(writer, '{"country":"Stored"}')
        reporter = self.reporter(writer)
        before = Path(writer.db_path).read_bytes()
        for value in (True, None, '0.5', -0.1, 1.1, float('nan'), float('inf'), 10**400):
            with self.assertRaises(ValueError):
                reporter.generate_geographic_report(min_confidence=value)
        for value in (1, False, [], {}):
            with self.assertRaises(TypeError):
                reporter.get_statistics(value)
        for value in ('US', [None], ['  ']):
            with self.assertRaises(ValueError):
                reporter.generate_geographic_report(exclude_countries=value)
        with self.assertRaises(ValueError):
            reporter.generate_geographic_report(output_format='pdf')
        self.assertFalse(Path(reporter.reports_dir).exists())
        blocker = self.root / 'output-blocker'
        blocker.write_bytes(b'original existing file')
        reporter.reports_dir = str(blocker / 'child')
        with self.assertRaises(OSError):
            reporter.generate_geographic_report()
        self.assertEqual(blocker.read_bytes(), b'original existing file')
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        with self.assertRaises(RuntimeError):
            GeographicReporter()

    def test_lone_surrogates_remain_lossless_in_json_and_do_not_break_html(self):
        writer = self.database()
        country = 'stored\ud800<\udfff> Ω 😀'
        self.add(writer, json.dumps({'country': country}), case='stored Ω 😀')
        reporter = self.reporter(writer)
        before = Path(writer.db_path).read_bytes()
        report = reporter.generate_geographic_report('stored Ω 😀', output_format='both')
        self.assertEqual(report['geographic_stats']['countries'], {country: 1})
        for filename in report['output_files']:
            text = Path(filename).read_text(encoding='utf-8')
            if filename.endswith('.json'):
                self.assertEqual(json.loads(text)['geographic_stats']['countries'], {country: 1})
            else:
                self.assertIn('stored\\ud800&lt;\\udfff&gt; Ω 😀', text)
                self.assertIn('Case: stored Ω 😀', text)
                self.assertNotIn('\ud800', text)
                self.assertNotIn('\udfff', text)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        body = {k: v for k, v in report.items() if k != 'output_files'}
        body['case_id'] = 'case\ud800<\udfff>'
        html = reporter._generate_html_report(body)
        self.assertIn('Case: case\\ud800&lt;\\udfff&gt;', html)
        html.encode('utf-8')

    def test_config_defaults_only_when_absent_and_never_hides_existing_source_errors(self):
        config = self.root / 'sentinel_config.json'
        self.assertEqual(geographic_database_path(config), str(Path('sentinel.db').absolute()))
        for invalid in ('null', 'false', '[]', '{}', '{broken',
                        '{"storage":{}}', '{"storage":{"database_path":" "}}',
                        '{"storage":{"database_path":3}}',
                        '{"storage":{"database_path":"A","database_path":"B"}}'):
            config.write_text(invalid, encoding='utf-8')
            before = config.read_bytes()
            with self.assertRaises(ValueError):
                geographic_database_path(config)
            self.assertEqual(config.read_bytes(), before)
        config.write_bytes(b'\xff')
        with self.assertRaises(UnicodeDecodeError):
            geographic_database_path(config)
        config.write_text(json.dumps({'storage': {'database_path': 'literal # Ω %.db'}}), encoding='utf-8')
        self.assertEqual(geographic_database_path(config), str(Path('literal # Ω %.db').absolute()))
        config.unlink()
        config.mkdir()
        with self.assertRaises(ValueError):
            geographic_database_path(config)

    def test_all_sixteen_legacy_partial_layouts_keep_null_confidence_without_migration(self):
        for index, fields in enumerate(fields for size in range(4)
                for fields in itertools.permutations(source_rows.INTERACTION_FIELDS, size)):
            path = self.root / f'legacy-{index}.db'
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                    key + ' ' + sql for key, sql in source_rows.LEGACY_FIELDS + list(fields)) + ')')
                conn.execute('INSERT INTO victim_intelligence (victim_ip, click_time, phishing_url, geolocation_data) '
                    'VALUES (?,?,?,?)', ('192.0.2.1', 'stored', 'https://example.invalid/', '{"lat":0,"lon":0}'))
            before = path.read_bytes()
            analyzer = IntelligenceAnalyzer(str(path), read_only=True)
            report = analyzer.get_geographic_statistics()
            self.assertEqual(report['total_victims'], 1)
            self.assertEqual(report['source_records'], analyzer.db.get_victim_intelligence(victim_id=1))
            self.assert_unverified(report)
            self.assertEqual(path.read_bytes(), before)

    def test_empty_unhealthy_later_journal_and_unsupported_scalars_never_hide_errors(self):
        writer = self.database()
        reporter = self.reporter(writer)
        empty = reporter.get_statistics()
        self.assertEqual(empty['total_records'], 0)
        self.assert_unverified(empty)
        self.add(writer, '{"country":"Stored"}')
        for field, value, error in (('interaction_confidence', float('inf'), ValueError), ('victim_ua', b'\xff', TypeError)):
            with writer.connection() as conn:
                conn.execute('UPDATE victim_intelligence SET interaction_confidence=NULL, victim_ua=?', ('stored UA',))
                conn.execute(f'UPDATE victim_intelligence SET {field}=?', (value,))
            before = Path(writer.db_path).read_bytes()
            with self.assertRaises(error):
                reporter.generate_geographic_report()
            self.assertEqual(Path(writer.db_path).read_bytes(), before)
            self.assertFalse(Path(reporter.reports_dir).exists())
        journal = Path(writer.db_path + '-journal')
        journal.write_bytes(b'pending original journal')
        with self.assertRaises(ValueError):
            reporter.get_statistics()
        self.assertEqual(journal.read_bytes(), b'pending original journal')
        incomplete = self.root / 'incomplete.db'
        incomplete.write_bytes(b'')
        incomplete_reporter = GeographicReporter(CampaignDatabase(str(incomplete), read_only=True))
        with self.assertRaises(sqlite3.OperationalError):
            incomplete_reporter.get_statistics()
        self.assertEqual(incomplete.read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
