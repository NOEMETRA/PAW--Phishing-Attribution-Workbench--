"""Passive descriptions of stored geographic claims; no identity inference."""
from collections import Counter, defaultdict
from html import escape
import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import uuid
from .config import configured_database_options, _storage_directory, _json_chunks, _bounded_report


def geographic_database_path(config_file='sentinel_config.json'):
    """Default only on absent config; unreadable/invalid selection must fail."""
    return geographic_database_options(config_file)['db_path']


def geographic_database_options(config_file='sentinel_config.json'):
    return configured_database_options(config_file, require_explicit=True)


def _html_text(value):
    # Preserve valid Unicode and display lone surrogates as literal escapes.
    return escape(value.encode('utf-8', errors='backslashreplace').decode('utf-8'))


def validate_geographic_options(case_id=None, min_confidence=0.0, exclude_countries=None,
                                output_format='both'):
    if case_id is not None and not isinstance(case_id, str):
        raise TypeError('case_id must be a string or None')
    if (isinstance(min_confidence, bool) or not isinstance(min_confidence, (int, float))
            or not 0 <= min_confidence <= 1 or not math.isfinite(min_confidence)):
        raise ValueError('min_confidence must be a finite number between 0 and 1')
    if output_format not in ('json', 'html', 'both'):
        raise ValueError('output_format must be json, html or both')
    if exclude_countries is not None and (not isinstance(exclude_countries, list)
            or any(not isinstance(c, str) or not c.strip() for c in exclude_countries)):
        raise ValueError('exclude_countries must be a list of nonblank country strings')


class GeographicReporter:
    """Build stored-row observations; saving is explicit report generation."""

    def __init__(self, db_connection=None):
        if db_connection is None:
            raise RuntimeError('Geographic reports require a real database connection')
        self.db = db_connection
        self.reports_dir = str(Path('reports/geographic').absolute())

    @property
    def reports_dir(self):
        return self._reports_dir

    @reports_dir.setter
    def reports_dir(self, value):
        from .contracts import _storage_path
        self._reports_dir = str(_storage_path(value))

    def generate_geographic_report(self, case_id: str = None, min_confidence: float = 0.0,
                                   exclude_countries: Optional[List[str]] = None, *,
                                   output_format: str = 'both') -> Dict[str, Any]:
        validate_geographic_options(case_id, min_confidence, exclude_countries, output_format)
        report = self._build_report(case_id, min_confidence, exclude_countries)
        self.db.check_report(report)
        report['output_files'] = self._save_report(report, output_format)
        return report

    @_bounded_report
    def get_statistics(self, case_id=None, min_confidence=0.0):
        """Same selected observations as the report, without output creation."""
        report = self._build_report(case_id, min_confidence)
        report.update(countries=report['geographic_stats']['countries'],
                      attackers=None, attacker_percentage=None)
        return report

    @staticmethod
    def _label(value):
        return value if isinstance(value, str) and value.strip() else None

    @staticmethod
    def _coordinates(geo):
        lat, lon = geo.get('lat'), geo.get('lon')
        if (isinstance(lat, (int, float)) and not isinstance(lat, bool) and -90 <= lat <= 90
                and isinstance(lon, (int, float)) and not isinstance(lon, bool) and -180 <= lon <= 180):
            return lat, lon
        return None

    def _build_report(self, case_id=None, min_confidence=0.0, exclude_countries=None):
        validate_geographic_options(case_id, min_confidence, exclude_countries)
        records = self.db.get_forensic_victim_intelligence(case_id)
        json.dumps(records, allow_nan=False)  # Explicit failure on unsupported native scalars.
        excluded = {c.casefold() for c in (exclude_countries or [])}
        countries, regions, cities = Counter(), defaultdict(list), defaultdict(list)
        interactions, coordinates = defaultdict(Counter), []
        selection = {key: [] for key in ('included_ids', 'confidence_unusable_ids',
            'confidence_below_threshold_ids', 'country_excluded_ids', 'geography_unusable_ids')}
        omissions = {key: [] for key in ('country', 'region', 'city', 'coordinates', 'interaction_type')}
        for record in records:
            identifier = record['id']
            confidence = record['interaction_confidence']
            if min_confidence > 0:
                if (isinstance(confidence, bool) or not isinstance(confidence, (int, float))
                        or not 0 <= confidence <= 1):
                    selection['confidence_unusable_ids'].append(identifier)
                    continue
                if confidence < min_confidence:
                    selection['confidence_below_threshold_ids'].append(identifier)
                    continue
            geo = record['geolocation_data']
            evidence = record['json_evidence']['fields']['geolocation_data']
            if evidence['status'] != 'decoded' or not isinstance(geo, dict):
                selection['geography_unusable_ids'].append(identifier)
                continue
            country, region, city = (self._label(geo.get(key)) for key in ('country', 'region', 'city'))
            point = self._coordinates(geo)
            if country is not None and country.casefold() in excluded:
                selection['country_excluded_ids'].append(identifier)
                continue
            if not any(value is not None for value in (country, region, city, point)):
                selection['geography_unusable_ids'].append(identifier)
                continue
            selection['included_ids'].append(identifier)
            label = self._label(record['interaction_type'])
            for key, value in (('country', country), ('region', region), ('city', city),
                               ('coordinates', point), ('interaction_type', label)):
                if value is None:
                    omissions[key].append(identifier)
            if country is not None:
                countries[country] += 1
                if label is not None:
                    interactions[label][country] += 1
            if region is not None:
                regions[(country, region)].append(identifier)
            if city is not None:
                cities[(country, region, city)].append(identifier)
            if point is not None:
                coordinates.append({'record_id': identifier, 'lat': point[0], 'lon': point[1],
                    'country': country, 'city': city, 'stored_interaction_type': record['interaction_type'],
                    'ip': record['victim_ip'], 'verified': False})
        stats = {
            'countries': dict(countries.most_common()),
            'regions': [{'country': key[0], 'region': key[1], 'count': len(ids), 'source_ids': ids}
                        for key, ids in regions.items()],
            'cities': [{'country': key[0], 'region': key[1], 'city': key[2], 'count': len(ids), 'source_ids': ids}
                       for key, ids in cities.items()],
            'interaction_types': {key: dict(counts) for key, counts in interactions.items()},
            'coordinates': coordinates, 'total_countries': len(countries),
            'field_omissions': omissions, 'attacker_countries': [], 'victim_countries': [],
            'top_attacker_country': None
        }
        return {
            'schema_version': 1, 'status': 'success', 'evidence_scope': 'stored_rows_unverified',
            'generated_at': time.time(), 'case_id': case_id, 'min_confidence': min_confidence,
            'confidence_filter': 'not_applied' if min_confidence == 0 else 'stored_numeric_threshold',
            'exclude_countries': list(exclude_countries or []), 'source_records': records,
            'total_records': len(records), 'total_victims': len(selection['included_ids']),
            'selection': selection, 'geographic_stats': stats,
            'summary': {'total_countries': len(countries), 'top_countries': list(stats['countries'])[:5],
                'top_countries_scope': 'five_country_preview; complete countries in geographic_stats',
                'attacker_countries': [], 'victim_countries': [],
                'risk_assessment': {'status': 'unavailable', 'level': None,
                    'reason': 'Stored locations and labels do not establish calibrated risk.'}},
            'visualizations': {},
            'unavailable': {
                'identity': 'Stored geographic and interaction labels do not identify attackers or victims.',
                'interactive_maps': 'No offline map renderer is validated; original coordinate observations are retained.'},
            'count_scope': 'Stored rows and literal geographic/interaction claims; not unique people or verified locations.'
        }

    @staticmethod
    def _generate_html_report(report):
        """Escaped passive text; no executable markup, scripts or remote assets."""
        case = 'All cases' if report['case_id'] is None else report['case_id']
        rows = ''.join('<tr><td>' + _html_text(country) + '</td><td>' + str(count) + '</td></tr>'
                       for country, count in report['geographic_stats']['countries'].items())
        source = escape(''.join(_json_chunks(report, 64*1024**2, indent=2)))
        return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            '<title>Stored geographic observations</title></head><body>'
            '<h1>Stored geographic observations</h1><p>Case: ' + _html_text(case) + '</p>'
            '<p>Unverified stored claims. Identity and risk assessment unavailable. Interactive maps unavailable.</p>'
            '<p>Selected rows: ' + str(report['total_records']) + '; rows with included geographic observations: '
            + str(report['total_victims']) + '</p><table><thead><tr><th>Stored country</th><th>Rows</th></tr></thead>'
            '<tbody>' + rows + '</tbody></table><h2>Complete report and original stored sources</h2><pre>'
            + source + '</pre></body></html>')

    def _save_report(self, report, output_format):
        stem = 'geographic_report_' + uuid.uuid4().hex
        directory = _storage_directory(self.reports_dir)
        outputs = []
        if output_format in ('json', 'both'):
            outputs.append((directory / (stem + '.json'), ''.join(_json_chunks(
                report, self.db.limits['max_output_bytes'], indent=2))))
        if output_format in ('html', 'both'):
            outputs.append((directory / (stem + '.html'), self._generate_html_report(report)))
        if sum(len(content.encode('utf-8')) for _, content in outputs) > self.db.limits['max_output_bytes']:
            raise ValueError('Sentinel geographic output byte limit exceeded')
        self.db.check_report({**report, 'output_files': [str(path) for path, _ in outputs]})
        directory.mkdir(parents=True, exist_ok=True)
        _storage_directory(directory)
        attempted = []
        try:
            for path, content in outputs:
                attempted.append(str(path))
                with path.open('x', encoding='utf-8') as handle:
                    handle.write(content)
            _storage_directory(directory)
        except OSError as error:
            raise OSError(f'Geographic output failed; inspect attempted files {attempted}: {error}') from error
        return attempted


def generate_geographic_report_cli(case_id=None, min_confidence=0.0, output_format='both',
                                   exclude_countries=None):
    from .database import CampaignDatabase
    validate_geographic_options(case_id, min_confidence, exclude_countries, output_format)
    database = CampaignDatabase(**geographic_database_options(), read_only=True)
    report = GeographicReporter(database).generate_geographic_report(case_id, min_confidence,
        exclude_countries, output_format=output_format)
    print(f"Stored selected rows: {report['total_records']}; geographic observations: {report['total_victims']}")
    print('Stored claims unverified; identity/risk/interactive maps unavailable')
    for filename in report['output_files']:
        print(f'Written: {filename}')
    return report


if __name__ == '__main__':
    generate_geographic_report_cli()
