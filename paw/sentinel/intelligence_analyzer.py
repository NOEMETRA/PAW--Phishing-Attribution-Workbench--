# paw/sentinel/intelligence_analyzer.py
"""
Stored-source reports; automatic identity/risk attribution and in-place enrichment are unavailable.
"""
import time
import json
from typing import List, Dict, Any, Optional
from .database import CampaignDatabase
from .config import _bounded_report, _require_active


class IntelligenceAnalyzer:
    """Describe stored unverified observations without identifying people or operators."""

    def __init__(self, db_path: str = "sentinel.db", use_proxy: bool = True, *, read_only: bool = False, limits=None):
        self.db = CampaignDatabase(db_path, read_only=read_only, limits=limits)
        self.ip_analyzer = None
        if not read_only:
            from .ip_analyzer import IPAnalyzer
            self.ip_analyzer = IPAnalyzer(use_proxy=use_proxy)

    def analyze_unanalyzed_victims(self, max_workers=3, case_id=None):
        """Automatic relabeling/publication has no validated versioned evidence contract."""
        _require_active()
        raise NotImplementedError('Automatic Sentinel victim analysis/publication is unavailable; collect explicit unverified observations with IPAnalyzer')

    def _analyze_single_victim(self, victim):
        _require_active()
        raise NotImplementedError('Automatic replacement of stored victim evidence is unavailable')

    def _update_attacker_correlations(self, case_id=None):
        _require_active()
        raise NotImplementedError('Stored address groups do not establish attackers; automatic attribution publication is unavailable')

    @_bounded_report
    def generate_intelligence_report(self, case_id: str = None) -> Dict[str, Any]:
        """Describe selected stored rows without inferring identity or risk."""
        records = self.db.get_forensic_victim_intelligence(case_id)
        # Match the strict export boundary: unsupported native SQLite values
        # abort, rather than being stringified, dropped or made healthy defaults.
        json.dumps(records, allow_nan=False)
        analyzed = [r for r in records if r['analyzed_status'] == 'analyzed']
        numeric_ids, unusable_scores, threshold_ids = [], [], []
        risk_ids, unusable_risks, country_ids, unusable_countries = [], [], [], []
        risk_stats, geo_stats, status_stats, unusable_statuses = {}, {}, {}, []
        for record in records:
            identifier = record['id']
            status = record['analyzed_status']
            if isinstance(status, str):
                status_stats[status] = status_stats.get(status, 0) + 1
            else:
                unusable_statuses.append(identifier)
            score = record['risk_score']
            numeric = isinstance(score, (int, float)) and not isinstance(score, bool)
            if numeric:
                numeric_ids.append(identifier)
                if score >= 7:
                    threshold_ids.append(identifier)
            else:
                unusable_scores.append(identifier)
            if status != 'analyzed':
                continue
            if numeric:
                key = str(score)
                risk_stats[key] = risk_stats.get(key, 0) + 1
                risk_ids.append(identifier)
            else:
                unusable_risks.append(identifier)
            geo = record['geolocation_data']
            source = record['json_evidence']['fields']['geolocation_data']
            country = geo.get('country') if isinstance(geo, dict) else None
            if source['status'] == 'decoded' and isinstance(country, str) and country.strip():
                geo_stats[country] = geo_stats.get(country, 0) + 1
                country_ids.append(identifier)
            else:
                unusable_countries.append(identifier)

        return {
            'schema_version': 1,
            'status': 'success',
            'evidence_scope': 'stored_rows_unverified',
            'generated_at': time.time(),
            'case_id': case_id,
            'source_records': records,
            'summary': {
                'total_victims': len(records),
                'analyzed_victims': len(analyzed),
                'stored_score_at_least_7': len(threshold_ids),
                'high_risk_victims': None,
                'recent_victims_24h': None
            },
            'summary_scope': 'Stored row count, literal analyzed status and numeric score threshold; not unique people or verified analysis/risk.',
            'status_breakdown': status_stats,
            'attacker_infrastructure': [],
            'geographic_distribution': geo_stats,
            'risk_distribution': risk_stats,
            'aggregation_evidence': {
                'status_breakdown': {'source_field': 'analyzed_status',
                    'unusable_ids': unusable_statuses},
                'stored_score_at_least_7': {'source_field': 'risk_score',
                    'numeric_ids': numeric_ids, 'counted_ids': threshold_ids,
                    'unusable_ids': unusable_scores},
                'risk_distribution': {'source_field': 'risk_score',
                    'scope': 'rows_with_stored_analyzed_status', 'counted_ids': risk_ids,
                    'unusable_ids': unusable_risks},
                'geographic_distribution': {'source_field': 'geolocation_data.country',
                    'scope': 'rows_with_stored_analyzed_status', 'counted_ids': country_ids,
                    'unusable_ids': unusable_countries, 'verified': False}
            },
            'recommendations': [],
            'unavailable': {
                'high_risk_victims': 'Stored scores are not a calibrated risk assessment.',
                'recent_victims_24h': 'No validated timestamp interpretation is defined; original created_at values are retained.',
                'attacker_infrastructure': 'IP similarity, location and stored correlation labels do not establish attacker infrastructure.',
                'recommendations': 'No operational action is justified by these unverified stored claims.'
            }
        }

    @_bounded_report
    def export_forensic_data(self, case_id: str = None) -> Dict[str, Any]:
        """Export stored claims with their source; no authentication or custody claim."""
        if case_id is not None and not isinstance(case_id, str):
            raise TypeError("case_id must be a string or None")
        victims = self.db.get_forensic_victim_intelligence(case_id)

        # Prepare forensic export
        forensic_data = {
            'schema_version': 1,
            'evidence_scope': 'stored_rows_unverified',
            'chain_of_custody': 'not_established',
            'export_time': time.time(),
            'case_id': case_id,
            'total_records': len(victims),
            'data_integrity': {'algorithm': 'sha256', 'scope': 'victims',
                               'serialization': 'json_sorted_keys_ascii_compact_v1'},
            'victims': []
        }

        for victim in victims:
            # Keep compatibility projections beside the complete named reader
            # record, including exact typed JSON source and decoding outcomes.
            forensic_victim = {
                'id': victim['id'],
                'victim_ip': victim['victim_ip'],
                'click_time': victim['click_time'],
                'phishing_url': victim['phishing_url'],
                'risk_score': victim['risk_score'],
                'geolocation': victim.get('geolocation_data', {}),
                'analyzed_status': victim['analyzed_status'],
                'stored_record': victim,
                'evidence_chain': {
                    'captured_at': victim['created_at'],
                    'analyzed_at': victim['updated_at'],
                    'analysis_method': None,
                    'scope': 'stored_timestamp_aliases',
                    'source_fields': {'captured_at': 'created_at', 'analyzed_at': 'updated_at'},
                    'verified': False
                }
            }
            forensic_data['victims'].append(forensic_victim)

        forensic_data['data_integrity_hash'] = self._calculate_integrity_hash(forensic_data['victims'])
        return forensic_data

    def _calculate_integrity_hash(self, victims: List[Dict[str, Any]]) -> str:
        """Digest the exported victims list; this does not establish provenance."""
        import hashlib
        payload = json.dumps(victims, sort_keys=True, ensure_ascii=True,
                             separators=(',', ':'), allow_nan=False).encode('ascii')
        return hashlib.sha256(payload).hexdigest()

    def _stored_interaction_rows(self, case_id):
        records = self.db.get_forensic_victim_intelligence(case_id)
        json.dumps(records, allow_nan=False)
        return records

    @staticmethod
    def _usable_stored_confidence(value):
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and 0 <= value <= 1)

    @_bounded_report
    def get_interaction_statistics(self, case_id: str = None) -> Dict[str, Any]:
        """Describe complete selected stored labels, without identity inference."""
        records = self._stored_interaction_rows(case_id)
        label_ids, unusable_labels, classified_ids = {}, [], []
        numeric_ids, unusable_confidences, candidate_ids, suspicious_ids = [], [], [], []
        for record in records:
            identifier, label = record['id'], record['interaction_type']
            confidence = record['interaction_confidence']
            usable_label = isinstance(label, str) and bool(label.strip())
            if usable_label:
                label_ids.setdefault(label, []).append(identifier)
                if label != 'unknown':
                    classified_ids.append(identifier)
            else:
                unusable_labels.append(identifier)
            numeric = self._usable_stored_confidence(confidence)
            (numeric_ids if numeric else unusable_confidences).append(identifier)
            if label in ('attacker_test', 'potential_attacker') and numeric and confidence >= 0.7:
                candidate_ids.append(identifier)
            if label in ('automated_or_suspicious', 'suspicious_ip'):
                suspicious_ids.append(identifier)
        return {
            'schema_version': 1, 'status': 'success', 'generated_at': time.time(),
            'case_id': case_id, 'evidence_scope': 'stored_rows_unverified',
            'source_records': records, 'total_interactions': len(records),
            'classified_interactions': len(classified_ids),
            'interaction_types': {label: len(ids) for label, ids in label_ids.items()},
            'stored_candidate_score_at_least_0_7': len(candidate_ids),
            'stored_suspicious_label_rows': len(suspicious_ids),
            'aggregation_evidence': {
                'interaction_types': {'source_field': 'interaction_type',
                    'source_ids': label_ids, 'unusable_ids': unusable_labels},
                'classified_interactions': {'counted_ids': classified_ids,
                    'scope': 'Nonblank stored labels other than literal unknown; not verified classification.'},
                'stored_confidence': {'source_field': 'interaction_confidence',
                    'numeric_0_to_1_ids': numeric_ids, 'unusable_ids': unusable_confidences},
                'stored_candidate_score_at_least_0_7': {'counted_ids': candidate_ids,
                    'labels': ['attacker_test', 'potential_attacker'], 'verified': False},
                'stored_suspicious_label_rows': {'counted_ids': suspicious_ids,
                    'labels': ['automated_or_suspicious', 'suspicious_ip'], 'verified': False}},
            'high_confidence_attacker_interactions': None, 'suspicious_interactions': None,
            'potential_attacker_ips': [],
            'unavailable': {
                'high_confidence_attacker_interactions': 'Stored labels/scores do not identify attackers or calibrated confidence.',
                'suspicious_interactions': 'Stored labels do not independently establish suspicious behavior.',
                'potential_attacker_ips': 'Stored IP/interaction labels do not establish attacker identity.'},
            'count_scope': 'Stored rows and literal labels/scores; not unique people or verified behavior.'}

    @_bounded_report
    def get_potential_attacker_interactions(self, case_id: str = None, min_confidence: float = 0.6) -> List[Dict[str, Any]]:
        """Legacy name: select unverified stored candidate labels and numeric scores."""
        if not self._usable_stored_confidence(min_confidence):
            raise ValueError('min_confidence must be a finite number between 0 and 1')
        records = self._stored_interaction_rows(case_id)
        labels = ('attacker_test', 'potential_attacker', 'automated_or_suspicious', 'suspicious_ip')
        candidates = []
        for record in records:
            confidence = record['interaction_confidence']
            if (record['interaction_type'] in labels and self._usable_stored_confidence(confidence)
                    and confidence >= min_confidence):
                candidates.append({
                    'id': record['id'], 'ip': record['victim_ip'],
                    'interaction_type': record['interaction_type'], 'confidence': confidence,
                    'indicators': record['interaction_indicators'], 'geolocation': record['geolocation_data'],
                    'risk_score': record['risk_score'], 'click_time': record['click_time'],
                    'case_id': record['case_id'], 'source_record': record,
                    'evidence_scope': 'stored_label_candidates_unverified', 'verified': False,
                    'selection': {'labels': list(labels), 'min_confidence': min_confidence,
                        'score_scope': 'Stored numeric score in 0..1; not calibrated confidence.'},
                    'unavailable': {'identity': 'Stored labels and scores do not establish attacker identity.',
                        'risk': 'Stored risk_score is not a calibrated risk assessment.'}})
        # Stable ties retain the reader's click_time DESC, id DESC source order.
        return sorted(candidates, key=lambda row: row['confidence'], reverse=True)

    def classify_interaction_type(self, victim_data):
        _require_active()
        if self.db.read_only:
            raise RuntimeError('Saved read-only claims cannot establish interaction identity')
        return {'type':'unknown','confidence':None,'indicators':[],'status':'unavailable','verified':False,
                'reason':'No independently validated identity or behavior model; missing fields do not establish a victim or attacker'}

    def _analyze_interaction_pattern(self, ip, ua, click_time, case_id, analysis):
        _require_active()
        return {'type':'unknown','confidence':None,'indicators':[],'status':'unavailable','verified':False,
                'reason':'Address, user-agent and timing claims do not establish interaction identity'}

    def _analyze_geographic_risk(self, geolocation):
        _require_active()
        return {'is_attacker_region':None,'confidence':None,'status':'unavailable','verified':False,
                'reason':'A country label is not attacker identity or calibrated risk'}

    def _analyze_user_agent_risk(self, ua):
        _require_active()
        return {'is_suspicious':None,'confidence':None,'indicators':[],'status':'unavailable','verified':False,
                'reason':'A supplied or absent user agent is not authenticated behavior or identity'}

    def _analyze_ip_reputation(self, ip, analysis):
        _require_active()
        return {'is_suspicious':None,'confidence':None,'indicators':[],'status':'unavailable','verified':False,
                'reason':'No authenticated/time-bound reputation source or independently calibrated model'}

    def generate_geographic_report(self, case_id: str = None, min_confidence: float = 0.0, *,
                                   output_format: str = 'both') -> Dict[str, Any]:
        """Write selected stored observations; failures do not become no-data reports."""
        from .geographic_reports import GeographicReporter
        return GeographicReporter(self.db).generate_geographic_report(case_id, min_confidence,
                                                                      output_format=output_format)

    def get_geographic_statistics(self, case_id: str = None, min_confidence: float = 0.0) -> Dict[str, Any]:
        """Same stored selection and interpretation as the report, without saving."""
        from .geographic_reports import GeographicReporter
        return GeographicReporter(self.db).get_statistics(case_id, min_confidence)
