# paw/sentinel/intelligence_analyzer.py
"""
Intelligence Analyzer - Orchestrates victim IP analysis and attacker correlation.
"""
import time
import json
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .database import CampaignDatabase
from .config import _bounded_report, _require_active


class IntelligenceAnalyzer:
    """Analyze victim intelligence to identify attacker infrastructure."""

    def __init__(self, db_path: str = "sentinel.db", use_proxy: bool = True, *, read_only: bool = False, limits=None):
        self.db = CampaignDatabase(db_path, read_only=read_only, limits=limits)
        self.ip_analyzer = None
        if not read_only:
            from .ip_analyzer import IPAnalyzer
            self.ip_analyzer = IPAnalyzer(use_proxy=use_proxy)

    def analyze_unanalyzed_victims(self, max_workers: int = 3, case_id: str = None) -> Dict[str, Any]:
        """Analyze all unanalyzed victims and update database."""
        _require_active()
        if self.db.read_only:
            raise RuntimeError("Saved read-only Sentinel storage cannot run IP analysis")
        victims = self.db.get_unanalyzed_victims()
        if case_id:
            victims = [v for v in victims if v['case_id'] == case_id]

        if not victims:
            message = f'No unanalyzed victims found'
            if case_id:
                message += f' for case {case_id}'
            return {'analyzed': 0, 'errors': 0, 'message': message}

        print(f"Analyzing {len(victims)} victims...")
        if case_id:
            print(f"  (filtered by case: {case_id})")

        results = {'analyzed': 0, 'errors': 0, 'high_risk': 0}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_victim = {
                executor.submit(self._analyze_single_victim, victim): victim
                for victim in victims
            }

            for future in as_completed(future_to_victim):
                victim = future_to_victim[future]
                try:
                    analysis_result = future.result()
                    if analysis_result['success']:
                        results['analyzed'] += 1
                        if analysis_result.get('risk_score', 0) >= 7:
                            results['high_risk'] += 1
                    else:
                        results['errors'] += 1
                except Exception as e:
                    print(f"Error analyzing victim {victim['id']}: {e}")
                    results['errors'] += 1

        # Update correlations after analysis
        self._update_attacker_correlations(case_id)

        results['message'] = f"Analysis complete: {results['analyzed']} analyzed, {results['errors']} errors, {results['high_risk']} high-risk victims"
        return results

    def _analyze_single_victim(self, victim: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single victim and update database."""
        _require_active()
        if self.db.read_only:
            raise RuntimeError("Saved read-only Sentinel storage cannot run IP analysis")
        try:
            # Perform IP analysis
            analysis = self.ip_analyzer.analyze_ip(victim['victim_ip'])

            # Derive risk score using database heuristics
            risk_score = self.db.calculate_risk_score(
                analysis.get('risk_indicators', []),
                analysis.get('geolocation', {}),
                analysis.get('whois', {})
            )
            analysis['risk_score'] = risk_score

            # Add victim context
            analysis['victim_context'] = {
                'phishing_url': victim['phishing_url'],
                'click_time': victim['click_time'],
                'user_agent': victim['victim_ua']
            }

            # Classify interaction type (victim vs attacker)
            victim_snapshot = dict(victim)
            victim_snapshot.update({
                'geolocation_data': analysis.get('geolocation', {}),
                'whois_data': analysis.get('whois', {}),
                'risk_score': risk_score,
                'analyzed_status': 'analyzed'
            })
            interaction_classification = self.classify_interaction_type(victim_snapshot)
            analysis['interaction_classification'] = interaction_classification

            # Update database
            success = self.db.update_victim_analysis(
                victim['id'],
                geolocation_data=analysis.get('geolocation'),
                whois_data=analysis.get('whois'),
                attacker_correlation=analysis.get('attacker_correlation'),
                risk_score=risk_score,
                analyzed_status='analyzed',
                related_ips=analysis.get('correlated_ips') or None,
                interaction_type=interaction_classification.get('type'),
                interaction_confidence=interaction_classification.get('confidence'),
                interaction_indicators=interaction_classification.get('indicators')
            )

            return {
                'success': success,
                'victim_id': victim['id'],
                'risk_score': analysis.get('risk_score', 0),
                'interaction_type': interaction_classification.get('type', 'unknown'),
                'interaction_confidence': interaction_classification.get('confidence', 0.0),
                'analysis': analysis
            }

        except Exception as e:
            return {
                'success': False,
                'victim_id': victim['id'],
                'error': str(e)
            }

    def _update_attacker_correlations(self, case_id: str = None) -> None:
        """Update attacker correlation data for all victims."""
        _require_active()
        if self.db.read_only:
            raise RuntimeError("Saved read-only Sentinel storage cannot update correlations")
        try:
            # Get all analyzed victims
            all_victims = self.db.get_victim_intelligence()
            analyzed_victims = [v for v in all_victims if v['analyzed_status'] == 'analyzed']

            # Filter by case if specified
            if case_id:
                analyzed_victims = [v for v in analyzed_victims if v['case_id'] == case_id]

            if len(analyzed_victims) < 3:
                return  # Need minimum victims for correlation

            # Extract IPs for correlation analysis
            victim_ips = [v['victim_ip'] for v in analyzed_victims]

            # Perform correlation analysis
            correlations = self.ip_analyzer.correlate_ips(victim_ips)

            # Update victims with correlation data
            for victim in analyzed_victims:
                victim_ip = victim['victim_ip']

                # Find correlations for this IP
                victim_correlations = []
                for network, ips in correlations['common_networks'].items():
                    if victim_ip in ips:
                        victim_correlations.append({
                            'type': 'network_cluster',
                            'network': network,
                            'cluster_size': len(ips),
                            'other_ips': [ip for ip in ips if ip != victim_ip]
                        })

                # Update database with correlations
                if victim_correlations:
                    correlation_data = {
                        'correlations': victim_correlations,
                        'updated_at': time.time()
                    }
                    self.db.update_victim_analysis(
                        victim['id'],
                        attacker_correlation=correlation_data
                    )

        except Exception as e:
            print(f"Error updating correlations: {e}")

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

    def classify_interaction_type(self, victim_data: Dict[str, Any]) -> str:
        """Classify interaction as victim, attacker, or suspicious."""
        if self.db.read_only:
            raise RuntimeError('Saved read-only claims cannot establish interaction identity')
        _require_active()
        ip = victim_data.get('victim_ip', '')
        ua = victim_data.get('victim_ua', '')
        click_time = victim_data.get('click_time', '')
        case_id = victim_data.get('case_id', '')

        # Get analysis data if available
        analysis = {}
        if victim_data.get('analyzed_status') == 'analyzed':
            analysis = {
                'geolocation': victim_data.get('geolocation_data', {}),
                'whois': victim_data.get('whois_data', {}),
                'risk_score': victim_data.get('risk_score', 0)
            }

        return self._analyze_interaction_pattern(ip, ua, click_time, case_id, analysis)

    def _analyze_interaction_pattern(self, ip: str, ua: str, click_time: str, case_id: str, analysis: Dict[str, Any]) -> str:
        """Analyze patterns to classify interaction type."""
        _require_active()
        classification = {
            'type': 'victim',  # default assumption
            'confidence': 0.5,
            'indicators': []
        }

        classification['timing_analysis'] = {'status': 'unavailable', 'reason': 'Deployment timestamp not recorded'}

        # 2. Geographic analysis (attacker locations)
        geo_risk = self._analyze_geographic_risk(analysis.get('geolocation', {}))
        if geo_risk['is_attacker_region']:
            classification['type'] = 'potential_attacker'
            classification['confidence'] = max(classification['confidence'], geo_risk['confidence'])
            classification['indicators'].append(f"high_risk_country_{geo_risk['country']}")

        # 3. User agent analysis (automated tools, suspicious patterns)
        ua_risk = self._analyze_user_agent_risk(ua)
        if ua_risk['is_suspicious']:
            classification['type'] = 'automated_or_suspicious'
            classification['confidence'] = max(classification['confidence'], ua_risk['confidence'])
            classification['indicators'].extend(ua_risk['indicators'])

        # 4. IP reputation analysis
        ip_risk = self._analyze_ip_reputation(ip, analysis)
        if ip_risk['is_suspicious']:
            classification['type'] = 'suspicious_ip'
            classification['confidence'] = max(classification['confidence'], ip_risk['confidence'])
            classification['indicators'].extend(ip_risk['indicators'])

        classification['behavioral_analysis'] = {'status': 'unavailable', 'reason': 'Session tracking not implemented'}

        return classification

    def _analyze_geographic_risk(self, geolocation: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic location for attacker indicators."""
        _require_active()
        country = geolocation.get('country', '').upper()
        country_code = geolocation.get('country_code', '')

        # High-risk countries for attackers (different from victim risk)
        attacker_countries = {
            'RU': {'risk': 0.9, 'reason': 'major_phishing_source'},
            'CN': {'risk': 0.8, 'reason': 'cybercrime_hotspot'},
            'IN': {'risk': 0.7, 'reason': 'business_email_compromise_source'},
            'NG': {'risk': 0.8, 'reason': '419_scam_origin'},
            'VN': {'risk': 0.7, 'reason': 'phishing_farms'},
            'RO': {'risk': 0.8, 'reason': 'bulletproof_hosting'},
            'UA': {'risk': 0.6, 'reason': 'cybercrime_activities'},
            'BY': {'risk': 0.7, 'reason': 'russian_sphere_influence'}
        }

        if country_code in attacker_countries:
            return {
                'is_attacker_region': True,
                'confidence': attacker_countries[country_code]['risk'],
                'country': country_code,
                'reason': attacker_countries[country_code]['reason']
            }

        return {
            'is_attacker_region': False,
            'confidence': 0.1,
            'country': country_code
        }

    def _analyze_user_agent_risk(self, ua: str) -> Dict[str, Any]:
        """Analyze user agent for automated tools and suspicious patterns."""
        _require_active()
        if not ua:
            return {'is_suspicious': True, 'confidence': 0.9, 'indicators': ['no_user_agent']}

        ua_lower = ua.lower()
        indicators = []
        confidence = 0.0

        # Automated tools and bots
        bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
            'headless', 'selenium', 'phantomjs', 'chrome-headless', 'puppeteer'
        ]

        for pattern in bot_patterns:
            if pattern in ua_lower:
                indicators.append(f'bot_pattern_{pattern}')
                confidence = max(confidence, 0.9)

        # Suspicious browser fingerprints
        if 'windows nt' in ua_lower and 'linux' in ua_lower:
            indicators.append('inconsistent_os_fingerprint')
            confidence = max(confidence, 0.8)

        # Very old browsers (often used by attackers)
        if 'msie 6' in ua_lower or 'msie 7' in ua_lower:
            indicators.append('ancient_browser_version')
            confidence = max(confidence, 0.7)

        # Missing common browser strings
        common_browsers = ['chrome', 'firefox', 'safari', 'edge']
        has_common_browser = any(browser in ua_lower for browser in common_browsers)
        if not has_common_browser and len(ua) < 50:  # Short, non-standard UA
            indicators.append('non_standard_user_agent')
            confidence = max(confidence, 0.6)

        return {
            'is_suspicious': len(indicators) > 0,
            'confidence': confidence,
            'indicators': indicators
        }

    def _analyze_ip_reputation(self, ip: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IP for reputation-based attacker indicators."""
        _require_active()
        indicators = []
        confidence = 0.0

        # Check if IP is from known attacker ranges
        # This would integrate with threat intelligence feeds
        suspicious_ranges = [
            '185.220.100.0/22',  # Tor exit nodes
            '91.193.75.0/24',    # Known Russian hosting
            '5.188.210.0/24',    # Russian datacenter
        ]

        try:
            from ipaddress import ip_address, ip_network
            victim_ip = ip_address(ip)

            for range_str in suspicious_ranges:
                network = ip_network(range_str)
                if victim_ip in network:
                    indicators.append(f'suspicious_range_{range_str}')
                    confidence = max(confidence, 0.8)
        except:
            pass

        # High-risk ISP analysis
        whois = analysis.get('whois', {})
        isp = whois.get('org', '').lower() if whois else ''

        high_risk_isps = [
            'contabo', 'hetzner', 'digitalocean', 'vultr', 'linode',
            'ovh', 'leaseweb', 'serverius', 'webzilla'
        ]

        for risky_isp in high_risk_isps:
            if risky_isp in isp:
                indicators.append(f'high_risk_isp_{risky_isp}')
                confidence = max(confidence, 0.7)

        # Risk score correlation
        risk_score = analysis.get('risk_score', 0)
        if risk_score >= 7:
            indicators.append('high_risk_score')
            confidence = max(confidence, 0.6)

        return {
            'is_suspicious': len(indicators) > 0,
            'confidence': confidence,
            'indicators': indicators
        }

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
