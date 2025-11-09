# paw/sentinel/intelligence_analyzer.py
"""
Intelligence Analyzer - Orchestrates victim IP analysis and attacker correlation.
"""
import time
import json
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .database import CampaignDatabase
from .ip_analyzer import IPAnalyzer
from .geographic_reports import GeographicReporter


class IntelligenceAnalyzer:
    """Analyze victim intelligence to identify attacker infrastructure."""

    def __init__(self, db_path: str = "sentinel.db", use_proxy: bool = True):
        self.db = CampaignDatabase(db_path)
        self.ip_analyzer = IPAnalyzer(use_proxy=use_proxy)

    def analyze_unanalyzed_victims(self, max_workers: int = 3, case_id: str = None) -> Dict[str, Any]:
        """Analyze all unanalyzed victims and update database."""
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

    def generate_intelligence_report(self, case_id: str = None) -> Dict[str, Any]:
        """Generate comprehensive intelligence report."""
        # Get victims, optionally filtered by case
        all_victims = self.db.get_victim_intelligence()
        if case_id:
            all_victims = [v for v in all_victims if v['case_id'] == case_id]

        # Calculate statistics
        total_victims = len(all_victims)
        analyzed_victims = len([v for v in all_victims if v['analyzed_status'] == 'analyzed'])
        high_risk_victims = len([v for v in all_victims if v.get('risk_score', 0) >= 7])
        recent_victims_24h = len([v for v in all_victims if self._is_recent_victim(v.get('created_at', ''))])

        # Status breakdown
        status_stats = {}
        for victim in all_victims:
            status = victim.get('analyzed_status', 'unknown')
            status_stats[status] = status_stats.get(status, 0) + 1

        # Risk distribution
        risk_stats = {}
        for victim in all_victims:
            if victim['analyzed_status'] == 'analyzed':
                risk = victim.get('risk_score', 0)
                risk_stats[risk] = risk_stats.get(risk, 0) + 1

        correlations = self.db.get_attacker_correlations()
        # Filter correlations by case if specified
        if case_id:
            # This is a simplified filter - in production you'd want to filter correlations by victims in the case
            pass

        # Geographic analysis
        geo_stats = {}
        for victim in [v for v in all_victims if v['analyzed_status'] == 'analyzed']:
            geo = victim.get('geolocation_data', {})
            country = geo.get('country', 'Unknown')
            if country not in geo_stats:
                geo_stats[country] = 0
            geo_stats[country] += 1

        report = {
            'generated_at': time.time(),
            'case_id': case_id,
            'summary': {
                'total_victims': total_victims,
                'analyzed_victims': analyzed_victims,
                'high_risk_victims': high_risk_victims,
                'recent_victims_24h': recent_victims_24h
            },
            'attacker_infrastructure': correlations,
            'geographic_distribution': geo_stats,
            'risk_distribution': risk_stats,
            'recommendations': self._generate_recommendations(correlations, [v for v in all_victims if v.get('risk_score', 0) >= 7])
        }

        return report

    def _generate_recommendations(self, correlations: List[Dict[str, Any]], high_risk_victims: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []

        # Network-based recommendations
        for correlation in correlations:
            if correlation['victim_count'] >= 5:
                recommendations.append(
                    f"URGENT: Investigate network {correlation['network']} - "
                    f"{correlation['victim_count']} victims from {len(correlation['countries'])} countries"
                )

        # Geographic recommendations
        if len(high_risk_victims) > 10:
            recommendations.append(
                "Scale up monitoring: High volume of suspicious activity detected"
            )

        # Risk-based recommendations
        if not correlations:
            recommendations.append(
                "Continue collecting victim data: Need more samples for correlation analysis"
            )

        return recommendations if recommendations else ["Continue monitoring and analysis"]

    def export_forensic_data(self, case_id: str = None) -> Dict[str, Any]:
        """Export victim intelligence data for forensic/legal use."""
        victims = self.db.get_victim_intelligence()
        if case_id:
            victims = [v for v in victims if v['case_id'] == case_id]

        # Prepare forensic export
        forensic_data = {
            'export_time': time.time(),
            'case_id': case_id,
            'total_records': len(victims),
            'data_integrity_hash': self._calculate_integrity_hash(victims),
            'victims': []
        }

        for victim in victims:
            # Sanitize for legal export (remove sensitive metadata)
            forensic_victim = {
                'id': victim['id'],
                'victim_ip': victim['victim_ip'],
                'click_time': victim['click_time'],
                'phishing_url': victim['phishing_url'],
                'risk_score': victim['risk_score'],
                'geolocation': victim.get('geolocation_data', {}),
                'analyzed_status': victim['analyzed_status'],
                'evidence_chain': {
                    'captured_at': victim['created_at'],
                    'analyzed_at': victim['updated_at'],
                    'analysis_method': 'automated_ip_intelligence'
                }
            }
            forensic_data['victims'].append(forensic_victim)

        return forensic_data

    def _calculate_integrity_hash(self, victims: List[Dict[str, Any]]) -> str:
        """Calculate integrity hash for forensic chain of custody."""
        import hashlib
        data_str = json.dumps(victims, sort_keys=True, default=str)
    def get_interaction_statistics(self, case_id: str = None) -> Dict[str, Any]:
        """Get statistics on classified interactions."""
        victims = self.db.get_victim_intelligence()
        if case_id:
            victims = [v for v in victims if v['case_id'] == case_id]

        # Analyze interactions
        interaction_stats = {
            'total_interactions': len(victims),
            'classified_interactions': 0,
            'interaction_types': {},
            'high_confidence_attacker_interactions': 0,
            'suspicious_interactions': 0,
            'potential_attacker_ips': []
        }

        for victim in victims:
            interaction_type = victim.get('interaction_type', 'unknown')
            confidence = victim.get('interaction_confidence', 0.0)

            if interaction_type != 'unknown':
                interaction_stats['classified_interactions'] += 1

            if interaction_type not in interaction_stats['interaction_types']:
                interaction_stats['interaction_types'][interaction_type] = 0
            interaction_stats['interaction_types'][interaction_type] += 1

            # Track high-confidence attacker interactions
            if interaction_type in ['attacker_test', 'potential_attacker'] and confidence >= 0.7:
                interaction_stats['high_confidence_attacker_interactions'] += 1
                interaction_stats['potential_attacker_ips'].append({
                    'ip': victim['victim_ip'],
                    'type': interaction_type,
                    'confidence': confidence,
                    'indicators': victim.get('interaction_indicators', [])
                })

            # Track suspicious interactions
            if interaction_type in ['automated_or_suspicious', 'suspicious_ip']:
                interaction_stats['suspicious_interactions'] += 1

        return interaction_stats

    def get_potential_attacker_interactions(self, case_id: str = None, min_confidence: float = 0.6) -> List[Dict[str, Any]]:
        """Get interactions classified as potential attacker activity."""
        victims = self.db.get_victim_intelligence()
        if case_id:
            victims = [v for v in victims if v['case_id'] == case_id]

        attacker_interactions = []
        for victim in victims:
            interaction_type = victim.get('interaction_type', 'unknown')
            confidence = victim.get('interaction_confidence', 0.0)

            if (interaction_type in ['attacker_test', 'potential_attacker', 'automated_or_suspicious', 'suspicious_ip']
                and confidence >= min_confidence):

                attacker_interactions.append({
                    'id': victim['id'],
                    'ip': victim['victim_ip'],
                    'interaction_type': interaction_type,
                    'confidence': confidence,
                    'indicators': victim.get('interaction_indicators', []),
                    'geolocation': victim.get('geolocation_data', {}),
                    'risk_score': victim.get('risk_score', 0),
                    'click_time': victim['click_time'],
                    'case_id': victim['case_id']
                })

        # Sort by confidence descending
        attacker_interactions.sort(key=lambda x: x['confidence'], reverse=True)
        return attacker_interactions

    def classify_interaction_type(self, victim_data: Dict[str, Any]) -> str:
        """Classify interaction as victim, attacker, or suspicious."""
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
        classification = {
            'type': 'victim',  # default assumption
            'confidence': 0.5,
            'indicators': []
        }

        # 1. Time-based analysis (immediate clicks after deployment)
        if self._is_suspicious_timing(click_time, case_id):
            classification['type'] = 'attacker_test'
            classification['confidence'] = max(classification['confidence'], 0.8)
            classification['indicators'].append('suspicious_timing')

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

        # 5. Behavioral analysis (future: session patterns, navigation)
        # TODO: Implement session tracking and behavioral analysis

        return classification

    def _is_suspicious_timing(self, click_time: str, case_id: str) -> bool:
        """Check if click happened suspiciously soon after campaign deployment."""
        try:
            from datetime import datetime
            click_dt = datetime.fromisoformat(click_time.replace(' ', 'T'))

            # Get campaign creation time (simplified - in production, store campaign metadata)
            # For now, assume clicks within 1 hour of "case creation" are suspicious
            # This is a placeholder - real implementation needs campaign deployment timestamps

            # Check if click is within first hour of campaign
            # This is a heuristic - attackers often test immediately
            current_hour = click_dt.hour
            if current_hour in [0, 1, 2]:  # Early morning clicks often suspicious
                return True

            return False
        except:
            return False

    def _analyze_geographic_risk(self, geolocation: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic location for attacker indicators."""
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

    def generate_geographic_report(self, case_id: str = None, min_confidence: float = 0.0) -> Dict[str, Any]:
        """Generate geographic report for analyzed victims."""
        try:
            reporter = GeographicReporter(self.db)
            return reporter.generate_geographic_report(case_id, min_confidence)
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Errore generazione report geografico: {e}',
                'case_id': case_id
            }

    def get_geographic_statistics(self, case_id: str = None, min_confidence: float = 0.0) -> Dict[str, Any]:
        """Get geographic statistics without generating full report."""
        try:
            victims = self.db.get_victim_intelligence()
            if case_id:
                victims = [v for v in victims if v.get('case_id') == case_id]

            # Filter by confidence and geolocation
            filtered_victims = []
            for victim in victims:
                confidence = victim.get('interaction_confidence', 0.0)
                if confidence >= min_confidence and victim.get('geolocation_data'):
                    filtered_victims.append(victim)

            if not filtered_victims:
                return {'total_victims': 0, 'countries': {}, 'attackers': 0, 'attacker_percentage': 0.0}

            # Basic statistics
            countries = {}
            attackers = 0

            for victim in filtered_victims:
                geo = victim.get('geolocation_data', {})
                country = geo.get('country', 'Unknown')
                countries[country] = countries.get(country, 0) + 1

                if victim.get('interaction_type') in ['attacker', 'suspicious']:
                    attackers += 1

            return {
                'total_victims': len(filtered_victims),
                'countries': countries,
                'attackers': attackers,
                'attacker_percentage': (attackers / len(filtered_victims)) * 100 if filtered_victims else 0
            }

        except Exception as e:
            return {'error': str(e)}
