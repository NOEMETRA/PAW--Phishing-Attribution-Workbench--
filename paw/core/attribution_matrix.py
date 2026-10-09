# attribution_matrix.py - Unified Attribution Matrix for Operator Hypothesis Generation
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class AttributionHypothesis:
    """Represents a single attribution hypothesis"""
    operator_name: str
    confidence_score: float
    evidence_count: int
    evidence_types: List[str]
    correlation_keys: List[str]
    risk_level: str
    last_updated: datetime.datetime
    supporting_evidence: Dict[str, Any]

class AttributionMatrix:
    """Unified attribution matrix that correlates all enrichment data"""

    def __init__(self):
        self.hypotheses = []
        self.correlation_matrix = defaultdict(dict)
        self.evidence_database = {}
        self.confidence_thresholds = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }

        # Known operator profiles for correlation
        self.known_operators = self._load_known_operators()

    def _load_known_operators(self) -> Dict[str, Dict[str, Any]]:
        """No sourced operator dataset is configured; attribution is unavailable."""
        return {}

    def generate_attribution_matrix(self, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate unified attribution matrix from all enrichment data"""
        matrix = {
            'timestamp': datetime.datetime.now().isoformat(),
            'target_url': enrichment_data.get('url', 'unknown'),
            'correlation_matrix': {},
            'hypotheses': [],
            'operator_attribution': {'status': 'unavailable', 'reason': 'No sourced operator dataset configured'},
            'evidence_summary': {},
            'confidence_assessment': {},
            'recommendations': []
        }

        try:
            # Extract correlation keys from all enrichment sources
            correlation_keys = self._extract_all_correlation_keys(enrichment_data)

            # Build correlation matrix
            matrix['correlation_matrix'] = self._build_correlation_matrix(correlation_keys)

            # Generate hypotheses
            matrix['hypotheses'] = self._generate_hypotheses(correlation_keys)

            # Create evidence summary
            matrix['evidence_summary'] = self._create_evidence_summary(enrichment_data)

            # Assess overall confidence
            matrix['confidence_assessment'] = self._assess_confidence(matrix['hypotheses'])

            # Generate recommendations
            matrix['recommendations'] = self._generate_recommendations(matrix)

        except Exception as e:
            logger.error(f"Attribution matrix generation failed: {e}")
            matrix['errors'] = [str(e)]

        return matrix

    def _extract_all_correlation_keys(self, enrichment_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract correlation keys from all enrichment sources"""
        keys = defaultdict(list)

        # Trackers
        trackers = enrichment_data.get('trackers', {})
        for key in trackers.get('correlation_keys', []):
            keys['trackers'].append(key)

        # TLS fingerprints
        tls = enrichment_data.get('tls_fingerprints', {})
        for key in tls.get('correlation_keys', []):
            keys['tls'].append(key)

        # DNS enrichment
        dns = enrichment_data.get('dns_enrichment', {})
        for key in dns.get('correlation_keys', []):
            keys['dns'].append(key)

        # Redirect chains
        redirects = enrichment_data.get('redirect_chains', {})
        for key in redirects.get('correlation_keys', []):
            keys['redirects'].append(key)

        # JA3 fingerprints
        ja3 = enrichment_data.get('ja3_fingerprints', {})
        for key in ja3.get('correlation_keys', []):
            keys['ja3'].append(key)

        # Form analysis
        forms = enrichment_data.get('form_analysis', {})
        for key in forms.get('correlation_keys', []):
            keys['forms'].append(key)

        return dict(keys)

    def _build_correlation_matrix(self, correlation_keys: Dict[str, List[str]]) -> Dict[str, Any]:
        """Build correlation matrix showing relationships between enrichment sources"""
        matrix = {
            'source_correlations': defaultdict(dict),
            'key_frequency': defaultdict(int),
            'cross_source_links': []
        }

        # Count key frequencies across all sources
        all_keys = []
        for source_keys in correlation_keys.values():
            all_keys.extend(source_keys)

        for key in all_keys:
            matrix['key_frequency'][key] += 1

        # Find correlations between sources
        sources = list(correlation_keys.keys())
        for i, source1 in enumerate(sources):
            for j, source2 in enumerate(sources):
                if i != j:
                    keys1 = set(correlation_keys[source1])
                    keys2 = set(correlation_keys[source2])

                    overlap = keys1.intersection(keys2)
                    if overlap:
                        matrix['source_correlations'][source1][source2] = {
                            'overlap_count': len(overlap),
                            'overlap_keys': list(overlap),
                            'correlation_strength': len(overlap) / max(len(keys1), len(keys2))
                        }

                        matrix['cross_source_links'].append({
                            'source1': source1,
                            'source2': source2,
                            'shared_keys': list(overlap),
                            'strength': len(overlap) / max(len(keys1), len(keys2))
                        })

        return dict(matrix)

    def _generate_hypotheses(self, correlation_keys: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Generate attribution hypotheses based on correlation patterns"""
        hypotheses = []

        # Score each known operator
        for operator_name, profile in self.known_operators.items():
            hypothesis = self._score_operator_hypothesis(operator_name, profile, correlation_keys)
            if hypothesis['confidence_score'] > 0.1:  # Only include hypotheses with some evidence
                hypotheses.append(hypothesis)

        # Sort by confidence score
        hypotheses.sort(key=lambda x: x['confidence_score'], reverse=True)

        return hypotheses

    def _score_operator_hypothesis(self, operator_name: str, profile: Dict[str, Any],
                                 correlation_keys: Dict[str, List[str]]) -> Dict[str, Any]:
        """Score how well evidence matches a known operator profile"""
        evidence_matches = []
        total_evidence_types = 0
        matched_evidence_types = 0

        # Check each evidence category
        evidence_categories = ['indicators', 'infrastructure', 'payment_processors', 'tls_patterns']

        for category in evidence_categories:
            profile_items = profile.get(category, [])
            if profile_items:
                total_evidence_types += 1

                # Check if any profile items appear in correlation keys
                category_matches = []
                for item in profile_items:
                    for source_keys in correlation_keys.values():
                        for key in source_keys:
                            if item.lower() in key.lower():
                                category_matches.append({
                                    'matched_item': item,
                                    'correlation_key': key,
                                    'category': category
                                })

                if category_matches:
                    matched_evidence_types += 1
                    evidence_matches.extend(category_matches)

        # Calculate confidence score
        if total_evidence_types > 0:
            base_confidence = matched_evidence_types / total_evidence_types
        else:
            base_confidence = 0.0

        # Boost confidence for multiple matches in same category
        category_boost = 0.0
        category_counts = defaultdict(int)
        for match in evidence_matches:
            category_counts[match['category']] += 1

        for count in category_counts.values():
            if count > 1:
                category_boost += 0.1 * (count - 1)  # Bonus for multiple matches

        confidence_score = min(1.0, base_confidence + category_boost)

        # Determine risk level
        risk_level = profile.get('risk_level', 'unknown')
        if confidence_score > 0.8:
            risk_level = 'critical'
        elif confidence_score > 0.6:
            risk_level = 'high'
        elif confidence_score > 0.4:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'operator_name': operator_name,
            'confidence_score': confidence_score,
            'evidence_count': len(evidence_matches),
            'evidence_types': list(set(m['category'] for m in evidence_matches)),
            'correlation_keys': [m['correlation_key'] for m in evidence_matches],
            'risk_level': risk_level,
            'last_updated': datetime.datetime.now().isoformat(),
            'supporting_evidence': {
                'matches': evidence_matches,
                'profile_indicators': profile,
                'scoring_breakdown': {
                    'base_confidence': base_confidence,
                    'category_boost': category_boost,
                    'total_evidence_types': total_evidence_types,
                    'matched_evidence_types': matched_evidence_types
                }
            }
        }

    def _create_evidence_summary(self, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of all evidence collected"""
        summary = {
            'enrichment_sources': {},
            'total_evidence_items': 0,
            'evidence_by_category': defaultdict(int),
            'high_confidence_findings': [],
            'suspicious_indicators': []
        }

        # Summarize each enrichment source
        source_mapping = {
            'trackers': 'trackers',
            'tls_fingerprints': 'tls_fingerprints',
            'dns_enrichment': 'dns_enrichment',
            'redirect_chains': 'redirect_chains',
            'ja3_fingerprints': 'ja3_fingerprints',
            'form_analysis': 'form_analysis'
        }

        for source_key, source_name in source_mapping.items():
            if source_key in enrichment_data:
                source_data = enrichment_data[source_key]
                source_summary = self._summarize_enrichment_source(source_data, source_name)
                summary['enrichment_sources'][source_name] = source_summary
                summary['total_evidence_items'] += source_summary.get('evidence_count', 0)

                # Collect suspicious indicators
                suspicious = source_data.get('suspicious_indicators', [])
                if suspicious:
                    summary['suspicious_indicators'].extend(suspicious)

        # Categorize evidence
        for source_summary in summary['enrichment_sources'].values():
            for evidence_type in source_summary.get('evidence_types', []):
                summary['evidence_by_category'][evidence_type] += 1

        return dict(summary)

    def _summarize_enrichment_source(self, source_data: Dict[str, Any], source_name: str) -> Dict[str, Any]:
        """Summarize a single enrichment source"""
        summary = {
            'evidence_count': 0,
            'evidence_types': [],
            'key_findings': [],
            'confidence_level': 'unknown'
        }

        if source_name == 'trackers':
            trackers = source_data.get('trackers', [])
            summary['evidence_count'] = len(trackers)
            summary['evidence_types'] = ['analytics_tracking']
            summary['key_findings'] = [t.get('tracker_type', 'unknown') for t in trackers[:5]]

        elif source_name == 'tls_fingerprints':
            certs = source_data.get('certificates', [])
            summary['evidence_count'] = len(certs)
            summary['evidence_types'] = ['tls_certificate', 'spki_fingerprint']
            if certs:
                summary['key_findings'] = [c.get('spki_hash', 'unknown')[:16] + '...' for c in certs[:3]]

        elif source_name == 'dns_enrichment':
            records = source_data.get('records', {})
            summary['evidence_count'] = sum(len(recs) for recs in records.values())
            summary['evidence_types'] = ['dns_record', 'nameserver', 'hosting_provider']
            provider = source_data.get('hosting_provider', {}).get('detected_provider')
            if provider:
                summary['key_findings'] = [f"Hosting: {provider}"]

        elif source_name == 'redirect_chains':
            chain = source_data.get('chain', [])
            summary['evidence_count'] = len(chain)
            summary['evidence_types'] = ['redirect_chain', 'utm_tracking']
            if chain:
                summary['key_findings'] = [f"Chain length: {len(chain)}"]

        elif source_name == 'ja3_fingerprints':
            ja3_fps = source_data.get('ja3_fingerprints', [])
            summary['evidence_count'] = len(ja3_fps)
            summary['evidence_types'] = ['ja3_fingerprint', 'client_identification']
            if ja3_fps:
                summary['key_findings'] = [fp.get('hash', 'unknown')[:16] + '...' for fp in ja3_fps[:3]]

        elif source_name == 'form_analysis':
            forms = source_data.get('forms', [])
            summary['evidence_count'] = len(forms)
            summary['evidence_types'] = ['form_field', 'payment_processor']
            processors = source_data.get('payment_processors', [])
            if processors:
                summary['key_findings'] = [p.get('processor', 'unknown') for p in processors]

        # Determine confidence level
        if summary['evidence_count'] > 10:
            summary['confidence_level'] = 'high'
        elif summary['evidence_count'] > 5:
            summary['confidence_level'] = 'medium'
        elif summary['evidence_count'] > 0:
            summary['confidence_level'] = 'low'

        return summary

    def _assess_confidence(self, hypotheses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall confidence in attribution"""
        assessment = {
            'overall_confidence': 'low',
            'top_hypothesis_score': 0.0,
            'hypothesis_count': len(hypotheses),
            'evidence_breadth': 0,
            'confidence_factors': []
        }

        if hypotheses:
            top_score = hypotheses[0]['confidence_score']
            assessment['top_hypothesis_score'] = top_score

            # Assess confidence level
            if top_score > 0.8:
                assessment['overall_confidence'] = 'high'
            elif top_score > 0.6:
                assessment['overall_confidence'] = 'medium'
            elif top_score > 0.4:
                assessment['overall_confidence'] = 'low'
            else:
                assessment['overall_confidence'] = 'insufficient_evidence'

            # Assess evidence breadth
            evidence_types = set()
            for hyp in hypotheses:
                evidence_types.update(hyp.get('evidence_types', []))

            assessment['evidence_breadth'] = len(evidence_types)

            # Confidence factors
            factors = []
            if assessment['evidence_breadth'] >= 3:
                factors.append('broad_evidence_coverage')
            if top_score > 0.7:
                factors.append('strong_top_hypothesis')
            if len(hypotheses) > 1 and hypotheses[1]['confidence_score'] > 0.3:
                factors.append('multiple_competing_hypotheses')
            if assessment['evidence_breadth'] < 2:
                factors.append('limited_evidence_breadth')

            assessment['confidence_factors'] = factors

        return assessment

    def _generate_recommendations(self, matrix: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on attribution analysis"""
        recommendations = []

        confidence = matrix.get('confidence_assessment', {})
        hypotheses = matrix.get('hypotheses', [])

        if confidence.get('overall_confidence') == 'high':
            recommendations.append("High confidence attribution achieved - proceed with targeted response")
        elif confidence.get('overall_confidence') == 'medium':
            recommendations.append("Medium confidence - gather additional evidence before action")
        else:
            recommendations.append("Low confidence - requires additional investigation")

        if confidence.get('evidence_breadth', 0) < 3:
            recommendations.append("Limited evidence breadth - consider additional enrichment sources")

        if hypotheses and len(hypotheses) > 1:
            score_diff = hypotheses[0]['confidence_score'] - hypotheses[1]['confidence_score']
            if score_diff < 0.2:
                recommendations.append("Multiple competing hypotheses - focus on differentiating evidence")

        # Source-specific recommendations
        evidence_summary = matrix.get('evidence_summary', {})
        sources = evidence_summary.get('enrichment_sources', {})

        if 'tls_fingerprints' not in sources or not sources['tls_fingerprints'].get('evidence_count'):
            recommendations.append("Consider TLS certificate analysis for additional attribution evidence")

        if 'dns_enrichment' not in sources or not sources['dns_enrichment'].get('evidence_count'):
            recommendations.append("DNS analysis may provide valuable infrastructure attribution clues")

        return recommendations

    def update_hypotheses_with_new_evidence(self, existing_matrix: Dict[str, Any],
                                          new_enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing attribution matrix with new evidence"""
        # Merge new enrichment data
        updated_data = existing_matrix.copy()
        updated_data.update(new_enrichment_data)

        # Regenerate matrix with combined data
        return self.generate_attribution_matrix(updated_data)

def generate_attribution_matrix(enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for attribution matrix generation"""
    matrix = AttributionMatrix()
    return matrix.generate_attribution_matrix(enrichment_data)
