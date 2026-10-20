#!/usr/bin/env python3
"""Legacy conclusion prototype: publication and principal APIs are unavailable.

Saved sources and prior outputs are preserved. Remaining helper algorithms are
unvalidated research code, not supported attribution, deployment or provenance
verification. See docs/legacy-conclusion-publication.md for the exact boundary.
"""
import json
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass
import argparse
import csv

UNAVAILABLE = 'Legacy conclusion publication unavailable: saved case sources and prior outputs are preserved'


@dataclass
class RealAttributionEvidence:
    evidence_type: str
    confidence: float
    scientific_basis: str
    cross_references: List[str]
    reproducibility_score: float
    forensic_integrity: str
    data_source: str


class RealScientificAttributionEngine:
    def __init__(self):
        self.evidence_standards = self.load_real_evidence_standards()

    def load_real_evidence_standards(self) -> Dict:
        """Return minimal evidence standards placeholder to make engine usable.

        This keeps the module self-contained; teams may replace with richer standards lookup.
        """
        return {}
    
    def analyze_real_attribution_evidence(self, case_data: Dict) -> List[RealAttributionEvidence]:
        """Unavailable pending sourced, validated capability and publication contracts."""
        raise RuntimeError(UNAVAILABLE)

    def analyze_real_infrastructure_dna(self, case_dir: Path) -> List[RealAttributionEvidence]:
        """Analyze REAL infrastructure DNA from actual data"""
        evidences = []
        
        # Load REAL infrastructure data
        infrastructure_data = self.load_real_infrastructure_data(case_dir)
        
        if not infrastructure_data.get('hosts'):
            return evidences
        
        # Analyze ASN patterns from REAL data
        asn_evidence = self.analyze_real_asn_patterns(infrastructure_data)
        if asn_evidence:
            evidences.append(asn_evidence)
        
        # Analyze hosting patterns from REAL data
        hosting_evidence = self.analyze_real_hosting_patterns(infrastructure_data)
        if hosting_evidence:
            evidences.append(hosting_evidence)
        
        # Analyze geographic patterns from REAL data
        geo_evidence = self.analyze_real_geographic_patterns(infrastructure_data)
        if geo_evidence:
            evidences.append(geo_evidence)
        
        return evidences

    def load_real_infrastructure_data(self, case_dir: Path) -> Dict:
        """Load REAL infrastructure data from case files"""
        infrastructure = {'hosts': [], 'asns': [], 'countries': []}
        
        # Try multiple data sources
        data_sources = [
            case_dir / "derived" / "threat_intel_enriched.csv",
            case_dir / "derived" / "host_ip_asn.csv"
        ]
        
        for data_file in data_sources:
            if data_file.exists():
                try:
                    with open(data_file, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            host_data = {
                                'host': row.get('host', ''),
                                'ip': row.get('ip', ''),
                                'asn': row.get('asn', ''),
                                'org': row.get('org', ''),
                                'asn_country': row.get('asn_country', ''),
                                'risk_score': float(row.get('risk_score', 0)) if row.get('risk_score') else 0.0
                            }
                            infrastructure['hosts'].append(host_data)
                            
                            if host_data['asn'] and host_data['asn'] not in infrastructure['asns']:
                                infrastructure['asns'].append(host_data['asn'])
                            if host_data['asn_country'] and host_data['asn_country'] not in infrastructure['countries']:
                                infrastructure['countries'].append(host_data['asn_country'])
                except Exception as e:
                    print(f"[!] Error loading infrastructure data from {data_file}: {e}")
        
        return infrastructure

    def analyze_real_asn_patterns(self, infrastructure: Dict) -> RealAttributionEvidence:
        """Analyze REAL ASN patterns for attribution"""
        asns = infrastructure.get('asns', [])
        
        if not asns:
            return None
        
        # REAL analysis of ASN patterns
        asn_diversity = len(asns)
        bulletproof_indicators = self.assess_bulletproof_indicators(infrastructure)
        
        confidence = min(asn_diversity * 0.2, 0.8)  # More ASNs = higher confidence
        if bulletproof_indicators:
            confidence = min(confidence + 0.2, 0.9)
        
        return RealAttributionEvidence(
            evidence_type="infrastructure_asn_analysis",
            confidence=confidence,
            scientific_basis="Analysis of Autonomous System Number patterns and diversity",
            cross_references=asns,
            reproducibility_score=0.85,
            forensic_integrity="high",
            data_source="threat_intel_enriched.csv"
        )

    def assess_bulletproof_indicators(self, infrastructure: Dict) -> bool:
        """Assess REAL bulletproof hosting indicators"""
        bulletproof_keywords = ['flokinet', 'maxided', 'sharktech', 'bulletproof', 'offshore']
        
        for host in infrastructure.get('hosts', []):
            org = str(host.get('org', '')).lower()
            if any(keyword in org for keyword in bulletproof_keywords):
                return True
        
        return False

    def analyze_real_hosting_patterns(self, infrastructure: Dict) -> RealAttributionEvidence:
        """Analyze REAL hosting provider patterns"""
        providers = []
        for host in infrastructure.get('hosts', []):
            org = host.get('org', '')
            if org and org not in providers:
                providers.append(org)
        
        if not providers:
            return None
        
        # REAL analysis of hosting patterns
        provider_diversity = len(providers)
        risk_scores = [h.get('risk_score', 0) for h in infrastructure.get('hosts', [])]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        confidence = min((provider_diversity * avg_risk) / 2, 0.8)
        
        return RealAttributionEvidence(
            evidence_type="hosting_provider_analysis",
            confidence=confidence,
            scientific_basis="Analysis of hosting provider patterns and risk distribution",
            cross_references=providers[:5],  # First 5 providers
            reproducibility_score=0.8,
            forensic_integrity="high",
            data_source="threat_intel_enriched.csv"
        )

    def analyze_real_geographic_patterns(self, infrastructure: Dict) -> RealAttributionEvidence:
        """Analyze REAL geographic patterns"""
        countries = infrastructure.get('countries', [])
        
        if not countries:
            return None
        
        # REAL analysis of geographic patterns
        country_diversity = len(countries)
        high_risk_countries = ['RU', 'CN', 'UA', 'BY', 'KZ']
        high_risk_count = len([c for c in countries if c in high_risk_countries])
        
        confidence = min((country_diversity * high_risk_count) / 5, 0.7)
        
        return RealAttributionEvidence(
            evidence_type="geographic_pattern_analysis",
            confidence=confidence,
            scientific_basis="Analysis of geographic distribution and high-risk country patterns",
            cross_references=countries,
            reproducibility_score=0.75,
            forensic_integrity="medium",
            data_source="threat_intel_enriched.csv"
        )

    def analyze_real_behavioral_patterns(self, case_dir: Path) -> List[RealAttributionEvidence]:
        """Analyze REAL behavioral patterns from detonation data"""
        evidences = []
        
        # Load behavioral data from requests
        requests_data = self.load_real_requests_data(case_dir)
        
        if requests_data:
            # Analyze timing patterns
            timing_evidence = self.analyze_real_timing_patterns(requests_data)
            if timing_evidence:
                evidences.append(timing_evidence)
            
            # Analyze request patterns
            request_evidence = self.analyze_real_request_patterns(requests_data)
            if request_evidence:
                evidences.append(request_evidence)
        
        return evidences

    def load_real_requests_data(self, case_dir: Path) -> List[Dict]:
        """Load REAL requests data from detonation"""
        requests = []
        requests_file = case_dir / "detonation" / "requests.jsonl"
        
        if requests_file.exists():
            try:
                with open(requests_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            request = json.loads(line.strip())
                            requests.append(request)
                        except:
                            continue
            except Exception as e:
                print(f"[!] Error loading requests data: {e}")
        
        return requests

    def analyze_real_timing_patterns(self, requests: List[Dict]) -> RealAttributionEvidence:
        """Analyze REAL timing patterns from requests"""
        if not requests:
            return None
        
        timestamps = [r.get('ts', 0) for r in requests if r.get('ts')]
        if not timestamps:
            return None
        
        # REAL analysis of timing patterns
        time_range = max(timestamps) - min(timestamps) if timestamps else 0
        request_density = len(requests) / max(time_range, 1)
        
        confidence = min(request_density * 0.1, 0.6)
        
        return RealAttributionEvidence(
            evidence_type="behavioral_timing_analysis",
            confidence=confidence,
            scientific_basis="Analysis of request timing patterns and density",
            cross_references=[f"time_range: {time_range}", f"density: {request_density:.2f}"],
            reproducibility_score=0.7,
            forensic_integrity="medium",
            data_source="requests.jsonl"
        )

    def analyze_real_request_patterns(self, requests: List[Dict]) -> RealAttributionEvidence:
        """Analyze REAL request patterns"""
        if not requests:
            return None
        
        # Analyze methods and endpoints
        methods = {}
        domains = set()
        
        for request in requests:
            method = request.get('method', '')
            url = request.get('url', '')
            
            if method:
                methods[method] = methods.get(method, 0) + 1
            
            if url:
                domain = self.extract_domain_from_url(url)
                if domain:
                    domains.add(domain)
        
        method_diversity = len(methods)
        domain_diversity = len(domains)
        
        confidence = min((method_diversity * domain_diversity) / 10, 0.65)
        
        return RealAttributionEvidence(
            evidence_type="request_pattern_analysis",
            confidence=confidence,
            scientific_basis="Analysis of HTTP methods and domain diversity patterns",
            cross_references=[f"methods: {list(methods.keys())}", f"domains: {len(domains)}"],
            reproducibility_score=0.75,
            forensic_integrity="medium",
            data_source="requests.jsonl"
        )

    def extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ""

    def analyze_real_technical_artifacts(self, case_dir: Path) -> List[RealAttributionEvidence]:
        """Analyze REAL technical artifacts"""
        evidences = []
        
        # Analyze kit artifacts if available
        kit_evidence = self.analyze_real_kit_artifacts(case_dir)
        if kit_evidence:
            evidences.extend(kit_evidence)
        
        return evidences

    def analyze_real_kit_artifacts(self, case_dir: Path) -> List[RealAttributionEvidence]:
        """Analyze REAL phishing kit artifacts"""
        evidences = []
        kit_dir = case_dir / "detonation" / "phishing_kit"
        
        if not kit_dir.exists():
            return evidences
        
        # Analyze file structure and patterns
        file_patterns = self.analyze_real_file_patterns(kit_dir)
        if file_patterns:
            evidences.append(file_patterns)
        
        # Analyze code patterns
        code_patterns = self.analyze_real_code_patterns(kit_dir)
        if code_patterns:
            evidences.append(code_patterns)
        
        return evidences

    def analyze_real_file_patterns(self, kit_dir: Path) -> RealAttributionEvidence:
        """Analyze REAL file patterns in phishing kit"""
        file_extensions = {}
        total_files = 0
        
        for file_path in kit_dir.rglob('*'):
            if file_path.is_file():
                total_files += 1
                ext = file_path.suffix.lower()
                file_extensions[ext] = file_extensions.get(ext, 0) + 1
        
        if total_files == 0:
            return None
        
        # REAL analysis of file patterns
        extension_diversity = len(file_extensions)
        confidence = min(extension_diversity * 0.1, 0.5)
        
        return RealAttributionEvidence(
            evidence_type="file_structure_analysis",
            confidence=confidence,
            scientific_basis="Analysis of file structure and extension patterns in phishing kit",
            cross_references=[f"extensions: {list(file_extensions.keys())}", f"total_files: {total_files}"],
            reproducibility_score=0.8,
            forensic_integrity="high",
            data_source="phishing_kit"
        )

    def analyze_real_code_patterns(self, kit_dir: Path) -> RealAttributionEvidence:
        """Analyze REAL code patterns in phishing kit"""
        code_files = list(kit_dir.rglob('*.js')) + list(kit_dir.rglob('*.php')) + list(kit_dir.rglob('*.html'))
        
        if not code_files:
            return None
        
        # REAL analysis of code file patterns
        file_types = set()
        for file_path in code_files:
            file_types.add(file_path.suffix)
        
        confidence = min(len(file_types) * 0.2, 0.6)
        
        return RealAttributionEvidence(
            evidence_type="code_file_analysis",
            confidence=confidence,
            scientific_basis="Analysis of code file types and distribution in phishing kit",
            cross_references=[f"file_types: {list(file_types)}", f"total_code_files: {len(code_files)}"],
            reproducibility_score=0.75,
            forensic_integrity="high",
            data_source="phishing_kit"
        )

    def generate_real_confidence_matrix(self, evidences: List[RealAttributionEvidence]) -> Dict:
        """Unavailable pending sourced, validated capability and publication contracts."""
        raise RuntimeError(UNAVAILABLE)

    def calculate_real_overall_confidence(self, evidences: List[RealAttributionEvidence]) -> float:
        """Calculate REAL overall confidence from actual evidence"""
        if not evidences:
            return 0.0
        
        # Weighted average based on evidence type and reproducibility
        weighted_scores = []
        
        for evidence in evidences:
            weight = self.get_real_evidence_weight(evidence.evidence_type)
            score = evidence.confidence * evidence.reproducibility_score * weight
            weighted_scores.append(score)
        
        return sum(weighted_scores) / len(weighted_scores) if weighted_scores else 0.0

    def get_real_evidence_weight(self, evidence_type: str) -> float:
        """Get REAL weight for different evidence types"""
        weights = {
            'infrastructure_asn_analysis': 1.0,
            'hosting_provider_analysis': 0.9,
            'geographic_pattern_analysis': 0.8,
            'behavioral_timing_analysis': 0.7,
            'request_pattern_analysis': 0.7,
            'file_structure_analysis': 0.6,
            'code_file_analysis': 0.6
        }
        
        return weights.get(evidence_type, 0.5)

    def breakdown_real_evidence_strength(self, evidences: List[RealAttributionEvidence]) -> Dict:
        """Break down REAL evidence strength by category"""
        categories = {}
        
        for evidence in evidences:
            category = evidence.evidence_type
            if category not in categories:
                categories[category] = {
                    'count': 0,
                    'average_confidence': 0,
                    'total_reproducibility': 0,
                    'data_sources': set()
                }
            
            categories[category]['count'] += 1
            categories[category]['average_confidence'] += evidence.confidence
            categories[category]['total_reproducibility'] += evidence.reproducibility_score
            categories[category]['data_sources'].add(evidence.data_source)
        
        # Calculate averages
        for category in categories:
            count = categories[category]['count']
            categories[category]['average_confidence'] /= count
            categories[category]['total_reproducibility'] /= count
            categories[category]['data_sources'] = list(categories[category]['data_sources'])
        
        return categories

    def calculate_real_scientific_validation(self, evidences: List[RealAttributionEvidence]) -> float:
        """Calculate REAL scientific validation score"""
        if not evidences:
            return 0.0
        
        validation_scores = []
        
        for evidence in evidences:
            score = (evidence.confidence + evidence.reproducibility_score) / 2
            if evidence.forensic_integrity == "high":
                score *= 1.2
            validation_scores.append(score)
        
        return sum(validation_scores) / len(validation_scores)

    def assess_real_forensic_integrity(self, evidences: List[RealAttributionEvidence]) -> float:
        """Assess REAL forensic integrity of evidence"""
        if not evidences:
            return 0.0
        
        integrity_scores = {
            "high": 1.0,
            "medium": 0.7,
            "low": 0.4
        }
        
        scores = [integrity_scores.get(evidence.forensic_integrity, 0.5) for evidence in evidences]
        return sum(scores) / len(scores)

    def calculate_real_reproducibility(self, evidences: List[RealAttributionEvidence]) -> Dict:
        """Calculate REAL reproducibility metrics"""
        if not evidences:
            return {'average_score': 0.0, 'reproducible_evidence_count': 0}
        
        reproducibility_scores = [evidence.reproducibility_score for evidence in evidences]
        
        return {
            'average_score': sum(reproducibility_scores) / len(reproducibility_scores),
            'reproducible_evidence_count': len([s for s in reproducibility_scores if s > 0.7]),
            'total_evidence_count': len(evidences)
        }

    def determine_real_confidence_level(self, confidence_score: float) -> str:
        """Determine REAL confidence level based on score"""
        if confidence_score >= 0.8:
            return "HIGH"
        elif confidence_score >= 0.6:
            return "MEDIUM"
        elif confidence_score >= 0.4:
            return "LOW"
        else:
            return "VERY_LOW"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Attribution, '
               'countermeasures and dossier publication need validated source '
               'and publication contracts; no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.add_argument('--output', '-o', help='Legacy output path; no file will be created or overwritten')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == "__main__":
    import sys
    sys.exit(main())

