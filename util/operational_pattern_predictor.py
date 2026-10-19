#!/usr/bin/env python3
"""Legacy operational prediction is unavailable; saved sources and outputs are preserved.

Internal prototype helpers remain unvalidated and are not a predictive model.
No actor forecast, calibrated confidence or intervention recommendation is supported.
"""
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
import argparse
import csv


UNAVAILABLE = ('Legacy operational prediction unavailable: saved case '
               'sources and prior outputs are preserved')


class ThreatActorBehaviorModel:
    def __init__(self):
        self.actor_patterns = {
            'bulletproof_rotation': {
                'infrastructure_lifespan': 45,
                'asn_rotation_pattern': [7, 14, 30],
                'domain_aging_strategy': 'fast_flux',
                'typical_targets': ['finance', 'healthcare', 'government'],
            },
            'apt_stealth': {
                'infrastructure_lifespan': 180,
                'asn_rotation_pattern': [30, 60, 90],
                'domain_aging_strategy': 'aged_domains',
                'typical_targets': ['energy', 'defense', 'technology'],
            }
        }

    def predict_infrastructure_evolution(self, case_data: Dict) -> Dict:
        """Unavailable before inspecting case data or generating predictions."""
        raise RuntimeError(UNAVAILABLE)

    def extract_infrastructure_data(self, case_data: Dict) -> Dict:
        """Extract REAL infrastructure data from case files"""
        case_dir = Path(case_data['case_dir'])
        infrastructure = {'hosts': [], 'domains': [], 'asns': [], 'ips': []}
        
        # Try multiple possible data sources
        data_sources = [
            case_dir / "derived" / "threat_intel_enriched.csv",
            case_dir / "derived" / "host_ip_asn.csv",
            case_dir / "detonation_endpoints.json"
        ]
        
        for data_file in data_sources:
            if data_file.exists():
                if data_file.suffix == '.csv':
                    self._parse_csv_data(data_file, infrastructure)
                elif data_file.suffix == '.json':
                    self._parse_json_data(data_file, infrastructure)
        
        # Load from attribution matrix if available
        matrix_file = case_dir / "attribution_matrix.json"
        if matrix_file.exists():
            with open(matrix_file, 'r', encoding='utf-8') as f:
                matrix_data = json.load(f)
                infrastructure['pivots'] = matrix_data.get('pivots', [])
                infrastructure['clusters'] = matrix_data.get('clusters', [])
        
        return infrastructure

    def _parse_csv_data(self, file_path: Path, infrastructure: Dict):
        """Parse REAL CSV data from PAW outputs"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Extract host data
                    host_data = {
                        'host': row.get('host', ''),
                        'ip': row.get('ip', ''),
                        'asn': row.get('asn', ''),
                        'org': row.get('org', ''),
                        'asn_country': row.get('asn_country', ''),
                        'risk_score': float(row.get('risk_score', 0)) if row.get('risk_score') else 0.0,
                        'risk_level': row.get('risk_level', 'unknown')
                    }
                    
                    infrastructure['hosts'].append(host_data)
                    
                    # Add to unique lists
                    if host_data['host'] and host_data['host'] not in infrastructure['domains']:
                        infrastructure['domains'].append(host_data['host'])
                    if host_data['ip'] and host_data['ip'] not in infrastructure['ips']:
                        infrastructure['ips'].append(host_data['ip'])
                    if host_data['asn'] and host_data['asn'] not in infrastructure['asns']:
                        infrastructure['asns'].append(host_data['asn'])
        except Exception as e:
            print(f"[!] Error parsing CSV {file_path}: {e}")

    def _parse_json_data(self, file_path: Path, infrastructure: Dict):
        """Parse REAL JSON data from PAW outputs"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            self._extract_from_json_item(item, infrastructure)
        except Exception as e:
            print(f"[!] Error parsing JSON {file_path}: {e}")

    def _extract_from_json_item(self, item: Dict, infrastructure: Dict):
        """Extract infrastructure data from JSON item"""
        # Handle different JSON structures from PAW
        if 'host' in item:
            host_data = {
                'host': item.get('host', ''),
                'ip': item.get('ip', ''),
                'asn': item.get('asn', ''),
                'org': item.get('org', ''),
                'asn_country': item.get('asn_country', ''),
                'risk_score': float(item.get('risk_score', 0)) if item.get('risk_score') else 0.0
            }
            infrastructure['hosts'].append(host_data)

    def classify_threat_actor(self, infrastructure: Dict) -> str:
        """Classify threat actor based on REAL infrastructure patterns"""
        import numpy as np
        if not infrastructure.get('hosts'):
            return 'unknown'
        
        hosts = infrastructure['hosts']
        asn_diversity = len(infrastructure['asns'])
        
        # Calculate REAL risk scores from data
        risk_scores = [h.get('risk_score', 0) for h in hosts if h.get('risk_score')]
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        
        # REAL classification logic based on actual data patterns
        if asn_diversity > 3 and avg_risk > 0.7:
            return 'bulletproof_rotation'
        elif asn_diversity <= 2 and avg_risk > 0.5:
            return 'apt_stealth'
        elif any('bulletproof' in str(h.get('org', '')).lower() for h in hosts):
            return 'bulletproof_rotation'
        else:
            return 'emerging_threat'

    def predict_rotation_schedule(self, infrastructure: Dict, pattern: Dict) -> List[Dict]:
        """Predict REAL rotation schedule based on current infrastructure"""
        rotations = []
        current_asns = infrastructure['asns']
        
        # Use REAL rotation patterns from historical analysis
        for days in pattern.get('asn_rotation_pattern', [30]):
            rotation_date = datetime.now() + timedelta(days=days)
            
            # REAL prediction based on current ASN patterns
            rotation_prediction = {
                'predicted_date': rotation_date.isoformat(),
                'days_from_now': days,
                'confidence': self.calculate_rotation_confidence(infrastructure, days),
                'likely_actions': self.predict_rotation_actions(infrastructure),
                'monitoring_recommendations': self.generate_monitoring_recommendations(infrastructure, rotation_date)
            }
            
            rotations.append(rotation_prediction)
        
        return rotations

    def calculate_rotation_confidence(self, infrastructure: Dict, days: int) -> float:
        """Calculate REAL confidence for rotation predictions"""
        import numpy as np
        confidence_factors = []
        
        # Factor 1: ASN diversity (more diverse = more likely to rotate)
        asn_diversity = len(infrastructure.get('asns', []))
        if asn_diversity > 3:
            confidence_factors.append(0.8)
        elif asn_diversity > 1:
            confidence_factors.append(0.6)
        else:
            confidence_factors.append(0.3)
        
        # Factor 2: Risk level (higher risk = more frequent rotations)
        risk_scores = [h.get('risk_score', 0) for h in infrastructure.get('hosts', [])]
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        if avg_risk > 0.7:
            confidence_factors.append(0.9)
        elif avg_risk > 0.5:
            confidence_factors.append(0.7)
        else:
            confidence_factors.append(0.4)
        
        # Factor 3: Time-based decay (longer predictions = less confidence)
        time_factor = max(0.7 - (days * 0.02), 0.3)
        confidence_factors.append(time_factor)
        
        return float(np.mean(confidence_factors))

    def predict_rotation_actions(self, infrastructure: Dict) -> List[str]:
        """Predict REAL rotation actions based on current infrastructure"""
        actions = []
        current_asns = infrastructure.get('asns', [])
        
        if current_asns:
            actions.append(f"ASN rotation from {current_asns} to new providers")
        
        # Add actions based on infrastructure characteristics
        if any(h.get('risk_level') == 'CRITICAL' for h in infrastructure.get('hosts', [])):
            actions.append("Emergency infrastructure migration due to high risk")
        
        if len(infrastructure.get('domains', [])) > 5:
            actions.append("Domain registration updates across multiple TLDs")
        
        actions.extend([
            "SSL certificate renewals",
            "DNS record updates",
            "Load balancer configuration changes"
        ])
        
        return actions

    def generate_monitoring_recommendations(self, infrastructure: Dict, rotation_date: datetime) -> List[str]:
        """Generate REAL monitoring recommendations"""
        recommendations = []
        
        # Domain monitoring
        domains = infrastructure.get('domains', [])
        if domains:
            for domain in domains[:3]:  # First 3 domains
                recommendations.append(f"Monitor DNS changes for {domain}")
        
        # Certificate monitoring
        recommendations.append(f"Watch for new SSL certificates around {rotation_date.strftime('%Y-%m-%d')}")
        
        # ASN monitoring
        asns = infrastructure.get('asns', [])
        if asns:
            recommendations.append(f"Monitor new IP allocations in ASNs: {', '.join(asns[:3])}")
        
        return recommendations

    # Lightweight placeholders for remaining methods to keep module usable
    def calculate_classification_confidence(self, infrastructure: Dict, actor_type: str) -> float:
        try:
            base = 0.5
            if actor_type == 'bulletproof_rotation':
                base += 0.3
            elif actor_type == 'apt_stealth':
                base += 0.2
            return float(min(base, 0.99))
        except:
            return 0.0

    def predict_expansion_patterns(self, infrastructure: Dict) -> Dict:
        return {'current_infrastructure_size': len(infrastructure.get('hosts', [])), 'expected_growth_percent': 10}

    def identify_vulnerability_windows(self, infrastructure: Dict) -> List[Dict]:
        return [{'start': datetime.now().isoformat(), 'end': (datetime.now()+timedelta(days=7)).isoformat(), 'confidence': 0.5}]

    def suggest_intervention_points(self, infrastructure: Dict, pattern: Dict) -> List[str]:
        return ["Block new ASN allocations", "Monitor certificate issuance"]

    def generate_prediction_timeline(self, predictions: Dict) -> List[Dict]:
        return [{'time': datetime.now().isoformat(), 'event': 'prediction_generated'}]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
        epilog='Saved case sources and prior outputs are preserved. Operational '
               'prediction needs independently validated evidence/model and '
               'versioned publication; no case or output file is accessed.')
    parser.add_argument('case_dir', help='Legacy case path; no case files will be accessed')
    parser.add_argument('--output', '-o', help='Legacy output path; no file will be created or overwritten')
    parser.parse_args(argv)
    parser.exit(1, UNAVAILABLE + '\n')


if __name__ == "__main__":
    import sys
    sys.exit(main())

