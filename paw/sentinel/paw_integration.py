import os
import json
from typing import Dict, List, Any, Optional

class PAWDataIntegration:
    """
    Integrazione con i dati esistenti di PAW per arricchire l'analisi
    senza duplicare il processo di analisi completo
    """

    def __init__(self, paw_cases_dir: str = "cases"):
        self.paw_cases_dir = paw_cases_dir
        self.case_data = {}

    async def load_paw_case_data(self, case_id: str) -> Dict[str, Any]:
        """Carica i dati di un caso PAW esistente"""
        case_path = f"{self.paw_cases_dir}/{case_id}"

        try:
            # Carica i file di analisi PAW
            case_files = {
                'attribution_matrix': 'attribution_matrix.json',
                'technical_analysis': 'report/technical.md',
                'intelligence_data': 'detonation/threat_intelligence.json',
                'infrastructure_mapping': 'detonation/infrastructure_mapping.json'
            }

            case_data = {}
            for key, filename in case_files.items():
                file_path = f"{case_path}/{filename}"
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        if filename.endswith('.json'):
                            case_data[key] = json.load(f)
                        else:
                            case_data[key] = f.read()

            self.case_data[case_id] = case_data
            return case_data

        except Exception as e:
            print(f"Error loading PAW case data: {e}")
            return {}

    async def enrich_observation_with_paw_data(self, observation_data: Dict[str, Any],
                                             case_id: str) -> Dict[str, Any]:
        """Arricchisce i dati di osservazione con l'intelligence di PAW"""
        paw_data = await self.load_paw_case_data(case_id)

        enriched_data = {
            **observation_data,
            'paw_attribution_matrix': paw_data.get('attribution_matrix', {}),
            'paw_infrastructure_mapping': paw_data.get('infrastructure_mapping', {}),
            'paw_threat_intelligence': paw_data.get('intelligence_data', {}),
            'cross_reference_analysis': await self._cross_reference_analysis(observation_data, paw_data)
        }

        return enriched_data

    async def _cross_reference_analysis(self, observation_data: Dict[str, Any],
                                      paw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisi incrociata reale tra dati di osservazione e PAW"""
        cross_reference = {
            'infrastructure_matches': [],
            'behavioral_correlations': [],
            'temporal_alignment': {},
            'confidence_boost': 0.0,
            'attribution_conflicts': [],
            'data_completeness_score': 0.0
        }

        # Confronta infrastruttura osservata con quella di PAW
        obs_infra = observation_data.get('infrastructure_mapping', {})
        paw_infra = paw_data.get('infrastructure_mapping', {})

        if obs_infra and paw_infra:
            # Confronta IP addresses
            obs_ips = set(obs_infra.get('ip_addresses', []))
            paw_ips = set()  # Estrai IP da dati PAW

            # Se PAW ha dati infrastrutturali strutturati
            if isinstance(paw_infra, dict):
                for key, value in paw_infra.items():
                    if isinstance(value, list):
                        paw_ips.update(str(item) for item in value if isinstance(item, (str, int)))

            # Trova corrispondenze
            ip_matches = obs_ips.intersection(paw_ips)
            if ip_matches:
                cross_reference['infrastructure_matches'].append({
                    'type': 'ip_address_match',
                    'matches': list(ip_matches),
                    'confidence': 0.9
                })

            # Confronta servizi rilevati
            obs_services = set(obs_infra.get('services_detected', []))
            paw_services = set()  # Estrai servizi da dati PAW

            service_matches = obs_services.intersection(paw_services)
            if service_matches:
                cross_reference['infrastructure_matches'].append({
                    'type': 'service_match',
                    'matches': list(service_matches),
                    'confidence': 0.8
                })

        # Analizza correlazioni comportamentali
        obs_behavioral = observation_data.get('behavioral_patterns', {})
        paw_behavioral = paw_data.get('intelligence_data', {})

        if obs_behavioral and paw_behavioral:
            # Confronta pattern tecnologici
            obs_tech = set(obs_behavioral.get('technological_footprint', []))
            paw_tech = set()  # Estrai tecnologie da dati PAW

            tech_matches = obs_tech.intersection(paw_tech)
            if tech_matches:
                cross_reference['behavioral_correlations'].append({
                    'type': 'technology_match',
                    'matches': list(tech_matches),
                    'confidence': 0.7
                })

        # Calcola allineamento temporale
        obs_temporal = observation_data.get('temporal_analysis', {})
        paw_temporal = paw_data.get('temporal_data', {})  # Se disponibile

        if obs_temporal and paw_temporal:
            # Confronta timestamp e pattern temporali
            cross_reference['temporal_alignment'] = {
                'observation_timestamp': obs_temporal.get('timestamp'),
                'paw_timestamp': paw_temporal.get('timestamp'),
                'alignment_score': 0.5  # Logica semplificata
            }

        # Calcola boost di confidenza basato su corrispondenze
        total_matches = len(cross_reference['infrastructure_matches']) + len(cross_reference['behavioral_correlations'])
        cross_reference['confidence_boost'] = min(0.3, total_matches * 0.1)  # Max 30% boost

        # Calcola punteggio completezza dati
        obs_completeness = self._calculate_data_completeness(observation_data)
        paw_completeness = self._calculate_data_completeness(paw_data)
        cross_reference['data_completeness_score'] = (obs_completeness + paw_completeness) / 2

        return cross_reference

    def _calculate_data_completeness(self, data: Dict[str, Any]) -> float:
        """Calcola punteggio di completezza dei dati"""
        required_fields = ['infrastructure_mapping', 'behavioral_patterns', 'temporal_analysis', 'attribution_evidence']
        present_fields = sum(1 for field in required_fields if field in data and data[field])

        return present_fields / len(required_fields)

    async def _merge_paw_evidence(self, observation_data: Dict[str, Any],
                                paw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fusione reale delle evidenze tra osservazione e PAW"""
        merged_evidence = {
            'combined_infrastructure': {},
            'merged_attribution': {},
            'evidence_conflicts': [],
            'consolidated_findings': []
        }

        # Unisci infrastruttura
        obs_infra = observation_data.get('infrastructure_mapping', {})
        paw_infra = paw_data.get('infrastructure_mapping', {})

        merged_evidence['combined_infrastructure'] = {
            **obs_infra,
            **paw_infra,  # PAW data ha priorità per conflitti
            'data_sources': ['passive_observation', 'paw_analysis']
        }

        # Unisci attribuzione
        obs_attr = observation_data.get('attribution_evidence', {})
        paw_attr = paw_data.get('attribution_matrix', {})

        merged_evidence['merged_attribution'] = {
            'observation_based': obs_attr,
            'paw_based': paw_attr,
            'consensus_level': self._calculate_attribution_consensus(obs_attr, paw_attr)
        }

        # Identifica conflitti
        conflicts = self._identify_evidence_conflicts(obs_attr, paw_attr)
        merged_evidence['evidence_conflicts'] = conflicts

        # Crea findings consolidati
        consolidated = self._create_consolidated_findings(observation_data, paw_data)
        merged_evidence['consolidated_findings'] = consolidated

        return merged_evidence

    def _calculate_attribution_consensus(self, obs_attr: Dict[str, Any], paw_attr: Dict[str, Any]) -> float:
        """Calcola livello di consenso tra attribuzioni"""
        if not obs_attr and not paw_attr:
            return 0.0

        # Logica semplificata: se entrambi hanno dati simili, alto consenso
        obs_keys = set(obs_attr.keys())
        paw_keys = set(paw_attr.keys())

        overlap = len(obs_keys.intersection(paw_keys))
        total = len(obs_keys.union(paw_keys))

        return overlap / total if total > 0 else 0.0

    def _identify_evidence_conflicts(self, obs_attr: Dict[str, Any], paw_attr: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identifica conflitti tra evidenze"""
        conflicts = []

        # Confronta valori contraddittori
        common_keys = set(obs_attr.keys()).intersection(set(paw_attr.keys()))

        for key in common_keys:
            obs_value = obs_attr[key]
            paw_value = paw_attr[key]

            if obs_value != paw_value:
                conflicts.append({
                    'field': key,
                    'observation_value': obs_value,
                    'paw_value': paw_value,
                    'severity': 'medium'
                })

        return conflicts

    def _create_consolidated_findings(self, observation_data: Dict[str, Any], paw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Crea findings consolidati dalla fusione dei dati"""
        findings = []

        # Finding infrastrutturale consolidato
        infra_finding = {
            'type': 'infrastructure_consolidation',
            'sources': ['passive_observation', 'paw_analysis'],
            'confidence': 0.8,
            'description': 'Combined infrastructure analysis from passive observation and PAW'
        }
        findings.append(infra_finding)

        # Finding di attribuzione consolidato
        attr_finding = {
            'type': 'attribution_consolidation',
            'sources': ['passive_observation', 'paw_analysis'],
            'confidence': 0.7,
            'description': 'Merged attribution evidence from multiple sources'
        }
        findings.append(attr_finding)

        return findings