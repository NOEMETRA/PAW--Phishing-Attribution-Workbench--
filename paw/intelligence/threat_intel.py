import os
from typing import Dict, List

import requests

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system env vars


class ThreatIntelligence:
    """Integrazione con feed ThreatFox e AlienVault OTX."""

    THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
    OTX_DOMAIN_API = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

    def __init__(self):
        self.session = requests.Session()
        self.threatfox_key = os.getenv("THREATFOX_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")

    def enrich_indicators(self, domain: str, ips: List[str]) -> Dict:
        """Arricchisce indicatori interrogando ThreatFox e AlienVault."""
        return {
            'threatfox': self._check_threatfox(domain, ips),
            'alienvault': self._check_alienvault(domain)
        }

    def _check_threatfox(self, domain: str, ips: List[str]) -> Dict:
        """Consulta ThreatFox per dominio e IP correlati."""
        domain_iocs = self._query_threatfox(domain)
        ip_iocs = {ip: self._query_threatfox(ip) for ip in ips} if ips else {}

        # Handle case where domain_iocs is a dict with error
        if isinstance(domain_iocs, dict) and 'error' in domain_iocs:
            return {
                'domain_iocs': [],
                'ip_iocs': ip_iocs,
                'malware_families': [],
                'error': domain_iocs['error']
            }

        malware_families = list({
            ioc.get('malware')
            for ioc in (domain_iocs or [])
            if isinstance(ioc, dict) and ioc.get('malware')
        })

        return {
            'domain_iocs': domain_iocs if isinstance(domain_iocs, list) else [],
            'ip_iocs': ip_iocs,
            'malware_families': malware_families
        }

    def _query_threatfox(self, search_term: str) -> Dict:
        """Esegue una query search_ioc su ThreatFox."""
        payload = {
            "query": "search_ioc",
            "search_term": search_term
        }
        
        headers = {}
        if self.threatfox_key:
            headers["Auth-Key"] = self.threatfox_key

        try:
            resp = self.session.post(self.THREATFOX_API, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if data.get('query_status') == 'ok':
                return data.get('data', []) or []
            return {'error': data.get('query_status')}
        except Exception as exc:
            return {'error': str(exc)}

    def _check_alienvault(self, domain: str) -> Dict:
        """Recupera informazioni dal feed AlienVault OTX sul dominio."""
        headers = {}
        if self.otx_key:
            headers['X-OTX-API-KEY'] = self.otx_key

        try:
            resp = self.session.get(
                self.OTX_DOMAIN_API.format(domain=domain),
                headers=headers,
                timeout=15
            )
            resp.raise_for_status()
            data = resp.json()

            pulses = data.get('pulse_info', {})
            reputation = data.get('reputation', {})
            related_ips = [
                entry.get('indicator')
                for entry in reputation.get('entries', [])
                if entry.get('type') == 'IPv4'
            ]

            return {
                'pulse_count': pulses.get('count', 0),
                'pulses': pulses.get('pulses', []),
                'related_ips': related_ips
            }
        except Exception as exc:
            return {'error': str(exc)}
