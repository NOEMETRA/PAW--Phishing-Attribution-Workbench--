"""Expose unavailable providers honestly; no invented results."""
from ..core.network_policy import network_allowed

class ThreatIntelligence:
    def enrich_indicators(self, domain, ips):
        offline = not network_allowed()
        return {name: {'status': 'skipped' if offline else 'unavailable',
            'reason': 'no-egress' if offline else 'provider adapter not implemented'}
            for name in ('virustotal', 'abuseipdb', 'alienvault', 'threatfox')}
