# paw/sentinel/ip_analyzer.py
"""
IP Analysis Engine for victim intelligence.
Provides geolocation, WHOIS, reverse DNS, and basic reconnaissance.
"""
import socket
from .config import _require_active
import json
import time
import os
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress


class IPAnalyzer:
    """Analyze IP addresses for victim intelligence and attacker localization."""

    def __init__(self, timeout: int = 10, use_proxy: bool = True, proxy_url: str = None):
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.proxy_url = proxy_url or os.environ.get('PAW_PROXY_URL')
        self.geolocation_cache = {}
        self.whois_cache = {}

        # Setup proxy for safe external requests
        self.proxies = None
        if self.use_proxy and self.proxy_url:
            self.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }

    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Complete analysis of an IP address."""
        _require_active()
        result = {
            'ip': ip,
            'analysis_time': time.time(),
            'geolocation': {},
            'whois': {},
            'reverse_dns': None,
            'network_info': {},
            'risk_indicators': [],
            'correlated_ips': []
        }

        try:
            # Validate IP
            ip_obj = ipaddress.ip_address(ip)

            # Reverse DNS lookup
            result['reverse_dns'] = self.reverse_dns_lookup(ip)

            # Network information
            result['network_info'] = self.get_network_info(ip)

            # Geolocation (requires API key for production)
            result['geolocation'] = self.geolocate_ip(ip)

            # WHOIS lookup
            result['whois'] = self.whois_lookup(ip)

            # Risk analysis
            result['risk_indicators'] = self.analyze_risk_indicators(result)

        except Exception as e:
            result['error'] = str(e)

        return result

    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        _require_active()
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def get_network_info(self, ip: str) -> Dict[str, Any]:
        """Extract network information from IP."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(f"{ip}/24", strict=False)

            return {
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_loopback': ip_obj.is_loopback,
                'is_multicast': ip_obj.is_multicast,
                'network': str(network),
                'version': ip_obj.version
            }
        except Exception as e:
            return {'error': str(e)}

    def geolocate_ip(self, ip: str) -> Dict[str, Any]:
        """Geolocate IP address using free APIs."""
        _require_active()
        if ip in self.geolocation_cache:
            return self.geolocation_cache[ip]

        # Try multiple free geolocation services
        services = [
            self._geolocate_ipapi(ip),
            self._geolocate_ipify(ip),
        ]

        for service_result in services:
            if service_result and 'country' in service_result:
                self.geolocation_cache[ip] = service_result
                return service_result

        # Fallback to basic info
        return {
            'ip': ip,
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown'
        }

    def _geolocate_ipapi(self, ip: str) -> Optional[Dict[str, Any]]:
        """Geolocate using ip-api.com (free tier)."""
        _require_active()
        import requests
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}",
                                  timeout=self.timeout,
                                  proxies=self.proxies)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'as': data.get('as', 'Unknown'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone', 'Unknown'),
                        'source': 'ip-api.com'
                    }
        except Exception as e:
            print(f"[IPAnalyzer] Geolocation request failed: {type(e).__name__}")
        return None

    def _geolocate_ipify(self, ip: str) -> Optional[Dict[str, Any]]:
        """Geolocate using ipify.org (limited free tier)."""
        _require_active()
        api_key = os.environ.get('PAW_IPIFY_API_KEY')
        if not api_key: return None
        import requests
        try:
            response = requests.get('https://geo.ipify.org/api/v2/country,city',
                                  params={'apiKey': api_key, 'ipAddress': ip},
                                  timeout=self.timeout,
                                  proxies=self.proxies)
            if response.status_code == 200:
                data = response.json()
                location = data.get('location', {})
                return {
                    'country': location.get('country', 'Unknown'),
                    'city': location.get('city', 'Unknown'),
                    'region': location.get('region', 'Unknown'),
                    'isp': 'Unknown',  # Not provided by this API
                    'org': 'Unknown',
                    'lat': location.get('lat'),
                    'lon': location.get('lon'),
                    'source': 'ipify.org'
                }
        except Exception as e:
            print(f"[IPAnalyzer] Geolocation request failed: {type(e).__name__}")
        return None

    def whois_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for IP address."""
        _require_active()
        if ip in self.whois_cache:
            return self.whois_cache[ip]

        try:
            import whois
            w = whois.whois(ip)
            result = {
                'domain': w.domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'org': w.org,
                'country': w.country,
                'state': w.state,
                'city': w.city,
                'address': w.address,
                'emails': w.emails,
                'source': 'whois'
            }
            self.whois_cache[ip] = result
            return result
        except ImportError:
            return {'error': 'whois library not installed', 'install_command': 'pip install python-whois'}
        except Exception as e:
            return {'error': str(e)}

    def analyze_risk_indicators(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Analyze IP for risk indicators."""
        _require_active()
        indicators = []

        geo = analysis_result.get('geolocation', {})
        whois = analysis_result.get('whois', {})
        network = analysis_result.get('network_info', {})

        # High-risk countries for cybercrime
        high_risk_countries = ['RU', 'CN', 'IN', 'BR', 'NG', 'VN', 'IR', 'KP', 'UA', 'BY']
        if geo.get('country_code') in high_risk_countries:
            indicators.append(f"High-risk country: {geo.get('country')}")

        # Recently registered domains
        if whois.get('creation_date'):
            try:
                import datetime
                creation = datetime.datetime.fromisoformat(str(whois['creation_date']).split(' ')[0])
                days_old = (datetime.datetime.now() - creation).days
                if days_old < 30:
                    indicators.append(f"Recently registered domain ({days_old} days old)")
                elif days_old < 90:
                    indicators.append(f"Relatively new domain ({days_old} days old)")
            except:
                pass

        # Suspicious ISP patterns
        suspicious_isps = ['contabo', 'hetzner', 'digitalocean', 'vultr', 'linode']
        isp = geo.get('isp', '').lower()
        if any(suspicious in isp for suspicious in suspicious_isps):
            indicators.append(f"Known bulletproof hosting: {geo.get('isp')}")

        # Private IP (shouldn't be in phishing)
        if network.get('is_private'):
            indicators.append("Private IP address (unusual for phishing)")

        # No reverse DNS
        if not analysis_result.get('reverse_dns'):
            indicators.append("No reverse DNS (suspicious)")

        return indicators

    def correlate_ips(self, victim_ips: List[str], known_attacker_ranges: List[str] = None) -> Dict[str, Any]:
        """Find correlations between victim IPs to identify attacker infrastructure."""
        _require_active()
        correlations = {
            'ip_clusters': {},
            'common_networks': {},
            'geographic_clusters': {},
            'temporal_patterns': {},
            'potential_attacker_ranges': []
        }

        # Group by /24 networks
        network_groups = {}
        for ip in victim_ips:
            try:
                network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                if network not in network_groups:
                    network_groups[network] = []
                network_groups[network].append(ip)
            except:
                continue

        # Find networks with multiple victims
        correlations['common_networks'] = {
            network: ips for network, ips in network_groups.items()
            if len(ips) > 1
        }

        # Identify potential attacker ranges (networks with many victims)
        for network, ips in network_groups.items():
            if len(ips) >= 3:  # 3+ victims from same /24
                correlations['potential_attacker_ranges'].append({
                    'network': network,
                    'victim_count': len(ips),
                    'victim_ips': ips
                })

        return correlations

    def batch_analyze_ips(self, ips: List[str], max_workers: int = 5) -> Dict[str, Dict[str, Any]]:
        """Analyze multiple IPs concurrently."""
        _require_active()
        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.analyze_ip, ip): ip for ip in ips}

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception as e:
                    results[ip] = {'ip': ip, 'error': str(e)}

        return results
