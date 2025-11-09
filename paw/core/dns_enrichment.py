# dns_enrichment.py - DNS Analysis and Enrichment
import dns.resolver
import dns.reversename
import dns.exception
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import socket
import re
from collections import defaultdict
import ipaddress
from datetime import datetime, timezone

import requests
import whois

logger = logging.getLogger(__name__)

class DNSEnrichmentAnalyzer:
    """Analyze DNS records for attribution patterns"""

    def __init__(self, timeout: float = 10.0, retries: int = 2):
        # Increase default DNS timeout and allow a small number of retries to
        # reduce transient socket/timeouts observed during enrichment runs.
        self.timeout = timeout
        self.retries = max(1, int(retries))
        self.resolver = dns.resolver.Resolver()
        # per-attempt timeout
        self.resolver.timeout = timeout
        # overall lifetime across retries (give some headroom)
        self.resolver.lifetime = timeout * (self.retries + 1)
        self._geoip_cache: Dict[str, Optional[Dict[str, Any]]] = {}

        # Known hosting providers and their patterns
        self.hosting_patterns = {
            'aws': ['amazonaws.com', 'awsglobalaccelerator.com'],
            'azure': ['azurewebsites.net', 'cloudapp.azure.com', 'azureedge.net'],
            'gcp': ['appspot.com', 'googleusercontent.com', 'run.app'],
            'cloudflare': ['cloudflare.net', 'pages.dev'],
            'fastly': ['fastly.net', 'fastlylb.net'],
            'akamai': ['akamai.net', 'akamaiedge.net'],
            'stackpath': ['stackpathdns.com', 'stackpathcdn.com'],
            'digitalocean': ['digitaloceanspaces.com', 'ondigitalocean.app'],
            'heroku': ['herokuapp.com', 'herokudns.com'],
            'vercel': ['vercel.app', 'now.sh'],
            'netlify': ['netlify.app', 'netlify.com'],
            'github': ['github.io', 'githubusercontent.com'],
            'gitlab': ['gitlab.io', 'pages.gitlab.io']
        }

        # Known registrar patterns
        self.registrar_patterns = {
            'godaddy': ['domaincontrol.com', 'secureserver.net'],
            'namecheap': ['namecheap.com'],
            'porkbun': ['porkbun.com'],
            'epik': ['epik.com'],
            'njalla': ['njalla.no'],
            'hover': ['hover.com'],
            'dreamhost': ['dreamhost.com'],
            'ionos': ['ionos.com', '1and1.com'],
            'hostinger': ['hostinger.com'],
            'siteground': ['siteground.com']
        }

    def analyze_domain_dns(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS analysis for a domain"""
        result = {
            'domain': domain,
            'records': {},
            'cname_chain': [],
            'nameservers': [],
            'mx_records': [],
            'txt_records': [],
            'hosting_provider': {},
            'registrar_hints': {},
            'reverse_dns': {},
            'ip_ranges': {},
            'attribution_hints': {},
            'errors': []
        }

        try:
            # Basic A/AAAA records
            result['records']['A'] = self._get_records(domain, 'A')
            result['records']['AAAA'] = self._get_records(domain, 'AAAA')

            # CNAME chain analysis
            result['cname_chain'] = self._analyze_cname_chain(domain)

            # Nameservers
            result['nameservers'] = self._get_records(domain, 'NS')

            # MX records
            result['mx_records'] = self._get_records(domain, 'MX')

            # TXT records (SPF, DMARC, etc.)
            result['txt_records'] = self._get_records(domain, 'TXT')

            # Reverse DNS for IPs
            self._analyze_reverse_dns(result)

            # Hosting provider detection
            result['hosting_provider'] = self._detect_hosting_provider(result)

            # Registrar hints
            result['registrar_hints'] = self._detect_registrar_hints(result)

            # IP range analysis
            result['ip_ranges'] = self._analyze_ip_ranges(result)

            # Generate attribution hints
            result['attribution_hints'] = self._generate_attribution_hints(result)

        except Exception as e:
            result['errors'].append(f"DNS analysis failed: {str(e)}")
            logger.error(f"DNS analysis failed for {domain}: {e}")

        return result

    def _get_records(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """Get DNS records of specified type"""
        records = []

        try:
            # Retry a few times on transient errors/timeouts
            answers = None
            last_exc = None
            for attempt in range(self.retries + 1):
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    break
                except dns.exception.Timeout as te:
                    last_exc = te
                    logger.debug("Timeout resolving %s %s (attempt %d)", domain, record_type, attempt + 1)
                    continue
                except dns.resolver.NXDOMAIN:
                    # domain does not exist, no need to retry
                    answers = []
                    break
                except dns.resolver.NoAnswer:
                    answers = []
                    break
                except Exception as e:
                    last_exc = e
                    logger.debug("Error resolving %s %s: %s (attempt %d)", domain, record_type, e, attempt + 1)
                    continue

            if answers is None:
                # All attempts failed
                if last_exc:
                    logger.debug("All DNS attempts failed for %s %s: %s", domain, record_type, last_exc)
                return records

            for answer in answers:
                record_info = {
                    'value': str(answer),
                    'ttl': answer.ttl if hasattr(answer, 'ttl') else None
                }

                # Add type-specific fields
                if record_type == 'MX':
                    record_info['preference'] = answer.preference
                    record_info['exchange'] = str(answer.exchange)
                elif record_type == 'TXT':
                    record_info['strings'] = answer.strings if hasattr(answer, 'strings') else [str(answer)]

                records.append(record_info)

        except Exception as e:
            # Any unexpected errors
            logger.warning(f"Failed to get {record_type} records for {domain}: {e}")

        return records

    def _analyze_cname_chain(self, domain: str) -> List[Dict[str, Any]]:
        """Analyze CNAME chain for domain"""
        chain = []
        current_domain = domain
        visited = set()
        max_depth = 10

        for depth in range(max_depth):
            if current_domain in visited:
                chain.append({'type': 'loop_detected', 'domain': current_domain})
                break

            visited.add(current_domain)

            try:
                # reuse the same retry logic as _get_records for CNAME
                answers = None
                last_exc = None
                for attempt in range(self.retries + 1):
                    try:
                        answers = self.resolver.resolve(current_domain, 'CNAME')
                        break
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        answers = []
                        break
                    except dns.exception.Timeout as te:
                        last_exc = te
                        logger.debug("Timeout resolving CNAME %s (attempt %d)", current_domain, attempt + 1)
                        continue
                    except Exception as e:
                        last_exc = e
                        logger.debug("Error resolving CNAME %s: %s (attempt %d)", current_domain, e, attempt + 1)
                        continue

                if not answers:
                    break

                cname_target = str(answers[0].target)
                chain.append({
                    'domain': current_domain,
                    'cname_target': cname_target,
                    'depth': depth
                })
                current_domain = cname_target.rstrip('.')
            except Exception as e:
                logger.warning(f"CNAME analysis failed for {current_domain}: {e}")
                break

        return chain

    def _analyze_reverse_dns(self, result: Dict[str, Any]) -> None:
        """Perform reverse DNS lookup on IP addresses"""
        reverse_info = {}

        # Get IPs from A records
        a_records = result['records'].get('A', [])
        for record in a_records:
            ip = record.get('value')
            if ip:
                try:
                    # Use DNS PTR resolution so we can control timeouts and retries
                    ptr_name = dns.reversename.from_address(ip)
                    answers = None
                    last_exc = None
                    for attempt in range(self.retries + 1):
                        try:
                            answers = self.resolver.resolve(ptr_name, 'PTR')
                            break
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            answers = []
                            break
                        except dns.exception.Timeout as te:
                            last_exc = te
                            logger.debug("Timeout PTR lookup %s (attempt %d)", ip, attempt + 1)
                            continue
                        except Exception as e:
                            last_exc = e
                            logger.debug("Error PTR lookup %s: %s (attempt %d)", ip, e, attempt + 1)
                            continue

                    if answers:
                        hostname = str(answers[0]).rstrip('.')
                        reverse_info[ip] = {
                            'hostname': hostname,
                            'matches_domain': hostname == result['domain']
                        }
                    else:
                        reverse_info[ip] = {'hostname': None, 'error': 'no_reverse_record'}
                except Exception as exc:
                    logger.debug("Reverse DNS lookup failed for %s: %s", ip, exc)
                    reverse_info[ip] = {'hostname': None, 'error': str(exc)}

        result['reverse_dns'] = reverse_info

    def _detect_hosting_provider(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Detect hosting provider from DNS records"""
        provider_info = {
            'detected_provider': None,
            'confidence': 0.0,
            'indicators': []
        }

        # Check CNAME chain
        for cname_record in result.get('cname_chain', []):
            target = cname_record.get('cname_target', '').lower()
            for provider, patterns in self.hosting_patterns.items():
                if any(pattern in target for pattern in patterns):
                    provider_info['detected_provider'] = provider
                    provider_info['confidence'] = 0.9
                    provider_info['indicators'].append(f"CNAME: {target}")
                    break

        # Check nameservers
        if not provider_info['detected_provider']:
            for ns_record in result.get('nameservers', []):
                ns = ns_record.get('value', '').lower()
                for provider, patterns in self.hosting_patterns.items():
                    if any(pattern in ns for pattern in patterns):
                        provider_info['detected_provider'] = provider
                        provider_info['confidence'] = 0.7
                        provider_info['indicators'].append(f"NS: {ns}")
                        break

        return provider_info

    def _detect_registrar_hints(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Detect registrar hints from DNS records"""
        registrar_info = {
            'detected_registrar': None,
            'confidence': 0.0,
            'indicators': []
        }

        # Check nameservers for registrar patterns
        for ns_record in result.get('nameservers', []):
            ns = ns_record.get('value', '').lower()
            for registrar, patterns in self.registrar_patterns.items():
                if any(pattern in ns for pattern in patterns):
                    registrar_info['detected_registrar'] = registrar
                    registrar_info['confidence'] = 0.8
                    registrar_info['indicators'].append(f"NS: {ns}")
                    break

        return registrar_info

    def _analyze_ip_ranges(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IP ranges for attribution"""
        ip_analysis = {
            'ranges': [],
            'providers': [],
            'geographic_hints': []
        }

        ips = []
        for record in result['records'].get('A', []):
            ip = record.get('value')
            if ip:
                ips.append(ip)

        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)

                # Check for known cloud provider ranges (simplified)
                if ip_obj in ipaddress.ip_network('52.0.0.0/8'):  # AWS
                    ip_analysis['providers'].append('AWS')
                    ip_analysis['ranges'].append('52.0.0.0/8')
                elif ip_obj in ipaddress.ip_network('104.0.0.0/8'):  # Google Cloud
                    ip_analysis['providers'].append('Google Cloud')
                    ip_analysis['ranges'].append('104.0.0.0/8')
                elif ip_obj in ipaddress.ip_network('13.64.0.0/11'):  # Azure
                    ip_analysis['providers'].append('Azure')
                    ip_analysis['ranges'].append('13.64.0.0/11')

                # Geographic hints from IP
                geo_hint = self._get_geo_hint_from_ip(ip)
                if geo_hint:
                    ip_analysis['geographic_hints'].append(geo_hint)

            except ValueError:
                continue

        # Remove duplicates
        ip_analysis['providers'] = list(set(ip_analysis['providers']))
        ip_analysis['ranges'] = list(set(ip_analysis['ranges']))
        ip_analysis['geographic_hints'] = list(set(ip_analysis['geographic_hints']))

        return ip_analysis

    def _get_geo_hint_from_ip(self, ip: str) -> Optional[str]:
        """Get geographic hint from IP using real GeoIP lookup."""
        geo = self._lookup_geoip(ip)
        if not geo:
            return None

        country = geo.get('country')
        country_code = geo.get('countryCode')
        region = geo.get('regionName')
        city = geo.get('city')
        isp = geo.get('isp') or geo.get('org')

        parts = []
        if country:
            country_part = country if not country_code else f"{country} ({country_code})"
            parts.append(country_part)
        location = ", ".join(filter(None, [region, city]))
        if location:
            parts.append(location)

        hint = " / ".join(parts) if parts else country
        if isp:
            hint = f"{hint} - {isp}" if hint else isp

        return hint or None

    def _lookup_geoip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query ip-api.com for GeoIP data with caching."""
        if ip in self._geoip_cache:
            return self._geoip_cache[ip]

        try:
            # Use a slightly higher timeout for external GeoIP queries and
            # tolerate transient network hiccups.
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={'fields': 'status,message,country,countryCode,regionName,city,isp,org,as'},
                timeout=8
            )
            data = response.json()
            if data.get('status') == 'success':
                self._geoip_cache[ip] = data
                return data
            logger.debug("GeoIP lookup failed for %s: %s", ip, data.get('message'))
        except requests.RequestException as exc:
            logger.debug("GeoIP lookup error for %s: %s", ip, exc)

        self._geoip_cache[ip] = None
        return None

        return None

    def _generate_attribution_hints(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attribution hints from DNS analysis"""
        hints = {
            'infrastructure_type': 'unknown',
            'hosting_category': 'unknown',
            'risk_indicators': [],
            'correlation_keys': []
        }

        # Infrastructure type
        hosting = result.get('hosting_provider', {})
        if hosting.get('detected_provider'):
            provider = hosting['detected_provider']
            if provider in ['aws', 'azure', 'gcp']:
                hints['infrastructure_type'] = 'cloud'
            elif provider in ['cloudflare', 'fastly', 'akamai']:
                hints['infrastructure_type'] = 'cdn'
            elif provider in ['digitalocean', 'heroku', 'vercel']:
                hints['infrastructure_type'] = 'paas'
            else:
                hints['infrastructure_type'] = 'hosting'

        # Hosting category
        if hosting.get('detected_provider'):
            hints['hosting_category'] = hosting['detected_provider']

        # Risk indicators
        risk_indicators = []

        # Check for dynamic DNS
        ns_records = [ns.get('value', '') for ns in result.get('nameservers', [])]
        dynamic_dns_patterns = ['dyn.com', 'dyndns.org', 'no-ip.com', 'duckdns.org']
        if any(any(pattern in ns.lower() for pattern in dynamic_dns_patterns) for ns in ns_records):
            risk_indicators.append('dynamic_dns_detected')

        # Check for suspicious TLDs
        domain = result.get('domain', '')
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_indicators.append('suspicious_tld')

        domain_age_days = self._get_domain_age_days(domain)
        if domain_age_days is not None:
            hints['domain_age_days'] = domain_age_days
            if domain_age_days < 30:
                risk_indicators.append('domain_age_less_30d')
            elif domain_age_days < 90:
                risk_indicators.append('domain_age_less_90d')
        else:
            hints['domain_age_days'] = None

        hints['risk_indicators'] = risk_indicators

        # Correlation keys
        correlation_keys = []

        # Hosting provider as correlation key
        if hosting.get('detected_provider'):
            correlation_keys.append(f"hosting:{hosting['detected_provider']}")

        # IP ranges
        ip_ranges = result.get('ip_ranges', {}).get('ranges', [])
        for ip_range in ip_ranges:
            correlation_keys.append(f"ip_range:{ip_range}")

        # Nameservers
        for ns in ns_records:
            if ns:
                correlation_keys.append(f"ns:{ns}")

        hints['correlation_keys'] = correlation_keys

        return hints

    def correlate_domains(self, domains: List[str]) -> Dict[str, Any]:
        """Correlate multiple domains for common infrastructure"""
        correlation_results = {
            'domains_analyzed': len(domains),
            'common_hosting': {},
            'common_nameservers': {},
            'common_ip_ranges': {},
            'infrastructure_clusters': []
        }

        domain_analyses = {}
        for domain in domains:
            analysis = self.analyze_domain_dns(domain)
            domain_analyses[domain] = analysis

        # Find common hosting providers
        hosting_count = defaultdict(int)
        for analysis in domain_analyses.values():
            provider = analysis.get('hosting_provider', {}).get('detected_provider')
            if provider:
                hosting_count[provider] += 1

        correlation_results['common_hosting'] = dict(hosting_count)

        # Find common nameservers
        ns_count = defaultdict(int)
        for analysis in domain_analyses.values():
            for ns_record in analysis.get('nameservers', []):
                ns = ns_record.get('value')
                if ns:
                    ns_count[ns] += 1

        correlation_results['common_nameservers'] = dict(ns_count)

        # Find common IP ranges
        ip_range_count = defaultdict(int)
        for analysis in domain_analyses.values():
            for ip_range in analysis.get('ip_ranges', {}).get('ranges', []):
                ip_range_count[ip_range] += 1

        correlation_results['common_ip_ranges'] = dict(ip_range_count)

        # Identify infrastructure clusters
        clusters = []
        for provider, count in hosting_count.items():
            if count > 1:
                cluster_domains = [d for d, a in domain_analyses.items()
                                 if a.get('hosting_provider', {}).get('detected_provider') == provider]
                clusters.append({
                    'type': 'hosting_provider',
                    'provider': provider,
                    'domains': cluster_domains,
                    'count': count
                })

        correlation_results['infrastructure_clusters'] = clusters

        return correlation_results

    def _get_domain_age_days(self, domain: str) -> Optional[int]:
        """Retrieve domain age in days using WHOIS data."""
        if not domain:
            return None

        try:
            whois_data = whois.whois(domain)
            creation_date = whois_data.creation_date

            if isinstance(creation_date, list):
                creation_date = next(
                    (d for d in creation_date if isinstance(d, datetime)),
                    creation_date[0] if creation_date else None
                )

            if isinstance(creation_date, datetime):
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                delta = datetime.now(timezone.utc) - creation_date
                return max(delta.days, 0)
        except Exception as exc:
            logger.debug("Domain age lookup failed for %s: %s", domain, exc)
        return None


def analyze_domain_dns(domain: str) -> Dict[str, Any]:
    """Convenience function for DNS analysis"""
    analyzer = DNSEnrichmentAnalyzer()
    return analyzer.analyze_domain_dns(domain)
