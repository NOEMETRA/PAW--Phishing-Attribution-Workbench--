import socket
import ssl
import dns.resolver
import http.client
import json
import os
import subprocess
from typing import Dict, List
from urllib.parse import urlparse
from datetime import datetime
import hashlib
import re
import math
import time
import statistics
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class CriminalHunter:
    """Standalone criminal infrastructure hunter - no external APIs.

    This class uses only local/network primitives (socket, DNS resolver,
    HTTP HEAD requests) and does not depend on third-party web APIs.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()

    def hunt_from_url(self, url: str) -> Dict:
        domain = self._extract_domain(url)
        return self.hunt_from_domain(domain)

    def hunt_from_domain(self, domain: str) -> Dict:
        print(f"🎯 Hunting criminal infrastructure for: {domain}")

        real_ips = self._find_real_ips(domain)
        infrastructure = self._map_infrastructure_standalone(domain, real_ips)
        threat_intel = self._correlate_threat_intel_standalone(domain, real_ips)
        le_package = self._generate_le_package_standalone(domain, real_ips, infrastructure, threat_intel)
        
        # Advanced attribution analysis
        infrastructure_clusters = self._identify_infrastructure_clusters(domain, real_ips)
        campaign_correlation = self._correlate_campaigns(domain, real_ips)
        operational_fingerprints = self._fingerprint_operational_techniques(domain, real_ips)

        return {
            'target_domain': domain,
            'real_ips': real_ips,
            'infrastructure': infrastructure,
            'threat_intel': threat_intel,
            'le_package': le_package,
            'infrastructure_clusters': infrastructure_clusters,
            'campaign_correlation': campaign_correlation,
            'operational_fingerprints': operational_fingerprints,
            'timestamp': datetime.now().isoformat(),
            'techniques_used': list({ip.get('technique') for ip in real_ips})
        }

    def _find_real_ips(self, domain: str) -> List[Dict]:
        ips_found: List[Dict] = []

        techniques = [
            self._technique_direct_dns,
            self._technique_ssl_certificate,
            self._technique_subdomain_enumeration,
            self._technique_http_headers,
            self._technique_dns_mx_records,
            self._technique_whois_local,
            self._technique_reverse_dns,
            self._technique_passive_dns_reverse,
            self._technique_ttl_analysis,
            self._technique_server_fingerprinting,
        ]

        for technique in techniques:
            try:
                res = technique(domain)
                if res and res.get('ip') and res['ip'] not in [i['ip'] for i in ips_found]:
                    ips_found.append(res)
                    print(f"  ✅ {technique.__name__}: {res['ip']}")
            except Exception as e:
                print(f"  ⚠️ {technique.__name__} failed: {e}")

        return ips_found

    def _technique_direct_dns(self, domain: str) -> Dict:
        try:
            ip = socket.gethostbyname(domain)
            return {'ip': ip, 'technique': 'direct_dns', 'confidence': 'high'}
        except Exception:
            return {}

    def _technique_ssl_certificate(self, domain: str) -> Dict:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert and 'subjectAltName' in cert:
                        for name in cert['subjectAltName']:
                            if name[0] == 'DNS' and name[1] != domain:
                                try:
                                    ip = socket.gethostbyname(name[1])
                                    return {'ip': ip, 'technique': 'ssl_certificate', 'confidence': 'high', 'source': name[1]}
                                except Exception:
                                    continue
        except Exception:
            pass
        return {}

    def _technique_subdomain_enumeration(self, domain: str) -> Dict:
        subs = ['www', 'mail', 'ftp', 'cpanel', 'webmail', 'admin', 'blog', 'api', 'test', 'dev', 'shop', 'store']
        for s in subs:
            d = f"{s}.{domain}"
            try:
                ip = socket.gethostbyname(d)
                return {'ip': ip, 'technique': 'subdomain_enum', 'confidence': 'medium', 'source': d}
            except Exception:
                continue
        return {}

    def _technique_http_headers(self, domain: str) -> Dict:
        try:
            conn = http.client.HTTPConnection(domain, timeout=5)
            conn.request('HEAD', '/')
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                loc = resp.getheader('Location')
                if loc and '://' in loc:
                    h = urlparse(loc).hostname
                    if h and h != domain:
                        ip = socket.gethostbyname(h)
                        return {'ip': ip, 'technique': 'http_redirect', 'confidence': 'medium', 'source': h}

            server = resp.getheader('Server', '')
            if server and 'cloudflare' not in server.lower():
                try:
                    ip = socket.gethostbyname(domain)
                    return {'ip': ip, 'technique': 'http_headers', 'confidence': 'medium', 'server': server}
                except Exception:
                    pass
        except Exception:
            pass
        return {}

    def _technique_dns_mx_records(self, domain: str) -> Dict:
        for t in ('MX', 'NS', 'TXT'):
            try:
                answers = dns.resolver.resolve(domain, t)
                for r in answers:
                    target = str(getattr(r, 'exchange', r)).rstrip('.')
                    try:
                        ip = socket.gethostbyname(target)
                        return {'ip': ip, 'technique': f'dns_{t.lower()}', 'confidence': 'medium', 'source': target}
                    except Exception:
                        continue
            except Exception:
                continue
        return {}

    def _technique_whois_local(self, domain: str) -> Dict:
        """Real WHOIS lookup with proper parsing"""
        try:
            import whois
            w = whois.whois(domain)

            # Extract useful data
            result = {
                'ip': '',
                'technique': 'whois',
                'confidence': 'medium',
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'status': w.status if hasattr(w, 'status') else None,
                'emails': w.emails if hasattr(w, 'emails') else [],
            }

            # Calculate domain age risk
            if result['creation_date']:
                from datetime import datetime
                try:
                    creation = result['creation_date']
                    if isinstance(creation, list):
                        creation = creation[0]
                    # Domain age < 30 days is suspicious
                    if 'days' in str(datetime.now() - datetime.fromisoformat(str(creation))):
                        result['confidence'] = 'high'
                        result['risk_indicator'] = 'newly_registered'
                except Exception:
                    pass

            return result
        except ImportError:
            # Fallback to raw WHOIS if python-whois not available
            return self._technique_whois_raw(domain)
        except Exception as e:
            return {'ip': '', 'technique': 'whois', 'confidence': 'low', 'error': str(e)}

    def _technique_whois_raw(self, domain: str) -> Dict:
        """Fallback raw WHOIS implementation"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(('whois.iana.org', 43))
                s.send(f"{domain}\r\n".encode())
                data = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                txt = data.decode('utf-8', errors='ignore')

                # Parse referral server
                for line in txt.splitlines():
                    if line.lower().startswith('refer:'):
                        server = line.split(':', 1)[1].strip()
                        return self._deep_whois_lookup(domain, server)

                # No referral, return raw data
                return {'ip': '', 'technique': 'whois', 'confidence': 'low', 'whois_raw': txt}
        except Exception as e:
            return {'ip': '', 'technique': 'whois', 'error': str(e)}

    def _technique_reverse_dns(self, domain: str) -> Dict:
        # Attempt reverse lookups on resolved IPs
        try:
            ip = socket.gethostbyname(domain)
            try:
                ptr = socket.gethostbyaddr(ip)
                return {'ip': ip, 'technique': 'reverse_dns', 'confidence': 'low', 'source': ptr[0]}
            except Exception:
                return {'ip': ip, 'technique': 'reverse_dns', 'confidence': 'low'}
        except Exception:
            return {}

    def _deep_whois_lookup(self, domain: str, server: str) -> Dict:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((server, 43))
                s.send(f"{domain}\r\n".encode())
                data = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                txt = data.decode('utf-8', errors='ignore')
                return {'ip': '', 'technique': 'whois', 'confidence': 'low', 'whois': txt}
        except Exception:
            return {}

    def _map_infrastructure_standalone(self, domain: str, ips: List[Dict]) -> Dict:
        if not ips:
            return {'primary_domain': domain, 'status': 'no_ips', 'techniques_applied': 0}

        primary = ips[0]['ip']
        related = self._find_related_domains(primary)
        advanced = self._advanced_infrastructure_analysis(domain, ips)
        return {
            'primary_domain': domain,
            'primary_ip': primary,
            'total_ips_found': len(ips),
            'related_domains': related,
            'open_ports': self._quick_port_scan(primary),
            'techniques_applied': len(ips),
            'advanced_analysis': advanced
        }

    def _find_related_domains(self, ip: str) -> List[str]:
        try:
            res = socket.gethostbyaddr(ip)
            return [res[0]]
        except Exception:
            return []

    def _analyze_ip_locally(self, ip: str) -> Dict:
        # Lightweight local analysis - private/public, class
        parts = ip.split('.')
        is_private = parts[0] == '10' or (parts[0] == '192' and parts[1] == '168') or (parts[0] == '172' and 16 <= int(parts[1]) <= 31)
        first_octet = int(parts[0]) if parts and parts[0].isdigit() else 0
        ip_class = 'A' if first_octet < 128 else 'B' if first_octet < 192 else 'C'
        return {'is_private': is_private, 'ip_class': ip_class}

    def _quick_port_scan(self, ip: str, ports: List[int] = None) -> List[int]:
        if ports is None:
            ports = [22, 80, 443, 8080, 8443]
        open_ports = []
        for p in ports:
            try:
                with socket.create_connection((ip, p), timeout=1):
                    open_ports.append(p)
            except Exception:
                continue
        return open_ports

    def _advanced_infrastructure_analysis(self, domain: str, ips: List[Dict]) -> Dict:
        """Analisi avanzata infrastruttura per attribuzione campaign"""
        analysis = {
            'temporal_patterns': {},
            'infrastructure_reuse': {},
            'content_fingerprinting': {},
            'ttl_analysis': {}
        }

        if not ips:
            return analysis

        primary_ip = ips[0]['ip']

        # Temporal patterns: DNS TTL
        try:
            answers = self.resolver.resolve(domain, 'A')
            if answers:
                ttl = answers.rrset.ttl
                analysis['temporal_patterns'] = {
                    'dns_ttl': ttl,
                    'ttl_category': 'low' if ttl < 300 else 'normal' if ttl < 3600 else 'high',
                    'evasion_potential': 'high' if ttl < 300 else 'medium' if ttl < 3600 else 'low'
                }
        except Exception:
            pass

        analysis['infrastructure_reuse'] = {'status': 'unavailable', 'reason': 'No sourced ASN/provider dataset'}

        # Content fingerprinting: HTTP headers pattern
        try:
            conn = http.client.HTTPSConnection(domain, timeout=5)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            headers = dict(response.getheaders())
            analysis['content_fingerprinting'] = {
                'server_header': headers.get('Server', 'unknown'),
                'content_type': headers.get('Content-Type', 'unknown'),
                'security_headers': [h for h in headers if 'security' in h.lower() or 'x-' in h.lower()]
            }
        except Exception:
            pass

        return analysis

    def _identify_infrastructure_clusters(self, domain: str, ips: List[Dict]) -> Dict:
        return {'status': 'unavailable', 'reason': 'No sourced ASN/provider dataset', 'asn_clusters': {}, 'ip_range_clusters': {}, 'cloud_provider_clusters': {}, 'geographic_clusters': {}}

    def _correlate_campaigns(self, domain: str, ips: List[Dict]) -> Dict:
        return {'status': 'unavailable', 'reason': 'Historical case correlation is not implemented', 'similar_domains': [], 'shared_infrastructure': [], 'temporal_patterns': {}, 'technique_patterns': []}

    def _fingerprint_operational_techniques(self, domain: str, ips: List[Dict]) -> Dict:
        """Advanced operational techniques fingerprinting with composite analysis"""
        fingerprints = {
            'server_configuration': {},
            'http_headers_pattern': {},
            'dns_patterns': {},
            'ssl_patterns': {},
            'content_patterns': {},
            'network_behavior': {},
            'behavioral_patterns': {},
            'composite_fingerprint': {}
        }

        # Get primary IP for advanced analysis
        primary_ip = ips[0]['ip'] if ips else None

        # 1. ADVANCED CONTENT-BASED FINGERPRINTING
        content_fp = self._advanced_content_fingerprinting(domain)
        fingerprints['content_patterns'] = content_fp

        # 2. NETWORK BEHAVIOR FINGERPRINTING
        if primary_ip:
            network_fp = self._network_behavior_fingerprinting(primary_ip)
            fingerprints['network_behavior'] = network_fp

        # 3. ADVANCED DNS FINGERPRINTING
        dns_fp = self._advanced_dns_fingerprinting(domain)
        fingerprints['dns_patterns'] = dns_fp

        # 4. BEHAVIORAL PATTERN ANALYSIS
        behavioral_fp = self._behavioral_pattern_analysis(domain)
        fingerprints['behavioral_patterns'] = behavioral_fp

        # 5. SERVER CONFIGURATION (enhanced)
        server_fp = self._enhanced_server_fingerprinting(domain)
        fingerprints['server_configuration'] = server_fp

        # 6. HTTP HEADERS PATTERN (enhanced)
        headers_fp = self._enhanced_headers_fingerprinting(domain)
        fingerprints['http_headers_pattern'] = headers_fp

        # 7. SSL PATTERNS (enhanced)
        if primary_ip:
            ssl_fp = self._ssl_pattern_analysis(primary_ip)
            fingerprints['ssl_patterns'] = ssl_fp

        # 8. CREATE COMPOSITE FINGERPRINT
        composite_hash = self._create_composite_fingerprint(fingerprints, domain, primary_ip)
        fingerprints['composite_fingerprint'] = {
            'hash': composite_hash,
            'components': len([k for k in fingerprints.keys() if fingerprints[k]]),
            'uniqueness_score': self._calculate_fingerprint_uniqueness(fingerprints)
        }

        return fingerprints

    def _correlate_threat_intel_standalone(self, domain: str, ips: List[Dict]) -> Dict:
        intel = {'threat_actor': 'Unknown', 'confidence': 0.0, 'campaigns': [], 'risk_score': 0}
        if not ips:
            return intel

        factors = self._analyze_risk_factors(domain, ips)
        intel['risk_score'] = factors['risk_score']
        intel['confidence'] = factors['confidence']
        actor = self._identify_threat_actor_patterns(domain, ips)
        intel.update(actor)
        return intel

    def _analyze_risk_factors(self, domain: str, ips: List[Dict]) -> Dict:
        risk_score = 0
        if self._check_dns_ttl(domain):
            risk_score += 20
        if self._check_domain_age(domain) == 'new':
            risk_score += 15
        return {'risk_score': risk_score, 'confidence': min(risk_score / 100.0, 1.0)}

    def _check_domain_age(self, domain: str) -> str:
        # No external WHOIS - assume unknown
        return 'unknown'

    def _check_dns_ttl(self, domain: str) -> bool:
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return getattr(answers.rrset, 'ttl', 3600) < 300
        except Exception:
            return False

    def _identify_threat_actor_patterns(self, domain: str, ips: List[Dict]) -> Dict:
        return {'status': 'unavailable', 'reason': 'Domain keywords do not establish an actor', 'threat_actor': 'Unknown', 'campaign_type': None, 'campaigns': [], 'confidence': 0.0}

    def _extract_brand_keywords(self, domain: str) -> List[str]:
        """Extract brand-related keywords from domain"""
        brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'instagram', 'netflix', 'ebay', 'bank',
            'secure', 'verify', 'account', 'update', 'confirm',
            'office365', 'outlook', 'login', 'signin', 'support'
        ]
        found = [brand for brand in brands if brand in domain.lower()]
        return found

    def _identify_hosting_provider(self, ips: List[Dict]) -> str:
        """Identify hosting provider from IP info"""
        if not ips:
            return 'Unknown'

        # Extract ASN/org info from IPs
        providers = []
        for ip_data in ips:
            if 'asn' in ip_data:
                providers.append(ip_data.get('asn', {}).get('org', 'Unknown'))
            elif 'org' in ip_data:
                providers.append(ip_data['org'])

        if not providers:
            return 'Unknown'

        # Most common provider
        from collections import Counter
        return Counter(providers).most_common(1)[0][0]

    def _analyze_geolocation_patterns(self, ips: List[Dict]) -> Dict:
        """Analyze geographic distribution of infrastructure"""
        countries = []
        for ip_data in ips:
            if 'country' in ip_data:
                countries.append(ip_data['country'])
            elif 'cc' in ip_data:
                countries.append(ip_data['cc'])

        high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'NG', 'PK']
        risk_count = sum(1 for c in countries if c in high_risk_countries)

        return {
            'countries': list(set(countries)),
            'high_risk_ratio': risk_count / len(countries) if countries else 0,
            'is_high_risk': risk_count > 0
        }

    def _classify_infrastructure_type(self, ips: List[Dict]) -> str:
        """Classify infrastructure type"""
        # Heuristics for infrastructure classification
        if len(ips) == 1:
            return 'Single-Host'
        elif len(ips) > 10:
            return 'Distributed'
        elif len(ips) > 5:
            return 'Multi-Host'
        else:
            return 'Small-Network'

    def _estimate_domain_age(self, domain: str) -> str:
        """Estimate domain age category"""
        try:
            import whois
            w = whois.whois(domain)
            if hasattr(w, 'creation_date') and w.creation_date:
                from datetime import datetime
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]

                age_days = (datetime.now() - creation).days
                if age_days < 30:
                    return 'Very New (< 30 days)'
                elif age_days < 90:
                    return 'New (< 90 days)'
                elif age_days < 365:
                    return 'Recent (< 1 year)'
                else:
                    return 'Established (> 1 year)'
        except Exception:
            pass
        return 'Unknown'

    def _analyze_certificate_patterns(self, domain: str) -> Dict:
        """Analyze SSL certificate patterns"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'has_cert': True,
                        'issuer': cert.get('issuer', []),
                        'subject': cert.get('subject', []),
                        'is_self_signed': cert.get('issuer') == cert.get('subject'),
                        'validity': cert.get('notAfter', 'Unknown')
                    }
        except Exception:
            return {'has_cert': False, 'is_self_signed': False}

    def _calculate_threat_profile(self, features: Dict) -> Dict:
        return {'status': 'unavailable', 'actor_type': 'Unknown Threat Actor', 'confidence': 0.0, 'reason': 'Attribution confidence is not calibrated'}

    def _identify_campaign_type(self, keywords: List[str]) -> str:
        """Identify campaign type from keywords"""
        if not keywords:
            return 'Generic Phishing'

        # Financial institutions
        financial = ['paypal', 'bank', 'ebay', 'stripe', 'square']
        if any(k in keywords for k in financial):
            return 'Financial Phishing'

        # Tech companies
        tech = ['microsoft', 'apple', 'google', 'amazon', 'office365', 'outlook']
        if any(k in keywords for k in tech):
            return 'Credential Harvesting (Tech)'

        # Social media
        social = ['facebook', 'instagram', 'twitter', 'linkedin']
        if any(k in keywords for k in social):
            return 'Social Media Phishing'

        # Generic
        return 'Brand Impersonation'

    def _generate_le_package_standalone(self, domain: str, ips: List[Dict], infrastructure: Dict, threat_intel: Dict) -> Dict:
        """Generate comprehensive Law Enforcement package"""

        # Executive summary
        threat_actor = threat_intel.get('threat_actor', 'Unknown')
        confidence = threat_intel.get('confidence', 0.0)
        campaigns = threat_intel.get('campaigns', [])

        executive_summary = f"""
PHISHING INFRASTRUCTURE ANALYSIS REPORT

Target Domain: {domain}
Threat Actor: {threat_actor}
Attribution Confidence: {confidence:.1%}
Campaign Type: {', '.join(campaigns) if campaigns else 'Unknown'}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

SUMMARY:
Infrastructure analysis identified {len(ips)} associated IP addresses using {len(set(ip.get('technique') for ip in ips))} discovery techniques.
{'HIGH CONFIDENCE attribution based on infrastructure patterns and domain analysis.' if confidence > 0.7 else 'MEDIUM CONFIDENCE - additional investigation recommended.'}
"""

        # Technical evidence
        ip_evidence = []
        for ip_data in ips:
            evidence = {
                'ip_address': ip_data.get('ip', 'Unknown'),
                'discovery_technique': ip_data.get('technique', 'Unknown'),
                'confidence_level': ip_data.get('confidence', 'Unknown'),
                'asn': ip_data.get('asn', {}),
                'geolocation': {
                    'country': ip_data.get('country', ip_data.get('cc', 'Unknown')),
                    'org': ip_data.get('org', 'Unknown')
                },
                'additional_metadata': {k: v for k, v in ip_data.items()
                                      if k not in ['ip', 'technique', 'confidence', 'asn', 'country', 'cc', 'org']}
            }
            ip_evidence.append(evidence)

        technical_evidence = {
            'target_domain': domain,
            'ip_addresses': ip_evidence,
            'infrastructure_summary': infrastructure,
            'threat_intelligence': {
                'threat_actor': threat_actor,
                'confidence': confidence,
                'campaigns': campaigns,
                'attribution_notes': threat_intel.get('attribution_notes', []),
                'infrastructure_features': threat_intel.get('infrastructure_features', {})
            },
            'collection_metadata': {
                'techniques_used': list(set(ip.get('technique') for ip in ips)),
                'total_ips_discovered': len(ips),
                'analysis_completeness': self._assess_analysis_completeness(ips)
            }
        }

        # Investigation notes
        investigation_notes = [
            f"Discovered {len(ips)} IP addresses using {len(set(ip.get('technique') for ip in ips))} techniques",
            f"Threat actor identified as: {threat_actor} (confidence: {confidence:.1%})",
        ]

        if threat_intel.get('attribution_notes'):
            investigation_notes.extend(threat_intel['attribution_notes'])

        # Add recommendations
        recommendations = self._generate_recommendations(threat_intel, infrastructure)

        # Abuse contacts
        abuse_contacts = self._extract_abuse_contacts(ips, infrastructure)

        return {
            'package_version': '2.0',
            'generated_at': datetime.now().isoformat(),
            'executive_summary': executive_summary.strip(),
            'technical_evidence': technical_evidence,
            'investigation_notes': investigation_notes,
            'recommendations': recommendations,
            'abuse_contacts': abuse_contacts,
            'legal_disclaimer': 'This report is generated for lawful investigation purposes only. All data collected using authorized techniques.'
        }

    def _assess_analysis_completeness(self, ips: List[Dict]) -> str:
        """Assess how complete the analysis is"""
        techniques_used = set(ip.get('technique') for ip in ips)
        total_possible_techniques = 10  # Number of techniques in _find_real_ips

        completeness_ratio = len(techniques_used) / total_possible_techniques

        if completeness_ratio >= 0.8:
            return 'Comprehensive'
        elif completeness_ratio >= 0.5:
            return 'Substantial'
        elif completeness_ratio >= 0.3:
            return 'Partial'
        else:
            return 'Limited'

    def _generate_recommendations(self, threat_intel: Dict, infrastructure: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        confidence = threat_intel.get('confidence', 0.0)

        if confidence > 0.7:
            recommendations.append('HIGH PRIORITY: Immediate takedown recommended')
            recommendations.append('Contact hosting provider and registrar for expedited suspension')
        elif confidence > 0.5:
            recommendations.append('MEDIUM PRIORITY: Further investigation recommended before takedown')
        else:
            recommendations.append('LOW PRIORITY: Additional evidence collection needed')

        # Infrastructure-specific recommendations
        if infrastructure.get('infrastructure_type') == 'Distributed':
            recommendations.append('Coordinate with multiple hosting providers for concurrent takedown')

        features = threat_intel.get('infrastructure_features', {})
        if features.get('domain_age') == 'Very New (< 30 days)':
            recommendations.append('Consider registrar suspension due to newly registered malicious domain')

        if not features.get('certificate_usage', {}).get('has_cert'):
            recommendations.append('No HTTPS - likely credential harvesting, prioritize user notification')

        return recommendations

    def _extract_abuse_contacts(self, ips: List[Dict], infrastructure: Dict) -> List[Dict]:
        """Extract abuse contact information"""
        contacts = []

        # Extract from WHOIS data
        for ip_data in ips:
            if 'emails' in ip_data:
                for email in ip_data['emails']:
                    if 'abuse' in email.lower():
                        contacts.append({
                            'type': 'ASN Abuse',
                            'contact': email,
                            'ip': ip_data.get('ip', 'Unknown')
                        })

            # ASN-based abuse contacts
            if 'asn' in ip_data and 'org' in ip_data['asn']:
                org = ip_data['asn']['org']
                # Generate likely abuse contact
                abuse_email = f"abuse@{org.lower().replace(' ', '')}.com"
                contacts.append({
                    'type': 'Estimated ASN Abuse',
                    'contact': abuse_email,
                    'org': org,
                    'note': 'Estimated contact - verify before use'
                })

        # Remove duplicates
        seen = set()
        unique_contacts = []
        for contact in contacts:
            key = contact.get('contact')
            if key and key not in seen:
                seen.add(key)
                unique_contacts.append(contact)

        return unique_contacts

    # Convenience helpers for batch operations
    def hunt_from_case(self, case_id: str) -> Dict:
        case_path = f"cases/{case_id}/manifest.json"
        if os.path.exists(case_path):
            with open(case_path, 'r') as f:
                data = json.load(f)
        else:
            data = {}
        domains = data.get('suspicious_domains', [])
        results = []
        for d in domains:
            results.append(self.hunt_from_domain(d))
        return {'case_id': case_id, 'results': results}

    
    def _check_bulletproof_hosting(self, ips: List[Dict]) -> bool:
        return None  # No sourced hosting reputation dataset.
    
    def _check_geolocation_risk(self, ips: List[Dict]) -> bool:
        return None  # Geography alone does not establish malicious hosting.
    
    def _identify_threat_actor_patterns(self, domain: str, ips: List[Dict]) -> Dict:
        return {'status': 'unavailable', 'reason': 'Domain keywords do not establish an actor', 'threat_actor': 'Unknown', 'campaign_type': None, 'campaigns': [], 'confidence': 0.0}
    
    def _generate_le_package(self, domain: str, ips: List[Dict], infrastructure: Dict, threat_intel: Dict) -> Dict:
        """Genera package completo per law enforcement"""
        return {
            'executive_summary': f"Criminal Infrastructure Analysis Report\n"
                               f"Target: {domain}\n"
                               f"Threat Actor: {threat_intel.get('threat_actor', 'Unknown')}\n"
                               f"Confidence: {threat_intel.get('confidence', 0):.0%}\n"
                               f"Risk Score: {threat_intel.get('risk_score', 0)}/100",
            
            'technical_evidence': {
                'ips_identified': [ip['ip'] for ip in ips],
                'hosting_infrastructure': {
                    'provider': infrastructure.get('asn_org', 'Unknown'),
                    'asn': infrastructure.get('asn', 'Unknown'),
                    'location': infrastructure.get('geolocation', 'Unknown')
                },
                'network_information': {
                    'related_domains': infrastructure.get('related_domains', []),
                    'blacklist_status': infrastructure.get('blacklist_status', [])
                }
            },
            
            'threat_analysis': {
                'actor_attribution': threat_intel.get('threat_actor', 'Unknown'),
                'campaign_identification': threat_intel.get('campaigns', []),
                'risk_assessment': threat_intel.get('risk_score', 0),
                'confidence_level': threat_intel.get('confidence', 0)
            },
            
            'recommended_actions': [
                f"Submit abuse report to: {infrastructure.get('asn_org', 'Unknown')}",
                "Contact local CERT for takedown assistance",
                "Share indicators with threat intelligence community",
                "Monitor for related infrastructure changes"
            ],
            
            'investigation_notes': [
                f"Primary IP: {ips[0]['ip'] if ips else 'Unknown'}",
                f"Hunting techniques used: {', '.join(set(ip['technique'] for ip in ips))}",
                f"Infrastructure first identified: {datetime.now().strftime('%Y-%m-%d')}",
                "Evidence collected: IP addresses, hosting information, threat actor patterns"
            ]
        }
    
    # Metodi per casi multipli (mantenuti dallo schema originale)
    def hunt_from_case(self, case_id: str) -> Dict:
        """Caccia partendo da caso PAW esistente"""
        case_data = self._load_case_data(case_id)
        domains = case_data.get('suspicious_domains', [])
        
        criminal_intel = []
        for domain in domains:
            intel = self.hunt_from_domain(domain)
            criminal_intel.append(intel)
        
        return {
            'case_id': case_id,
            'domains_hunted': domains,
            'criminal_intel': criminal_intel,
            'summary': self._generate_summary(criminal_intel)
        }
    
    def hunt_from_domains(self, domains: List[str]) -> Dict:
        """Caccia partendo da lista di domini"""
        criminal_intel = []
        for domain in domains:
            intel = self.hunt_from_domain(domain)
            criminal_intel.append(intel)
        
        return {
            'domains_hunted': domains,
            'criminal_intel': criminal_intel,
            'summary': self._generate_summary(criminal_intel)
        }
    
    def _extract_domain(self, url: str) -> str:
        """Estrae dominio da URL"""
        if '://' in url:
            url = url.split('://', 1)[1]
        if '/' in url:
            url = url.split('/')[0]
        if ':' in url:
            url = url.split(':')[0]
        return url

    def _technique_passive_dns_reverse(self, domain: str) -> Dict:
        """Passive DNS: cerca altri domini con lo stesso IP (reverse DNS esteso)"""
        try:
            # Prima ottieni l'IP principale
            primary_ip = socket.gethostbyname(domain)
            # Prova reverse DNS esteso (potrebbe rivelare altri domini)
            try:
                names = socket.gethostbyaddr(primary_ip)
                for alias in names[1]:  # aliases
                    if alias != domain and alias != names[0]:
                        try:
                            ip_check = socket.gethostbyname(alias)
                            if ip_check == primary_ip:
                                return {'ip': primary_ip, 'technique': 'passive_dns_reverse', 'confidence': 'medium', 'related_domain': alias}
                        except Exception:
                            continue
            except Exception:
                pass
        except Exception:
            pass
        return {}

    def _technique_ttl_analysis(self, domain: str) -> Dict:
        """Analizza TTL DNS per pattern di evasione detection"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            if answers:
                ttl = answers.rrset.ttl
                # TTL bassi (<300) spesso indicano domini temporanei/phishing
                if ttl < 300:
                    ip = str(answers[0])
                    return {'ip': ip, 'technique': 'ttl_analysis', 'confidence': 'low', 'ttl': ttl, 'note': 'Low TTL suggests temporary domain'}
        except Exception:
            pass
        return {}

    def _technique_server_fingerprinting(self, domain: str) -> Dict:
        """Fingerprinting server HTTP per identificare configurazioni specifiche"""
        try:
            conn = http.client.HTTPSConnection(domain, timeout=5)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            server_header = response.getheader('Server')
            if server_header:
                # Analizza header Server per pattern noti
                if 'nginx' in server_header.lower():
                    ip = socket.gethostbyname(domain)
                    return {'ip': ip, 'technique': 'server_fingerprinting', 'confidence': 'medium', 'server': server_header, 'note': 'Nginx server detected'}
        except Exception:
            pass
        return {}

    def _load_case_data(self, case_id: str) -> Dict:
        """Carica dati caso PAW esistente"""
        case_path = f"cases/{case_id}/manifest.json"
        if os.path.exists(case_path):
            with open(case_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _generate_summary(self, criminal_intel: List[Dict]) -> Dict:
        """Genera summary dell'operazione di hunting"""
        total_domains = len(criminal_intel)
        unique_ips = set()
        threat_actors = set()
        
        for intel in criminal_intel:
            for ip in intel.get('real_ips', []):
                unique_ips.add(ip['ip'])
            threat_actors.add(intel.get('threat_intel', {}).get('threat_actor', 'Unknown'))
        
        return {
            'total_domains_hunted': total_domains,
            'unique_criminal_ips': len(unique_ips),
            'threat_actors_identified': list(threat_actors),
            'highest_risk_score': max(
                [intel.get('threat_intel', {}).get('risk_score', 0) for intel in criminal_intel]
            ) if criminal_intel else 0
        }

    def _advanced_content_fingerprinting(self, domain: str) -> Dict:
        """Advanced content-based fingerprinting with HTML, JS, CSS analysis - PENETRATING VERSION"""
        try:
            import requests
            if not BS4_AVAILABLE:
                return {'error': 'BeautifulSoup not available', 'error_type': 'missing_dependency'}

            # Enhanced session with realistic headers to bypass basic protections
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            })

            fingerprints = {}
            response = None

            # Try multiple HTTP methods and ports for penetration
            methods_and_ports = [
                ('HEAD', 80, 'http'),
                ('GET', 80, 'http'),
                ('HEAD', 443, 'https'),
            ]

            successful_response = None
            for method, port, scheme in methods_and_ports:
                try:
                    url = f"{scheme}://{domain}"
                    if port == 443:
                        url = f"https://{domain}"

                    # Use SSL verification from environment variable (default: True)
                    verify_ssl = os.environ.get('PAW_VERIFY_SSL', 'true').lower() == 'true'
                    response = session.request(method, url, timeout=8, allow_redirects=True, verify=verify_ssl)

                    if response.status_code < 400 or response.status_code in [403, 409]:  # Accept some error codes
                        successful_response = response
                        fingerprints['successful_method'] = f"{method}_{scheme}_{port}"
                        fingerprints['final_url'] = response.url
                        fingerprints['status_code'] = response.status_code
                        break

                except requests.exceptions.RequestException as e:
                    fingerprints[f'{method}_{scheme}_{port}_error'] = str(e)
                    continue

            if not successful_response:
                return {
                    'error': 'All HTTP requests failed',
                    'error_type': 'connection_failed',
                    'attempted_methods': list(fingerprints.keys())
                }

            response = successful_response

            # Parse HTML content
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                return {
                    'error': f'HTML parsing failed: {e}',
                    'error_type': 'parsing_failed',
                    'raw_content_length': len(response.text) if response.text else 0
                }

            # 1. HTML Structure Analysis
            clean_html = re.sub(r'\s+', ' ', soup.prettify())
            fingerprints['html_structure_hash'] = hashlib.md5(clean_html.encode()).hexdigest()
            fingerprints['html_length'] = len(clean_html)
            fingerprints['has_forms'] = len(soup.find_all('form')) > 0
            fingerprints['has_scripts'] = len(soup.find_all('script')) > 0

            # 2. Enhanced JavaScript Fingerprinting
            scripts = soup.find_all('script')
            js_patterns = []
            obfuscation_indicators = []
            suspicious_js_patterns = []

            for script in scripts:
                js_content = ''
                if script.string:
                    js_content = script.string
                elif script.get('src'):
                    # Try to fetch external JS
                    try:
                        js_url = script['src']
                        if not js_url.startswith('http'):
                            js_url = f"{response.url.rstrip('/')}/{js_url.lstrip('/')}"
                        verify_ssl = os.environ.get('PAW_VERIFY_SSL', 'true').lower() == 'true'
                        js_response = session.get(js_url, timeout=5, verify=verify_ssl)
                        if js_response.status_code == 200:
                            js_content = js_response.text
                            fingerprints['external_js_loaded'] = True
                    except:
                        continue

                if js_content:
                    # Advanced obfuscation detection
                    if re.search(r'fromCharCode\s*\(', js_content, re.IGNORECASE):
                        js_patterns.append('charcode_obfuscation')
                        obfuscation_indicators.append('fromCharCode')
                    if re.search(r'\beval\s*\(', js_content, re.IGNORECASE):
                        js_patterns.append('eval_obfuscation')
                        obfuscation_indicators.append('eval_execution')
                        suspicious_js_patterns.append('dynamic_code_execution')
                    if re.search(r'document\.write\s*\(', js_content, re.IGNORECASE):
                        js_patterns.append('document_write_injection')
                    if re.search(r'unescape\s*\(', js_content, re.IGNORECASE):
                        js_patterns.append('unescape_obfuscation')
                        obfuscation_indicators.append('unescape')
                    if re.search(r'String\.fromCharCode', js_content, re.IGNORECASE):
                        js_patterns.append('string_fromcharcode')
                    if re.search(r'atob\s*\(', js_content, re.IGNORECASE):
                        js_patterns.append('base64_decode')
                        obfuscation_indicators.append('atob')
                    if re.search(r'btoa\s*\(', js_content, re.IGNORECASE):
                        js_patterns.append('base64_encode')
                    if re.search(r'\\x[0-9a-fA-F]{2}', js_content):
                        js_patterns.append('hex_encoding')
                        obfuscation_indicators.append('hex_escape')
                    if re.search(r'window\.location', js_content, re.IGNORECASE):
                        suspicious_js_patterns.append('location_manipulation')
                    if re.search(r'setTimeout\s*\(\s*eval', js_content, re.IGNORECASE):
                        suspicious_js_patterns.append('timed_eval_execution')

            fingerprints['js_patterns'] = js_patterns
            fingerprints['obfuscation_indicators'] = obfuscation_indicators
            fingerprints['suspicious_js_patterns'] = suspicious_js_patterns
            fingerprints['total_scripts'] = len(scripts)

            # 3. Enhanced CSS/Resource Fingerprinting
            css_links = soup.find_all('link', rel='stylesheet')
            css_hashes = []
            external_resources = []

            for link in css_links:
                href = link.get('href')
                if href:
                    css_hashes.append(hashlib.md5(href.encode()).hexdigest()[:8])
                    if href.startswith(('http://', 'https://', '//')):
                        external_resources.append(href)

            # Check for images and other resources
            images = soup.find_all('img')
            image_sources = []
            for img in images:
                src = img.get('src')
                if src:
                    image_sources.append(src)
                    if src.startswith(('http://', 'https://', '//')):
                        external_resources.append(src)

            fingerprints['css_references_hash'] = hashlib.md5(str(css_hashes).encode()).hexdigest()[:16]
            fingerprints['css_count'] = len(css_links)
            fingerprints['image_count'] = len(images)
            fingerprints['external_resources'] = external_resources[:10]  # Limit to first 10
            fingerprints['external_resources_count'] = len(external_resources)

            # 4. Advanced Form Analysis
            forms = soup.find_all('form')
            form_structures = []
            phishing_indicators = []

            for form in forms:
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': [],
                    'input_names': [],
                    'input_types': []
                }

                inputs = form.find_all('input')
                for input_tag in inputs:
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name', '')
                    input_value = input_tag.get('value', '')

                    form_data['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })

                    if input_name:
                        form_data['input_names'].append(input_name)
                    form_data['input_types'].append(input_type)

                    # Phishing indicators
                    if input_type == 'password':
                        phishing_indicators.append('password_field')
                    if 'email' in input_name.lower() or 'mail' in input_name.lower():
                        phishing_indicators.append('email_field')
                    if 'credit' in input_name.lower() or 'card' in input_name.lower():
                        phishing_indicators.append('credit_card_field')

                # Check for common phishing form patterns
                if any(inp['type'] == 'password' for inp in form_data['inputs']):
                    if any('email' in name.lower() for name in form_data['input_names']):
                        phishing_indicators.append('credentials_harvesting_form')

                form_structures.append(form_data)

            fingerprints['form_structures'] = form_structures
            fingerprints['forms_count'] = len(forms)
            fingerprints['phishing_indicators'] = phishing_indicators

            # 5. Meta tags and page structure analysis
            title = soup.find('title')
            fingerprints['page_title'] = title.text.strip() if title else ''

            meta_desc = soup.find('meta', attrs={'name': 'description'})
            fingerprints['meta_description'] = meta_desc.get('content', '') if meta_desc else ''

            # Check for common phishing meta patterns
            if title and any(word in title.text.lower() for word in ['login', 'signin', 'verify', 'secure', 'account']):
                fingerprints['suspicious_title'] = True

            # 6. Content analysis for phishing patterns
            text_content = soup.get_text()
            suspicious_words = ['verify', 'confirm', 'urgent', 'suspended', 'limited', 'security', 'alert']
            found_suspicious = [word for word in suspicious_words if word in text_content.lower()]
            fingerprints['suspicious_content_words'] = found_suspicious

            # 7. Cookie analysis
            cookies = response.cookies
            cookie_analysis = {
                'count': len(cookies),
                'names': [cookie.name for cookie in cookies],
                'has_session_cookies': any('session' in cookie.name.lower() or 'unique' in cookie.name.lower() for cookie in cookies)
            }
            fingerprints['cookie_analysis'] = cookie_analysis

            # 8. Response headers analysis
            response_headers = dict(response.headers)
            security_headers = {}
            custom_headers = {}

            for header, value in response_headers.items():
                header_lower = header.lower()
                if header_lower in ['x-frame-options', 'x-content-type-options', 'content-security-policy', 'x-xss-protection']:
                    security_headers[header] = value
                elif header_lower.startswith('x-') or header_lower.startswith('cf-'):
                    custom_headers[header] = value

            fingerprints['security_headers'] = security_headers
            fingerprints['custom_headers'] = custom_headers
            fingerprints['response_headers_count'] = len(response_headers)

            return fingerprints

        except Exception as e:
            return {
                'error': str(e),
                'error_type': 'content_fingerprinting_failed'
            }
            return {'error': str(e), 'error_type': 'content_fingerprinting_failed'}

    def _network_behavior_fingerprinting(self, ip: str) -> Dict:
        """Network behavior fingerprinting with timing and protocol analysis"""
        fingerprints = {}

        # 1. TCP Connection Behavior
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            sock.connect((ip, 80))
            connection_time = time.time() - start_time
            fingerprints['tcp_connection_time'] = round(connection_time, 3)

            # 2. HTTP Banner Grabbing with timing
            sock.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            banner_start = time.time()
            response = sock.recv(2048)
            banner_time = time.time() - banner_start

            banner_text = response.decode('utf-8', errors='ignore')
            fingerprints['http_banner'] = banner_text[:200]  # First 200 chars
            fingerprints['banner_response_time'] = round(banner_time, 3)

            # Parse banner for additional info
            banner_lines = banner_text.split('\r\n')
            fingerprints['http_status_line'] = banner_lines[0] if banner_lines else ''
            fingerprints['server_header_raw'] = ''
            for line in banner_lines:
                if line.lower().startswith('server:'):
                    fingerprints['server_header_raw'] = line.split(':', 1)[1].strip()
                    break

            sock.close()

        except Exception as e:
            fingerprints['tcp_error'] = str(e)

        # 3. SSL/TLS Fingerprinting (port 443)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    fingerprints['ssl_cipher'] = str(ssock.cipher())
                    fingerprints['ssl_version'] = ssock.version()
                    fingerprints['ssl_has_certificate'] = True

                    # Certificate analysis
                    cert = ssock.getpeercert()
                    if cert:
                        fingerprints['cert_issuer'] = dict(cert.get('issuer', []))
                        fingerprints['cert_subject'] = dict(cert.get('subject', []))
                        fingerprints['cert_notbefore'] = cert.get('notBefore', '')
                        fingerprints['cert_notafter'] = cert.get('notAfter', '')

        except Exception as e:
            fingerprints['ssl_error'] = str(e)
            fingerprints['ssl_has_certificate'] = False

        # 4. Port scanning basics (common ports)
        common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        fingerprints['open_ports'] = open_ports
        fingerprints['ports_scanned'] = len(common_ports)

        return fingerprints

    def _advanced_dns_fingerprinting(self, domain: str) -> Dict:
        """Advanced DNS fingerprinting with all record types and analysis"""
        fingerprints = {}

        try:
            # 1. Complete DNS record enumeration
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR']
            dns_records = {}

            for record_type in record_types:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except:
                    dns_records[record_type] = []

            fingerprints['dns_records'] = dns_records

            # 2. TTL Analysis with statistics
            if dns_records.get('A'):
                try:
                    answers = self.resolver.resolve(domain, 'A')
                    ttl_values = [answer.ttl for answer in answers]
                    fingerprints['ttl_values'] = ttl_values
                    fingerprints['ttl_min'] = min(ttl_values)
                    fingerprints['ttl_max'] = max(ttl_values)
                    fingerprints['ttl_avg'] = round(sum(ttl_values) / len(ttl_values), 2)
                    fingerprints['ttl_variance'] = round(statistics.variance(ttl_values), 2) if len(ttl_values) > 1 else 0

                    # TTL pattern analysis
                    if min(ttl_values) < 300:
                        fingerprints['ttl_category'] = 'suspicious'
                        fingerprints['evasion_indicator'] = True
                        fingerprints['ttl_evasion_score'] = (300 - min(ttl_values)) / 300
                    else:
                        fingerprints['ttl_category'] = 'normal'
                        fingerprints['evasion_indicator'] = False
                        fingerprints['ttl_evasion_score'] = 0

                except:
                    fingerprints['ttl_analysis_error'] = 'Failed to analyze TTL'

            # 3. Reverse DNS for all IPs
            reverse_lookups = {}
            if dns_records.get('A'):
                for ip in dns_records['A']:
                    try:
                        import dns.reversename
                        rev_name = dns.reversename.from_address(ip)
                        reverse_answers = self.resolver.resolve(rev_name, "PTR")
                        reverse_lookups[ip] = str(reverse_answers[0])
                    except:
                        reverse_lookups[ip] = "No PTR record"

            fingerprints['reverse_dns'] = reverse_lookups

            # 4. DNSSEC analysis
            try:
                dnssec_answers = self.resolver.resolve(domain, 'DNSKEY')
                fingerprints['dnssec_enabled'] = len(dnssec_answers) > 0
            except:
                fingerprints['dnssec_enabled'] = False

        except Exception as e:
            fingerprints['dns_error'] = str(e)

        return fingerprints

    def _behavioral_pattern_analysis(self, domain: str) -> Dict:
        """Behavioral pattern analysis with temporal and complexity metrics"""
        fingerprints = {}

        fingerprints['timing_analysis'] = {'status': 'unavailable', 'reason': 'No observed attacker activity timestamps'}

        # 2. Domain complexity analysis
        domain_length = len(domain)
        vowel_count = len([c for c in domain if c.lower() in 'aeiou'])
        digit_count = len([c for c in domain if c.isdigit()])
        special_count = len([c for c in domain if not c.isalnum()])

        fingerprints['domain_complexity'] = {
            'length': domain_length,
            'vowel_ratio': round(vowel_count / domain_length, 3) if domain_length > 0 else 0,
            'digit_ratio': round(digit_count / domain_length, 3) if domain_length > 0 else 0,
            'special_char_ratio': round(special_count / domain_length, 3) if domain_length > 0 else 0,
            'entropy_score': self._calculate_entropy(domain),
            'is_suspicious_length': domain_length > 20 or domain_length < 4
        }

        # 3. Domain pattern analysis
        domain_lower = domain.lower()
        suspicious_patterns = []

        # Check for DGA-like patterns
        if fingerprints['domain_complexity']['entropy_score'] > 4.0:
            suspicious_patterns.append('high_entropy_dga_pattern')

        # Check for phishing patterns
        if 'login' in domain_lower or 'secure' in domain_lower or 'bank' in domain_lower:
            suspicious_patterns.append('phishing_keyword_domain')

        # Check for random-like domains
        if len(set(domain_lower)) / len(domain_lower) > 0.8:  # High character diversity
            suspicious_patterns.append('random_character_distribution')

        fingerprints['suspicious_domain_patterns'] = suspicious_patterns

        return fingerprints

    def _enhanced_server_fingerprinting(self, domain: str) -> Dict:
        """Enhanced server fingerprinting with multiple techniques"""
        fingerprints = {}

        try:
            # Basic HTTP fingerprinting
            conn = http.client.HTTPConnection(domain, timeout=5)
            conn.request("HEAD", "/")
            response = conn.getresponse()

            server_header = response.getheader('Server', '')
            fingerprints['server_header'] = server_header

            # Server type detection
            if 'nginx' in server_header.lower():
                fingerprints['server_type'] = 'nginx'
                fingerprints['uniqueness_score'] = 0.7
            elif 'apache' in server_header.lower():
                fingerprints['server_type'] = 'apache'
                fingerprints['uniqueness_score'] = 0.6
            elif 'iis' in server_header.lower():
                fingerprints['server_type'] = 'iis'
                fingerprints['uniqueness_score'] = 0.8
            else:
                fingerprints['server_type'] = 'unknown'
                fingerprints['uniqueness_score'] = 0.3

            # Version extraction
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', server_header)
            fingerprints['version_pattern'] = version_match.group(1) if version_match else 'unknown'

            # Additional headers analysis
            all_headers = dict(response.getheaders())
            fingerprints['all_response_headers'] = all_headers

            conn.close()

        except Exception as e:
            fingerprints['server_error'] = str(e)

        return fingerprints

    def _enhanced_headers_fingerprinting(self, domain: str) -> Dict:
        """Enhanced HTTP headers fingerprinting"""
        fingerprints = {}

        try:
            conn = http.client.HTTPConnection(domain, timeout=5)
            conn.request("HEAD", "/")
            response = conn.getresponse()

            headers = dict(response.getheaders())

            # Security headers
            security_headers = []
            for header_name in headers:
                if any(keyword in header_name.lower() for keyword in ['security', 'x-', 'csp', 'hsts', 'xss', 'csrf']):
                    security_headers.append(header_name)

            # Custom headers (X-*)
            custom_headers = [h for h in headers if h.startswith('X-') or h.startswith('x-')]

            # Cookie analysis
            set_cookie = headers.get('Set-Cookie', '')
            has_cookies = bool(set_cookie)

            fingerprints['security_headers'] = security_headers
            fingerprints['custom_headers'] = custom_headers
            fingerprints['has_cookies'] = has_cookies
            fingerprints['fingerprint_score'] = (len(security_headers) * 0.1) + (len(custom_headers) * 0.2)

            if set_cookie:
                fingerprints['cookie_analysis'] = {
                    'has_session_cookie': 'session' in set_cookie.lower() or 'jsessionid' in set_cookie.lower(),
                    'has_tracking_cookie': 'track' in set_cookie.lower() or 'unique' in set_cookie.lower(),
                    'cookie_length': len(set_cookie)
                }

        except Exception as e:
            fingerprints['headers_error'] = str(e)

        return fingerprints

    def _ssl_pattern_analysis(self, ip: str) -> Dict:
        """SSL/TLS pattern analysis"""
        fingerprints = {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    # Certificate chain analysis
                    cert = ssock.getpeercert()
                    fingerprints['has_certificate'] = bool(cert)

                    if cert:
                        # Certificate validity
                        not_before = cert.get('notBefore', '')
                        not_after = cert.get('notAfter', '')
                        fingerprints['cert_validity'] = {
                            'not_before': not_before,
                            'not_after': not_after
                        }

                        # Subject Alternative Names
                        san = cert.get('subjectAltName', [])
                        fingerprints['san_domains'] = [name[1] for name in san if name[0] == 'DNS']

                        # Certificate fingerprint
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_hash = hashlib.sha256(cert_der).hexdigest()
                        fingerprints['cert_fingerprint_sha256'] = cert_hash

                        # Self-signed detection
                        issuer = dict(cert.get('issuer', []))
                        subject = dict(cert.get('subject', []))
                        is_self_signed = issuer == subject
                        fingerprints['is_self_signed'] = is_self_signed

        except Exception as e:
            fingerprints['ssl_analysis_error'] = str(e)

        return fingerprints

    def _create_composite_fingerprint(self, fingerprints: Dict, domain: str, ip: str) -> str:
        """Create composite fingerprint hash from all analysis components"""
        # Collect all non-error components
        components = {}

        for key, value in fingerprints.items():
            if value and not isinstance(value, dict) or (isinstance(value, dict) and 'error' not in value):
                components[key] = value

        # Add domain and IP context
        components['domain'] = domain
        components['primary_ip'] = ip
        components['timestamp'] = datetime.now().isoformat()

        # Create deterministic JSON string
        fingerprint_json = json.dumps(components, sort_keys=True, default=str)

        # Generate SHA256 hash
        composite_hash = hashlib.sha256(fingerprint_json.encode()).hexdigest()

        return composite_hash

    def _calculate_fingerprint_uniqueness(self, fingerprints: Dict) -> float:
        """Calculate uniqueness score based on fingerprint components"""
        score = 0.0
        total_components = 0

        # Server uniqueness (nginx is common, IIS is unique)
        if fingerprints.get('server_configuration', {}).get('server_type') == 'iis':
            score += 0.3
        elif fingerprints.get('server_configuration', {}).get('server_type') == 'nginx':
            score += 0.1
        total_components += 1

        # Headers uniqueness
        headers_score = fingerprints.get('http_headers_pattern', {}).get('fingerprint_score', 0)
        score += min(headers_score, 0.4)  # Cap at 0.4
        total_components += 1

        # Content uniqueness
        if fingerprints.get('content_patterns', {}).get('obfuscation_indicators'):
            score += len(fingerprints['content_patterns']['obfuscation_indicators']) * 0.1
        total_components += 1

        # Behavioral uniqueness
        if fingerprints.get('behavioral_patterns', {}).get('suspicious_domain_patterns'):
            score += len(fingerprints['behavioral_patterns']['suspicious_domain_patterns']) * 0.1
        total_components += 1

        # Network uniqueness
        if fingerprints.get('network_behavior', {}).get('tcp_connection_time'):
            # Unusual timing gets higher score
            timing = fingerprints['network_behavior']['tcp_connection_time']
            if timing > 1.0:  # Slow connection
                score += 0.2
            elif timing < 0.1:  # Very fast connection
                score += 0.15
        total_components += 1

        return round(score / total_components, 3) if total_components > 0 else 0.0

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy for domain analysis"""
        if not string:
            return 0.0

        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return round(entropy, 3)
