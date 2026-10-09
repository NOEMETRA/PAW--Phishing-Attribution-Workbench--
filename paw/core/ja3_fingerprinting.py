# ja3_fingerprinting.py - JA3 and JA3S Fingerprint Analysis
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import json

logger = logging.getLogger(__name__)

class JA3FingerprintAnalyzer:
    """Analyze JA3 and JA3S fingerprints for TLS client/server identification"""

    def __init__(self):
        # Unverified built-in fingerprint labels removed.
        self.known_ja3_fingerprints = {}
        self.known_ja3s_fingerprints = {}

    def analyze_ja3_from_network_logs(self, network_logs: List[Dict]) -> Dict[str, Any]:
        """Extract and analyze JA3 fingerprints from network capture logs"""
        result = {
            'ja3_fingerprints': [],
            'ja3s_fingerprints': [],
            'client_identifications': [],
            'server_identifications': [],
            'handshake_patterns': {},
            'suspicious_activity': [],
            'attribution_hints': {}
        }

        ja3_hashes = set()
        ja3s_hashes = set()

        for log in network_logs:
            if isinstance(log, dict):
                # Extract JA3 from ClientHello
                if 'tls' in log or 'ssl' in log:
                    tls_data = log.get('tls') or log.get('ssl')

                    if tls_data:
                        # Client fingerprint
                        ja3_hash = self._extract_ja3_from_client_hello(tls_data.get('client_hello', tls_data))
                        if ja3_hash and ja3_hash not in ja3_hashes:
                            ja3_hashes.add(ja3_hash)
                            result['ja3_fingerprints'].append({
                                'hash': ja3_hash,
                                'timestamp': log.get('timestamp'),
                                'destination': log.get('destination'),
                                'source_ip': log.get('source_ip'),
                                'identified_as': self.known_ja3_fingerprints.get(ja3_hash, 'Unknown')
                            })

                        # Server fingerprint
                        ja3s_hash = self._extract_ja3s_from_server_hello(tls_data.get('server_hello', tls_data))
                        if ja3s_hash and ja3s_hash not in ja3s_hashes:
                            ja3s_hashes.add(ja3s_hash)
                            result['ja3s_fingerprints'].append({
                                'hash': ja3s_hash,
                                'timestamp': log.get('timestamp'),
                                'source': log.get('source'),
                                'destination_ip': log.get('destination_ip'),
                                'identified_as': self.known_ja3s_fingerprints.get(ja3s_hash, 'Unknown')
                            })

        # Identify clients and servers
        result['client_identifications'] = self._identify_clients(result['ja3_fingerprints'])
        result['server_identifications'] = self._identify_servers(result['ja3s_fingerprints'])

        # Analyze handshake patterns
        result['handshake_patterns'] = self._analyze_handshake_patterns(network_logs)

        # Detect suspicious activity
        result['suspicious_activity'] = self._detect_suspicious_ja3_activity(result)

        # Generate attribution hints
        result['attribution_hints'] = self._generate_ja3_attribution_hints(result)

        result['status'] = 'completed' if ja3_hashes or ja3s_hashes else 'unavailable'
        if result['status'] == 'unavailable':
            result['reason'] = 'No captured TLS handshake fields; HTTP logs cannot establish JA3'
        return result

    def _extract_ja3_from_client_hello(self, client_hello: Dict) -> Optional[str]:
        """Extract JA3 fingerprint from ClientHello data"""
        try:
            # JA3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
            if 'version' not in client_hello or 'cipher_suites' not in client_hello:
                return None
            version = client_hello['version']
            ciphers = client_hello.get('cipher_suites', [])
            extensions = client_hello.get('extensions', [])
            curves = client_hello.get('elliptic_curves', [])
            formats = client_hello.get('ec_point_formats', [])

            # Convert to strings and sort
            cipher_str = '-'.join(str(c) for c in [v for v in ciphers if v not in {0x0a0a + 0x1010 * i for i in range(16)}])
            extension_str = '-'.join(str(e) for e in [v for v in extensions if v not in {0x0a0a + 0x1010 * i for i in range(16)}])
            curve_str = '-'.join(str(c) for c in [v for v in curves if v not in {0x0a0a + 0x1010 * i for i in range(16)}])
            format_str = '-'.join(str(f) for f in formats)

            # Create JA3 string
            ja3_string = f"{version},{cipher_str},{extension_str},{curve_str},{format_str}"

            # Create MD5 hash
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

            return ja3_hash

        except Exception as e:
            logger.warning(f"JA3 extraction failed: {e}")
            return None

    def _extract_ja3s_from_server_hello(self, server_hello: Dict) -> Optional[str]:
        """Extract JA3S fingerprint from ServerHello data"""
        try:
            # JA3S = SSLVersion,Cipher,SSLExtension
            if 'version' not in server_hello or 'cipher_suite' not in server_hello:
                return None
            version = server_hello['version']
            cipher = server_hello.get('cipher_suite', '')
            extensions = server_hello.get('extensions', [])

            # Convert extensions to string and sort
            extension_str = '-'.join(str(e) for e in [v for v in extensions if v not in {0x0a0a + 0x1010 * i for i in range(16)}])

            # Create JA3S string
            ja3s_string = f"{version},{cipher},{extension_str}"

            # Create MD5 hash
            ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()

            return ja3s_hash

        except Exception as e:
            logger.warning(f"JA3S extraction failed: {e}")
            return None

    def _identify_clients(self, ja3_fingerprints: List[Dict]) -> List[Dict[str, Any]]:
        """Identify client applications from JA3 fingerprints"""
        identifications = []

        for fp in ja3_fingerprints:
            ja3_hash = fp.get('hash')
            identified_as = fp.get('identified_as', 'Unknown')

            if identified_as != 'Unknown':
                identifications.append({
                    'client_type': identified_as,
                    'ja3_hash': ja3_hash,
                    'confidence': 'high' if 'malware' not in identified_as.lower() else 'medium',
                    'source_ips': [fp.get('source_ip')],
                    'timestamps': [fp.get('timestamp')]
                })

        # Group by client type
        grouped = defaultdict(lambda: {'ja3_hashes': [], 'source_ips': [], 'timestamps': [], 'count': 0})
        for ident in identifications:
            client_type = ident['client_type']
            grouped[client_type]['ja3_hashes'].append(ident['ja3_hash'])
            grouped[client_type]['source_ips'].extend(ident['source_ips'])
            grouped[client_type]['timestamps'].extend(ident['timestamps'])
            grouped[client_type]['count'] += 1

        # Convert to list
        result = []
        for client_type, data in grouped.items():
            result.append({
                'client_type': client_type,
                'ja3_hashes': list(set(data['ja3_hashes'])),
                'unique_ips': len(set(data['source_ips'])),
                'total_occurrences': data['count'],
                'time_range': {
                    'first_seen': min(data['timestamps']) if data['timestamps'] else None,
                    'last_seen': max(data['timestamps']) if data['timestamps'] else None
                }
            })

        return result

    def _identify_servers(self, ja3s_fingerprints: List[Dict]) -> List[Dict[str, Any]]:
        """Identify server software from JA3S fingerprints"""
        identifications = []

        for fp in ja3s_fingerprints:
            ja3s_hash = fp.get('hash')
            identified_as = fp.get('identified_as', 'Unknown')

            if identified_as != 'Unknown':
                identifications.append({
                    'server_type': identified_as,
                    'ja3s_hash': ja3s_hash,
                    'destination_ips': [fp.get('destination_ip')],
                    'timestamps': [fp.get('timestamp')]
                })

        # Group by server type
        grouped = defaultdict(lambda: {'ja3s_hashes': [], 'destination_ips': [], 'timestamps': [], 'count': 0})
        for ident in identifications:
            server_type = ident['server_type']
            grouped[server_type]['ja3s_hashes'].append(ident['ja3s_hash'])
            grouped[server_type]['destination_ips'].extend(ident['destination_ips'])
            grouped[server_type]['timestamps'].extend(ident['timestamps'])
            grouped[server_type]['count'] += 1

        # Convert to list
        result = []
        for server_type, data in grouped.items():
            result.append({
                'server_type': server_type,
                'ja3s_hashes': list(set(data['ja3s_hashes'])),
                'unique_ips': len(set(data['destination_ips'])),
                'total_occurrences': data['count'],
                'time_range': {
                    'first_seen': min(data['timestamps']) if data['timestamps'] else None,
                    'last_seen': max(data['timestamps']) if data['timestamps'] else None
                }
            })

        return result

    def _analyze_handshake_patterns(self, network_logs: List[Dict]) -> Dict[str, Any]:
        """Analyze TLS handshake patterns"""
        patterns = {
            'total_handshakes': 0,
            'successful_handshakes': 0,
            'failed_handshakes': 0,
            'cipher_suite_distribution': defaultdict(int),
            'tls_version_distribution': defaultdict(int),
            'handshake_timings': []
        }

        for log in network_logs:
            if isinstance(log, dict) and ('tls' in log or 'ssl' in log):
                tls_data = log.get('tls') or log.get('ssl')
                patterns['total_handshakes'] += 1

                # Check for successful handshake
                if tls_data.get('handshake_complete') or tls_data.get('server_hello'):
                    patterns['successful_handshakes'] += 1
                elif tls_data.get('alert') or tls_data.get('error'):
                    patterns['failed_handshakes'] += 1

                # Cipher suite analysis
                cipher = tls_data.get('cipher_suite')
                if cipher:
                    patterns['cipher_suite_distribution'][str(cipher)] += 1

                # TLS version analysis
                version = tls_data.get('version')
                if version:
                    patterns['tls_version_distribution'][str(version)] += 1

                # Timing analysis
                timing = tls_data.get('handshake_time')
                if timing:
                    patterns['handshake_timings'].append(timing)

        return dict(patterns)

    def _detect_suspicious_ja3_activity(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect suspicious JA3 fingerprint activity"""
        suspicious = []

        # Check for known malware JA3 fingerprints
        for fp in result.get('ja3_fingerprints', []):
            if 'malware' in fp.get('identified_as', '').lower():
                suspicious.append({
                    'type': 'malware_ja3_fingerprint',
                    'description': f"Known malware JA3 fingerprint detected: {fp['hash']}",
                    'severity': 'high',
                    'evidence': fp
                })

        # Check for unusual client distributions
        client_types = [c['client_type'] for c in result.get('client_identifications', [])]
        if client_types.count('Unknown') > len(client_types) * 0.8:
            suspicious.append({
                'type': 'unusual_client_distribution',
                'description': 'High percentage of unknown JA3 fingerprints',
                'severity': 'medium',
                'evidence': {'unknown_ratio': client_types.count('Unknown') / len(client_types)}
            })

        # Check for rapid JA3 changes (potential fingerprint spoofing)
        timestamps = []
        for fp in result.get('ja3_fingerprints', []):
            if fp.get('timestamp'):
                timestamps.append(fp['timestamp'])

        if len(timestamps) > 10:
            timestamps.sort()
            time_span = timestamps[-1] - timestamps[0]
            changes_per_minute = len(set([fp['hash'] for fp in result['ja3_fingerprints']])) / (time_span / 60)
            if changes_per_minute > 5:  # More than 5 different JA3 per minute
                suspicious.append({
                    'type': 'rapid_ja3_changes',
                    'description': 'Unusual rate of JA3 fingerprint changes',
                    'severity': 'medium',
                    'evidence': {'changes_per_minute': changes_per_minute}
                })

        return suspicious

    def _generate_ja3_attribution_hints(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attribution hints from JA3 analysis"""
        hints = {
            'client_ecosystem': 'unknown',
            'server_infrastructure': 'unknown',
            'threat_indicators': [],
            'correlation_keys': []
        }

        # Client ecosystem analysis
        client_types = [c['client_type'] for c in result.get('client_identifications', [])]
        if client_types:
            # Determine dominant client type
            type_counts = defaultdict(int)
            for ct in client_types:
                type_counts[ct] += 1

            dominant_type = max(type_counts, key=type_counts.get)
            if 'Chrome' in dominant_type:
                hints['client_ecosystem'] = 'chrome_based'
            elif 'Firefox' in dominant_type:
                hints['client_ecosystem'] = 'firefox_based'
            elif 'Safari' in dominant_type:
                hints['client_ecosystem'] = 'safari_based'
            elif 'Edge' in dominant_type:
                hints['client_ecosystem'] = 'edge_based'
            elif 'Malware' in dominant_type:
                hints['client_ecosystem'] = 'malware_bot'

        # Server infrastructure analysis
        server_types = [s['server_type'] for s in result.get('server_identifications', [])]
        if server_types:
            type_counts = defaultdict(int)
            for st in server_types:
                type_counts[st] += 1

            dominant_server = max(type_counts, key=type_counts.get)
            if 'Cloudflare' in dominant_server:
                hints['server_infrastructure'] = 'cloudflare_cdn'
            elif 'AWS' in dominant_server:
                hints['server_infrastructure'] = 'aws_cloud'
            elif 'Nginx' in dominant_server:
                hints['server_infrastructure'] = 'nginx_webserver'
            elif 'Apache' in dominant_server:
                hints['server_infrastructure'] = 'apache_webserver'

        # Threat indicators
        suspicious = result.get('suspicious_activity', [])
        threat_indicators = []
        for susp in suspicious:
            threat_indicators.append({
                'type': susp['type'],
                'severity': susp['severity'],
                'description': susp['description']
            })

        hints['threat_indicators'] = threat_indicators

        # Correlation keys
        correlation_keys = []

        # JA3 hashes as correlation keys
        for fp in result.get('ja3_fingerprints', []):
            correlation_keys.append(f"ja3:{fp['hash']}")

        # JA3S hashes as correlation keys
        for fp in result.get('ja3s_fingerprints', []):
            correlation_keys.append(f"ja3s:{fp['hash']}")

        # Client types
        for client in result.get('client_identifications', []):
            correlation_keys.append(f"client:{client['client_type']}")

        # Server types
        for server in result.get('server_identifications', []):
            correlation_keys.append(f"server:{server['server_type']}")

        hints['correlation_keys'] = correlation_keys

        return hints

    def correlate_ja3_fingerprints(self, fingerprint_sets: List[Dict]) -> Dict[str, Any]:
        """Correlate JA3 fingerprints across multiple captures"""
        correlation = {
            'common_ja3_hashes': {},
            'common_ja3s_hashes': {},
            'shared_clients': {},
            'shared_servers': {},
            'temporal_patterns': {},
            'correlation_clusters': []
        }

        # Collect all fingerprints
        all_ja3 = defaultdict(list)
        all_ja3s = defaultdict(list)

        for i, fp_set in enumerate(fingerprint_sets):
            for ja3 in fp_set.get('ja3_fingerprints', []):
                all_ja3[ja3['hash']].append(i)

            for ja3s in fp_set.get('ja3s_fingerprints', []):
                all_ja3s[ja3s['hash']].append(i)

        # Find common fingerprints
        correlation['common_ja3_hashes'] = {k: v for k, v in all_ja3.items() if len(v) > 1}
        correlation['common_ja3s_hashes'] = {k: v for k, v in all_ja3s.items() if len(v) > 1}

        # Find shared client/server identifications
        client_types = defaultdict(list)
        server_types = defaultdict(list)

        for i, fp_set in enumerate(fingerprint_sets):
            for client in fp_set.get('client_identifications', []):
                client_types[client['client_type']].append(i)

            for server in fp_set.get('server_identifications', []):
                server_types[server['server_type']].append(i)

        correlation['shared_clients'] = {k: v for k, v in client_types.items() if len(v) > 1}
        correlation['shared_servers'] = {k: v for k, v in server_types.items() if len(v) > 1}

        # Create correlation clusters
        clusters = []

        # Cluster by shared JA3
        for ja3_hash, capture_indices in correlation['common_ja3_hashes'].items():
            clusters.append({
                'type': 'shared_ja3',
                'key': ja3_hash,
                'captures': capture_indices,
                'capture_count': len(capture_indices)
            })

        # Cluster by shared infrastructure
        for server_type, capture_indices in correlation['shared_servers'].items():
            clusters.append({
                'type': 'shared_infrastructure',
                'key': server_type,
                'captures': capture_indices,
                'capture_count': len(capture_indices)
            })

        correlation['correlation_clusters'] = clusters

        return correlation

def analyze_ja3_fingerprints(network_logs: List[Dict]) -> Dict[str, Any]:
    """Convenience function for JA3 analysis"""
    analyzer = JA3FingerprintAnalyzer()
    return analyzer.analyze_ja3_from_network_logs(network_logs)
