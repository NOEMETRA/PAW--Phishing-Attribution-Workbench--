# tls_fingerprinting.py - TLS Certificate and Fingerprint Analysis
import ssl
import hashlib
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import socket
import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

logger = logging.getLogger(__name__)

class TLSFingerprintAnalyzer:
    """Analyze TLS certificates and extract fingerprints for attribution"""

    def __init__(self):
        self.cert_cache = {}

    def analyze_certificate_chain(self, hostname: str, port: int = 443,
                                timeout: int = 10) -> Dict[str, Any]:
        """Analyze TLS certificate chain for a given hostname"""
        result = {
            'hostname': hostname,
            'port': port,
            'certificates': [],
            'fingerprints': {},
            'spki_hashes': {},
            'issuer_info': {},
            'validation': {},
            'errors': []
        }

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate chain
                    cert_chain = ssock.getpeercert(binary_form=True)
                    if cert_chain:
                        cert = x509.load_der_x509_certificate(cert_chain)
                        result['certificates'].append(self._parse_certificate(cert))

                    # Get peer certificate details
                    peercert = ssock.getpeercert()
                    if peercert:
                        result['validation'] = {
                            'has_expired': self._check_cert_expiry(peercert),
                            'issuer': peercert.get('issuer'),
                            'subject': peercert.get('subject'),
                            'version': peercert.get('version'),
                            'serial_number': str(peercert.get('serialNumber', '')),
                            'not_before': peercert.get('notBefore'),
                            'not_after': peercert.get('notAfter')
                        }

        except Exception as e:
            result['errors'].append(f"Certificate analysis failed: {str(e)}")
            logger.warning(f"TLS analysis failed for {hostname}:{port} - {e}")

        return result

    def extract_spki_fingerprint(self, cert_data: Dict) -> Optional[str]:
        """Extract SPKI (Subject Public Key Info) fingerprint from certificate"""
        try:
            if 'public_key_der' in cert_data:
                public_key_der = cert_data['public_key_der']
                # Create SPKI hash (SHA256 of public key)
                spki_hash = hashlib.sha256(public_key_der).hexdigest()
                return spki_hash
        except Exception as e:
            logger.warning(f"SPKI extraction failed: {e}")

        return None

    def analyze_ja3_fingerprint(self, network_logs: List[Dict]) -> Dict[str, Any]:
        """Extract JA3 fingerprints from network capture"""
        ja3_fingerprints = {
            'client_hellos': [],
            'server_hellos': [],
            'handshake_patterns': {}
        }

        for log in network_logs:
            if isinstance(log, dict):
                # Look for TLS handshake data in network logs
                if 'tls' in log or 'ssl' in log:
                    tls_data = log.get('tls') or log.get('ssl')

                    if tls_data:
                        # Extract JA3 from ClientHello
                        if 'client_hello' in tls_data:
                            ja3 = self._extract_ja3_from_client_hello(tls_data['client_hello'])
                            if ja3:
                                ja3_fingerprints['client_hellos'].append({
                                    'ja3': ja3,
                                    'timestamp': log.get('timestamp'),
                                    'destination': log.get('destination')
                                })

                        # Extract server information
                        if 'server_hello' in tls_data:
                            server_info = {
                                'cipher_suite': tls_data['server_hello'].get('cipher_suite'),
                                'version': tls_data['server_hello'].get('version'),
                                'timestamp': log.get('timestamp')
                            }
                            ja3_fingerprints['server_hellos'].append(server_info)

        return ja3_fingerprints

    def correlate_certificates(self, current_certs: List[Dict],
                             known_certificates: List[Dict]) -> Dict[str, Any]:
        """Correlate current certificates with known ones"""
        correlations = {
            'spki_matches': [],
            'issuer_matches': [],
            'serial_matches': [],
            'confidence': 0.0
        }

        current_spkis = set()
        for cert in current_certs:
            spki = cert.get('spki_hash')
            if spki:
                current_spkis.add(spki)

        for known_cert in known_certificates:
            known_spki = known_cert.get('spki_hash')

            # SPKI correlation (same public key)
            if known_spki and known_spki in current_spkis:
                correlations['spki_matches'].append({
                    'known_cert': known_cert.get('hostname'),
                    'current_match': [c.get('hostname') for c in current_certs
                                    if c.get('spki_hash') == known_spki],
                    'spki_hash': known_spki
                })

            # Issuer correlation
            current_issuers = [c.get('issuer', {}).get('organizationName') for c in current_certs]
            known_issuer = known_cert.get('issuer', {}).get('organizationName')

            if known_issuer and known_issuer in current_issuers:
                correlations['issuer_matches'].append({
                    'issuer': known_issuer,
                    'known_hosts': [known_cert.get('hostname')],
                    'current_hosts': [c.get('hostname') for c in current_certs
                                    if c.get('issuer', {}).get('organizationName') == known_issuer]
                })

        # Calculate confidence
        total_matches = (len(correlations['spki_matches']) +
                        len(correlations['issuer_matches']) +
                        len(correlations['serial_matches']))

        correlations['confidence'] = min(1.0, total_matches * 0.4)

        return correlations

    def _parse_certificate(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Parse X.509 certificate into dictionary"""
        try:
            # Extract public key
            public_key = cert.public_key()
            # Use the correct method for cryptography library (cryptography 3.0+)
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Extract key information
            key_info = {}
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info = {
                    'type': 'RSA',
                    'size': public_key.key_size
                }
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_info = {
                    'type': 'ECDSA',
                    'curve': public_key.curve.name
                }

            # Create SPKI hash
            spki_hash = hashlib.sha256(public_key_der).hexdigest()

            return {
                'subject': {
                    'common_name': self._get_subject_field(cert.subject, 'commonName'),
                    'organization_name': self._get_subject_field(cert.subject, 'organizationName'),
                    'country': self._get_subject_field(cert.subject, 'countryName')
                },
                'issuer': {
                    'common_name': self._get_subject_field(cert.issuer, 'commonName'),
                    'organization_name': self._get_subject_field(cert.issuer, 'organizationName'),
                    'country': self._get_subject_field(cert.issuer, 'countryName')
                },
                'validity': {
                    'not_before': cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
                    'not_after': cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
                },
                'serial_number': str(cert.serial_number),
                'version': cert.version.name if hasattr(cert.version, 'name') else str(cert.version),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key': key_info,
                'public_key_der': public_key_der.hex(),
                'spki_hash': spki_hash,
                'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
                'fingerprint_sha1': cert.fingerprint(hashes.SHA1()).hex()
            }

        except Exception as e:
            logger.error(f"Certificate parsing failed: {e}")
            return {'error': str(e)}

    def _get_subject_field(self, subject, field_name: str) -> Optional[str]:
        """Extract field from certificate subject"""
        try:
            for attribute in subject:
                if attribute.oid._name == field_name:
                    return attribute.value
        except:
            pass
        return None

    def _check_cert_expiry(self, peercert: Dict) -> bool:
        """Check if certificate has expired"""
        try:
            import datetime
            not_after = peercert.get('notAfter')
            if not_after:
                # Parse ASN.1 time format
                expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                return expiry_date < datetime.datetime.now()
        except:
            pass
        return False

    def _extract_ja3_from_client_hello(self, client_hello: Dict) -> Optional[str]:
        from .ja3_fingerprinting import JA3FingerprintAnalyzer
        return JA3FingerprintAnalyzer()._extract_ja3_from_client_hello(client_hello)


def analyze_tls_fingerprints(hostname: str, network_logs: List[Dict] = None) -> Dict[str, Any]:
    """Convenience function for complete TLS analysis"""
    analyzer = TLSFingerprintAnalyzer()

    results = {
        'certificate_analysis': analyzer.analyze_certificate_chain(hostname),
        'ja3_analysis': {},
        'correlations': {},
        'summary': {}
    }

    if network_logs:
        results['ja3_analysis'] = analyzer.analyze_ja3_fingerprint(network_logs)

    # Generate summary
    cert_analysis = results['certificate_analysis']
    results['summary'] = {
        'hostname': hostname,
        'has_certificate': len(cert_analysis.get('certificates', [])) > 0,
        'spki_hash': cert_analysis.get('certificates', [{}])[0].get('spki_hash'),
        'issuer_org': cert_analysis.get('certificates', [{}])[0].get('issuer', {}).get('organization_name'),
        'ja3_fingerprints': len(results['ja3_analysis'].get('client_hellos', [])),
        'tls_errors': len(cert_analysis.get('errors', []))
    }

    return results