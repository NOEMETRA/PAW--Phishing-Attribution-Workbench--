#!/usr/bin/env python3
"""
PAW - URL Deobfuscation Module
Deoffusca URL e link offuscati nei phishing
"""

import re
import base64
from urllib.parse import unquote, urlparse
from typing import Dict, List, Any, Optional

import requests

# Optional homoglyph normalization layer (if available in package)
try:
    from .homoglyph import HomoglyphDetector
except Exception:
    HomoglyphDetector = None
import logging

logger = logging.getLogger(__name__)

class URLDeobfuscator:
    """Deoffuscatore specializzato per URL"""

    def __init__(self):
        # Ordered techniques — URL deobfuscation is iterative so we'll re-run until stable
        self.techniques = [
            self._preprocess_obfuscation,
            self._decode_url_encoding,
            self._decode_hex_escapes,
            self._decode_base64_url_parts,
            self._decode_base64_in_query,
            self._analyze_url_shorteners,
            self._detect_idn_homograph_attack,
        ]

        # If homoglyph detector exists, use it as a final normalization step
        self.homoglyph = HomoglyphDetector() if HomoglyphDetector else None

    def deobfuscate_url(self, url: str) -> Dict[str, Any]:
        """
        Deoffusca un URL applicando multiple tecniche

        Args:
            url: URL potenzialmente offuscato

        Returns:
            Dizionario con URL finale e trasformazioni applicate
        """
        # Skip email addresses - they're not URLs to deobfuscate
        if '@' in url and re.match(r'^[^@]+@[^@]+\.[^@]+$', url):
            return {
                'original_url': url,
                'final_url': url,
                'transformations': [],
                'suspicion_score': 0,
                'suspicion_indicators': ['email_address'],
                'is_email': True
            }
        
        # Iterative multi-pass application: run techniques repeatedly until stable
        current_url = url
        transformations: List[Dict[str, Any]] = []
        suspicion_indicators = []

        # allow instance-level configuration
        max_iter = getattr(self, 'max_iter', 4)
        for i in range(max_iter):
            changed = False
            for technique in self.techniques:
                try:
                    result = technique(current_url)
                    # Some techniques return a tuple or dict (e.g., homoglyph later) — handle str results
                    if isinstance(result, dict):
                        # if a module returns structured result, extract final_url
                        result_url = result.get('final_url') or result.get('url') or current_url
                    else:
                        result_url = result

                    if result_url != current_url:
                        transformations.append({
                            'technique': technique.__name__.lstrip('_'),
                            'from': current_url,
                            'to': result_url,
                            'description': self._get_technique_description(technique.__name__),
                            'iteration': i + 1
                        })
                        current_url = result_url
                        changed = True
                except Exception as e:
                    logger.warning(f"Errore in {technique.__name__}: {e}")
                    continue

            # Homoglyph normalization as a separate final pass per-iteration
            if self.homoglyph:
                try:
                    hg = self.homoglyph.deobfuscate_url(current_url)
                    if hg and hg.get('is_changed') and hg.get('final_url') != current_url:
                        transformations.append({
                            'technique': 'homoglyph_in_hostname',
                            'from': current_url,
                            'to': hg.get('final_url'),
                            'description': 'Normalized homoglyphs in hostname',
                            'iteration': i + 1
                        })
                        current_url = hg.get('final_url')
                        changed = True
                except Exception:
                    pass

            if not changed:
                break

        # Analizza URL finale per indicatori di sospetto
        suspicion_indicators = self._analyze_suspicion_indicators(current_url)

        return {
            'original_url': url,
            'final_url': current_url,
            'transformations': transformations,
            'suspicion_indicators': suspicion_indicators,
            'suspicion_score': self._calculate_url_suspicion(transformations, suspicion_indicators),
            'is_changed': len(transformations) > 0
        }

    def _decode_url_encoding(self, url: str) -> str:
        """Decodifica URL encoding (percent-encoding)"""
        try:
            decoded = unquote(url)
            # Decodifica multipla per encoding annidati
            while decoded != unquote(decoded):
                decoded = unquote(decoded)
            return decoded
        except Exception:
            return url

    def _decode_base64_url_parts(self, url: str) -> str:
        """Decodifica parti dell'URL che potrebbero essere in base64"""
        result_url = url

        # Find candidate tokens (path segments and parameter values)
        try:
            # split path segments
            parsed = urlparse(url)
            path_segs = [seg for seg in parsed.path.split('/') if seg]
            for seg in path_segs:
                dec = self._try_base64_decode_string(seg)
                if dec and self._looks_like_url(dec):
                    result_url = result_url.replace(seg, dec)
                    return result_url

            # inspect query params
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for k, vals in qs.items():
                for v in vals:
                    dec = self._try_base64_decode_string(v)
                    if dec and self._looks_like_url(dec):
                        result_url = result_url.replace(v, dec)
                        return result_url

            # fallback: generic long token matcher (allow URL-safe base64)
            for m in re.finditer(r'([A-Za-z0-9_\-]{12,}={0,2})', url):
                tok = m.group(1)
                dec = self._try_base64_decode_string(tok)
                if dec and self._looks_like_url(dec):
                    result_url = result_url.replace(tok, dec)
                    return result_url
        except Exception:
            pass

        return result_url

    def _try_base64_decode_string(self, s: str) -> Optional[str]:
        """Try various base64 decoding modes (standard, urlsafe, padded/unpadded)."""
        if not s or len(s) < 8:
            return None

        # normalize common URL-safe characters
        cand = s.strip()
        # remove surrounding quotes or brackets
        cand = cand.strip('"\'"')

        # Replace URL-safe chars and try padded/unpadded
        variants = [cand, cand.replace('-', '+').replace('_', '/')]
        for v in variants:
            # try with padding up to 2 '='
            for pad in ['', '=', '==']:
                tryv = v + pad
                try:
                    decoded = base64.b64decode(tryv, validate=False)
                    decs = decoded.decode('utf-8', errors='ignore')
                    if decs and len(decs) > 3:
                        return decs
                except Exception:
                    continue

        return None

    def _decode_base64_in_query(self, url: str) -> str:
        """Specifically decode obvious base64 tokens in query parameters"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        try:
            p = urlparse(url)
            qs = parse_qs(p.query, keep_blank_values=True)
            changed = False
            for k, vals in qs.items():
                new_vals = []
                for v in vals:
                    # try decoding only if likely base64 (contains '=' padding or long length)
                    if re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', v):
                        try:
                            dec = base64.b64decode(v).decode('utf-8', errors='ignore')
                            if self._looks_like_url(dec):
                                new_vals.append(dec)
                                changed = True
                                continue
                        except Exception:
                            pass
                    new_vals.append(v)
                qs[k] = new_vals

            if changed:
                new_query = urlencode(qs, doseq=True)
                return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))
        except Exception:
            return url

        return url

    def _detect_idn_homograph_attack(self, url: str) -> str:
        """Rileva e decodifica attacchi homograph usando caratteri Unicode"""
        suspicious_chars = []

        # Mappa caratteri Unicode simili ad ASCII
        unicode_map = {
            'а': 'a', 'А': 'A',  # Cyrillic
            'е': 'e', 'Е': 'E',
            'о': 'o', 'О': 'O',
            'р': 'p', 'Р': 'P',
            'с': 'c', 'С': 'C',
            'х': 'x', 'Х': 'X',
            'і': 'i', 'І': 'I',
            'ј': 'j', 'Ј': 'J',
            'ӏ': 'l', 'Ӏ': 'l',
        }

        result_url = url
        for char in url:
            if ord(char) > 127:  # Carattere non-ASCII
                ascii_equivalent = unicode_map.get(char)
                if ascii_equivalent:
                    suspicious_chars.append({
                        'unicode': char,
                        'ascii': ascii_equivalent,
                        'codepoint': ord(char)
                    })
                    # Sostituisci con equivalente ASCII
                    result_url = result_url.replace(char, ascii_equivalent)

        # Also attempt to normalize punycode IDN to unicode and viceversa for detection
        try:
            # If hostname contains xn-- punycode, decode to unicode for inspection
            p = urlparse(result_url)
            host = p.netloc
            if host and host.startswith('xn--'):
                try:
                    import idna
                    decoded = idna.decode(host)
                    # if decoded contains non-ascii, replace host with decoded
                    if any(ord(c) > 127 for c in decoded):
                        result_url = result_url.replace(host, decoded)
                except Exception:
                    pass
        except Exception:
            pass

        return result_url

    def _analyze_url_shorteners(self, url: str) -> str:
        """Riconosce e risolve URL shortener reali."""
        shortener_hosts = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'buff.ly', 'adf.ly', 'is.gd', 'v.gd', 's.coop',
            'lnkd.in', 'trib.al', 'eepurl.com', 'shorte.st', 'cutt.ly'
        }

        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            host = host.split(':')[0]

            if host in shortener_hosts:
                expanded = self._expand_short_url(url)
                return expanded or url
        except Exception as exc:
            logger.debug("Shortener analysis failed for %s: %s", url, exc)

        return url

    def _expand_short_url(self, url: str) -> Optional[str]:
        """Segui i redirect per ottenere la destinazione finale di uno short link."""
        session = requests.Session()
        try:
            response = session.head(url, allow_redirects=True, timeout=10)
            if response.history:
                return response.url

            # Alcuni shortener non rispondono a HEAD, esegui GET leggera
            response = session.get(url, allow_redirects=True, timeout=10)
            if response.history:
                return response.url
        except requests.RequestException as exc:
            logger.debug("Short URL expansion failed for %s: %s", url, exc)

        return None

    def _decode_hex_escapes(self, url: str) -> str:
        """Decodifica escape hex nel formato \\xHH"""
        try:
            # Pattern per \\xHH (hex escape)
            hex_pattern = r'\\x([0-9a-fA-F]{2})'
            def hex_replace(match):
                hex_value = match.group(1)
                return chr(int(hex_value, 16))

            return re.sub(hex_pattern, hex_replace, url)
        except Exception:
            return url

    def _preprocess_obfuscation(self, url: str) -> str:
        """Apply quick fixes for common textual obfuscation: hxxp/hxxps, [.] and [dot]"""
        if not url:
            return url

        s = url
        # fix scheme obfuscation
        s = re.sub(r'^hxxps?://', lambda m: 'https://' if m.group(0).lower().startswith('hxxps') else 'http://', s, flags=re.IGNORECASE)

        # replace [.] or (.) or [dot] with .
        s = re.sub(r'\[\.\]|\(\.\)|\[dot\]', '.', s, flags=re.IGNORECASE)
        s = re.sub(r'\[\s*\.\s*\]', '.', s)

        # common bracketed dots like google[.]com
        s = re.sub(r'\[\s*\.\s*\]', '.', s)
        s = re.sub(r'\[\.\]', '.', s)

        # replace literal '[.]' written without escaping
        s = s.replace('[.]', '.')

        # remove spaces around dots
        s = re.sub(r'\s*\.\s*', '.', s)

        return s

    def _looks_like_url(self, text: str) -> bool:
        """Verifica se una stringa sembra un URL"""
        if not text or len(text) < 4:
            return False

        # Deve contenere http o https, o iniziare con www.
        return ('http' in text.lower() or
                text.lower().startswith('www.') or
                '://' in text)

    def _analyze_suspicion_indicators(self, url: str) -> List[Dict]:
        """Analizza URL per indicatori di sospetto"""
        indicators = []

        parsed = urlparse(url)

        # IP invece di dominio
        if self._is_ip_address(parsed.netloc):
            indicators.append({
                'type': 'ip_in_url',
                'description': 'URL contiene indirizzo IP invece di dominio',
                'severity': 'medium'
            })

        # Porta non standard
        if parsed.port and parsed.port not in [80, 443, 8080]:
            indicators.append({
                'type': 'non_standard_port',
                'description': f'Porta non standard: {parsed.port}',
                'severity': 'low'
            })

        # Path lungo o complesso
        if len(parsed.path) > 100:
            indicators.append({
                'type': 'long_path',
                'description': 'Path URL insolitamente lungo',
                'severity': 'low'
            })

        # Molti parametri
        if parsed.query and len(parsed.query.split('&')) > 5:
            indicators.append({
                'type': 'many_parameters',
                'description': 'Molti parametri nell\'URL',
                'severity': 'low'
            })

        return indicators

    def _is_ip_address(self, hostname: str) -> bool:
        """Verifica se una stringa è un indirizzo IP"""
        import ipaddress
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _calculate_url_suspicion(self, transformations: List, indicators: List) -> float:
        """Calcola punteggio di sospetto per l'URL"""
        score = 0.0

        # Peso per trasformazioni
        score += len(transformations) * 0.2

        # Peso per indicatori
        severity_weights = {'low': 0.1, 'medium': 0.3, 'high': 0.5}
        for indicator in indicators:
            score += severity_weights.get(indicator.get('severity', 'low'), 0.1)

        return min(1.0, score)

    def _get_technique_description(self, technique_name: str) -> str:
        """Restituisce descrizione della tecnica"""
        descriptions = {
            '_decode_url_encoding': 'Decodifica URL encoding (percent-encoding)',
            '_decode_base64_url_parts': 'Decodifica parti URL in base64',
            '_detect_idn_homograph_attack': 'Decodifica attacco homograph IDN',
            '_analyze_url_shorteners': 'Analizza URL shortener',
            '_decode_hex_escapes': 'Decodifica escape hex (\\xHH)'
        }
        return descriptions.get(technique_name, technique_name)
