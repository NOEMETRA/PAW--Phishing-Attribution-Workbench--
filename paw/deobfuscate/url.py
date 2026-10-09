"""Offline URL interpretation without replacing observed network destinations.

Percent escapes inside a URL, embedded redirect values and visual lookalikes
are evidence to inspect, not permission to rewrite the enclosing URL.
"""
import base64
import ipaddress
import json
import re
from urllib.parse import unquote, urlsplit

from .homoglyph import HomoglyphDetector

_SCHEME = re.compile(r'^(https?|hxxps?)://', re.IGNORECASE)
_HEX = re.compile(r'\\x([0-9a-fA-F]{2})')
_DOT = re.compile(r'\[\s*\.\s*\]|\(\.\)|\[dot\]', re.IGNORECASE)


def http_url_status(value):
    """Conservative syntax check; does not verify reachability or ownership."""
    if len(value) > 65536:
        return 'partial', 'URL character limit exceeded'
    if not re.match(r'^https?://', value, re.IGNORECASE):
        return 'not_url', 'Not an absolute HTTP(S) URL'
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        return 'invalid', 'Whitespace/control characters in URL'
    if '\\' in value:
        return 'invalid', 'Backslashes have ambiguous HTTP URL parsing'
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        return 'invalid', 'Malformed percent escape in URL'
    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return 'invalid', 'Missing hostname'
        # Accessing port detects both nonnumeric and out-of-range values.
        parsed.port
        if any(c in parsed.hostname for c in '\\<>"{}|^`'):
            return 'invalid', 'Invalid hostname characters'
        if '%' in parsed.hostname:
            host = unquote(parsed.hostname, errors='strict')
            if any(c.isspace() or c in '/?#@:[]%\\' or ord(c) < 32 or ord(c) == 127 for c in host):
                return 'invalid', 'Ambiguous encoded hostname'
    except (ValueError, UnicodeError) as exc:
        return 'invalid', str(exc)
    return 'completed', None


class URLDeobfuscator:
    """Preserve URL bytes; expose bounded derived candidates separately."""

    max_iter = 4
    max_url_chars = 65536
    max_token_chars = 16384
    max_candidates = 32
    max_tokens = 128
    max_json_nodes = 128
    max_json_depth = 8

    def __init__(self):
        self.homoglyph = HomoglyphDetector()

    def _recover_text_url(self, value):
        """Decode an encoded whole URL only until its scheme becomes visible."""
        current, transformations = value, []
        limit = min(8, max(1, self.max_iter))
        for iteration in range(limit + 1):
            match = _SCHEME.match(current)
            if match:
                # Refanging applies only to scheme/authority, never resource
                # components or visual confusables.
                end = min([len(current)] + [p for d in '/?#'
                    if (p := current.find(d, match.end())) >= 0])
                scheme = match.group(1)
                scheme = {'hxxp':'http', 'hxxps':'https'}.get(scheme.lower(), scheme)
                authority = current[match.end():end]
                userinfo, at, host_port = authority.rpartition('@')
                authority = userinfo + at + _DOT.sub('.', host_port) if at else _DOT.sub('.', authority)
                recovered = scheme + '://' + authority + current[end:]
                if recovered != current:
                    transformations.append({'technique':'text_url_refang', 'from':current,
                        'to':recovered, 'iteration':iteration + 1,
                        'description':'Refanged scheme/authority; resource components preserved'})
                return recovered, transformations, False
            if iteration == limit:
                return current, transformations, bool(transformations)
            # A decoded tracking container is structured data. Decoding all
            # of it again would change percent escapes inside its URL values.
            if current.lstrip().startswith(('{', '[')):
                return current, transformations, False
            decoded, technique = current, None
            if re.search(r'%[0-9a-fA-F]{2}', current):
                try:
                    decoded = unquote(current, errors='strict')
                    technique = 'whole_url_percent_decode'
                except UnicodeError:
                    break
            elif _HEX.search(current):
                decoded = _HEX.sub(lambda m: chr(int(m.group(1), 16)), current)
                technique = 'whole_url_hex_decode'
            else:
                decoded = self._try_base64_decode_string(current) or current
                technique = 'whole_url_base64_decode'
            if decoded == current:
                break
            transformations.append({'technique':technique, 'from':current, 'to':decoded,
                'iteration':iteration + 1, 'description':'Decoded an entire textual URL candidate'})
            current = decoded
        return current, transformations, False

    def _try_base64_decode_string(self, value):
        if not 8 <= len(value) <= self.max_token_chars:
            return None
        if not re.fullmatch(r'[A-Za-z0-9+/_-]+={0,2}', value):
            return None
        try:
            padded = value + '=' * (-len(value) % 4)
            return base64.b64decode(padded, altchars=b'-_', validate=True).decode('utf-8', errors='strict')
        except (ValueError, UnicodeError):
            return None

    def _embedded_candidates(self, url):
        parsed = urlsplit(url)
        tokens = []
        for index, segment in enumerate(parsed.path.split('/')):
            if segment:
                tokens.append(('path_segment', index, None, segment))
        for index, field in enumerate(parsed.query.split('&')):
            name, separator, value = field.partition('=')
            if separator and value:
                tokens.append(('query_value', index, name, value))
        if parsed.fragment:
            tokens.append(('fragment', 0, None, parsed.fragment))
        candidates, limited = [], len(tokens) > self.max_tokens
        for component, index, name, token in tokens[:self.max_tokens]:
            if len(token) > self.max_token_chars:
                limited = True
                continue
            decoded, steps, token_limited = self._recover_text_url(token)
            limited |= token_limited
            values, container_limited = self._candidate_values(decoded)
            limited |= container_limited
            for candidate, pointer, value_steps in values:
                if len(candidates) == self.max_candidates:
                    limited = True
                    break
                candidates.append({'url':candidate, 'source_url':url, 'source_component':component,
                    'source_index':index, 'source_name':name, 'encoded_value':token,
                    'source_json_pointer':pointer, 'decoding':steps + value_steps,
                    'status':'candidate_not_verified', 'network_target':False})
            if len(candidates) == self.max_candidates and limited:
                break
        return candidates, limited

    def _candidate_values(self, decoded):
        """Extract URL string values from bounded JSON, without guessing links
        from arbitrary text or treating the JSON as an enclosing destination.
        """
        if http_url_status(decoded)[0] == 'completed':
            return [(decoded, None, [])], False
        if not decoded.lstrip().startswith(('{', '[')):
            return [], False
        try:
            data = json.loads(decoded)
        except (ValueError, RecursionError):
            return [], True
        stack, values, nodes, limited = [(data, '', 0)], [], 0, False
        while stack and nodes < self.max_json_nodes:
            value, pointer, depth = stack.pop()
            nodes += 1
            if depth > self.max_json_depth:
                limited = True
                continue
            if isinstance(value, str):
                candidate, steps, decode_limited = self._recover_text_url(value)
                limited |= decode_limited
                if http_url_status(candidate)[0] == 'completed':
                    values.append((candidate, pointer, [{'technique':'json_url_value',
                        'json_pointer':pointer, 'description':'URL string value in decoded JSON'}] + steps))
            elif isinstance(value, dict):
                stack.extend((item, pointer + '/' + key.replace('~', '~0').replace('/', '~1'), depth + 1)
                    for key, item in reversed(list(value.items())))
            elif isinstance(value, list):
                stack.extend((item, pointer + '/' + str(index), depth + 1)
                    for index, item in reversed(list(enumerate(value))))
        return values, limited or bool(stack)

    def deobfuscate_url(self, url):
        result = {'original_url':url, 'final_url':url, 'transformations':[],
            'suspicion_indicators':[], 'suspicion_score':0.0, 'is_changed':False,
            'embedded_url_candidates':[], 'network_url':None, 'network_target':False,
            'url_provenance':'observed', 'analysis_status':'completed'}
        if len(url) > self.max_url_chars:
            result.update(status='partial', analysis_status='partial', reason='URL character limit exceeded')
            return result
        if not _SCHEME.match(url) and re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', url):
            result.update(status='not_url', is_email=True, reason='Email address, not URL')
            return result
        current, transformations, limited = self._recover_text_url(url)
        status, reason = http_url_status(current)
        result.update(status=status, reason=reason)
        if status != 'completed':
            result['decoding_attempts'] = transformations
            if limited:
                result.update(status='partial', analysis_status='partial', reason='Whole URL decoding limit exceeded')
            return result
        result.update(final_url=current, transformations=transformations, is_changed=current != url,
            url_provenance='derived_text_url' if transformations else 'observed',
            network_url=current, network_target=True)
        candidates, limited = self._embedded_candidates(current)
        result['embedded_url_candidates'] = candidates
        if limited:
            result.update(analysis_status='partial', analysis_limitation='Embedded URL decoding limits reached')
        hg = self.homoglyph.deobfuscate_url(current)
        result['hostname_analysis'] = hg.get('hostname_analysis', {})
        if result['hostname_analysis'].get('status') == 'partial':
            result.update(analysis_status='partial', hostname_limitation='IDN comparison not completed')
        indicators = list(hg.get('suspicion_indicators', []))
        parsed = urlsplit(current)
        try:
            ipaddress.ip_address(parsed.hostname)
            indicators.append({'type':'ip_in_url','severity':'medium','description':'IP literal in URL hostname'})
        except ValueError:
            pass
        if parsed.port and parsed.port not in (80, 443, 8080):
            indicators.append({'type':'non_standard_port','severity':'low','description':'Non-standard URL port'})
        if len(parsed.path) > 100:
            indicators.append({'type':'long_path','severity':'low','description':'Long URL path'})
        if parsed.query and len(parsed.query.split('&')) > 5:
            indicators.append({'type':'many_parameters','severity':'low','description':'Many query fields'})
        if parsed.username is not None:
            indicators.append({'type':'userinfo_in_url','severity':'low','description':'URL contains user information'})
        result['suspicion_indicators'] = indicators
        # Preserve the engine's existing transform-count heuristic; candidate
        # decoding and routine percent escapes do not change the enclosing URL.
        count = len(transformations)
        result['suspicion_score'] = min(1.0, .1 * count + min(.3, .05 * count) +
            hg.get('suspicion_score', 0.0))
        return result
