"""Preserve JavaScript source and expose bounded, unexecuted lexical candidates."""
import base64
import binascii
import hashlib
import re
from typing import Any, Dict
from urllib.parse import unquote


class JavaScriptDeobfuscator:
    """Static candidate scanner, not a parser or interpreter.

    Matches may occur in comments/strings or refer to shadowed functions. No
    candidate establishes a runtime call, network destination or phishing risk.
    """

    MAX_SCAN_CHARS = 262144
    MAX_CANDIDATES = 32
    MAX_ARGUMENT_CHARS = 16384
    _CALL = re.compile(r'\b(?P<name>String\.fromCharCode|decodeURIComponent|atob|eval)\s*\(')

    def deobfuscate_javascript(self, js_code: str) -> Dict[str, Any]:
        scan = js_code[:self.MAX_SCAN_CHARS]
        candidates, reasons = [], []
        search_stop = len(scan)
        if len(js_code) > len(scan):
            reasons.append('source_scan_limit')
        for match in self._CALL.finditer(scan):
            if len(candidates) >= self.MAX_CANDIDATES:
                reasons.append('candidate_limit')
                search_stop = match.start()
                break
            candidate = self._observe_call(scan, match)
            candidates.append(candidate)
            if candidate['status'] == 'limited':
                reasons.append('argument_scan_limit')
        return {
            'javascript_schema_version': 2,
            'original_code': js_code, 'final_code': js_code,
            'transformations': [], 'suspicion_indicators': [],
            'iterations_performed': 0, 'complexity_score': None,
            # Nested zero is only a compatibility contribution, not assessed risk.
            'suspicion_score': 0.0,
            'assessment_status': 'partial' if reasons else 'descriptive_only',
            'risk_detection': 'not_evaluated',
            'execution': {'status': 'not_evaluated', 'reason': 'No JavaScript execution is implemented'},
            'calibrated': False,
            'literal_candidates': {
                'status': 'partial' if reasons else 'completed', 'candidates': candidates,
                'coverage_scope': 'literal_candidate_search',
                'scanned_characters': search_stop,
                'available_window_characters': len(scan),
                'unprocessed_source_span': [search_stop,len(js_code)] if search_stop < len(js_code) else None,
                'reasons': sorted(set(reasons)),
                'limits': {'source_characters': self.MAX_SCAN_CHARS,
                           'candidates': self.MAX_CANDIDATES,
                           'argument_characters': self.MAX_ARGUMENT_CHARS},
            },
            'lexical_observations': {
                'source': 'original_code', 'syntax_verified': False,
                'scanned_characters': len(scan),
                'hex_escape_count': len(re.findall(r'\\x[0-9a-fA-F]{2}', scan)),
                'unicode_escape_count': len(re.findall(r'\\u[0-9a-fA-F]{4}', scan)),
            },
            'limitation': ('Bounded lexical candidates may occur in comments, strings or shadowed calls; '
                           'syntax, runtime behavior and JavaScript risk are not evaluated. '
                           'Decoded candidates are never executed, reparsed or promoted to network targets.'),
        }

    def _observe_call(self, source, match):
        start, argument_start = match.start(), match.end()
        stop = min(len(source), argument_start + self.MAX_ARGUMENT_CHARS)
        # Balance nested parentheses within the bounded region; quoted ones do
        # not delimit calls. This still does not verify full JS lexical syntax.
        quote, escaped, end, depth = None, False, None, 1
        for position in range(argument_start, stop):
            char = source[position]
            if quote:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in ('"', "'"):
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    end = position + 1
                    break
        candidate = {'kind': match.group('name'), 'source_span': [start,end or stop],
                     'original': source[start:end or stop], 'source': 'original_code',
                     'candidate_only': True, 'syntax_verified': False,
                     'network_target': False, 'decoded_text': None}
        if end is None:
            candidate['status'] = 'limited' if stop - argument_start >= self.MAX_ARGUMENT_CHARS else 'unsupported_literal'
            return candidate
        argument = source[argument_start:end-1].strip()
        try:
            if candidate['kind'] == 'String.fromCharCode':
                # Decimal integer subset, without expressions or rounded Numbers.
                if argument and not re.fullmatch(r'[+-]?(?:0|[1-9][0-9]*)(?:\s*,\s*[+-]?(?:0|[1-9][0-9]*))*', argument):
                    raise NotImplementedError
                parts = argument.split(',') if argument else []
                if any(len(part.strip().lstrip('+-')) > 16 for part in parts):
                    raise NotImplementedError
                numbers = [int(part) for part in parts]
                if any(abs(number) > 2**53-1 for number in numbers):
                    raise NotImplementedError
                self._set_units(candidate, [number % 65536 for number in numbers])
            else:
                value = self._literal(argument)
                if candidate['kind'] == 'atob':
                    # WHATWG forgiving-base64: ASCII whitespace/omitted padding
                    # allowed, invalid alphabet/padding rejected.
                    token = re.sub(r'[\t\n\f\r ]', '', value)
                    if len(token) % 4 == 0:
                        token = re.sub(r'={1,2}$', '', token)
                    if len(token) % 4 == 1 or not re.fullmatch(r'[A-Za-z0-9+/]*', token):
                        raise ValueError
                    raw = base64.b64decode(token + '='*((-len(token))%4), validate=True)
                    candidate.update(status='decoded_literal_candidate', decoded_text=raw.decode('latin-1'),
                                     text_encoding='javascript_binary_string', decoded_size=len(raw),
                                     sha256=hashlib.sha256(raw).hexdigest())
                elif candidate['kind'] == 'decodeURIComponent':
                    if re.search(r'%(?![0-9a-fA-F]{2})', value):
                        raise ValueError
                    candidate.update(status='decoded_literal_candidate',
                                     decoded_text=unquote(value,encoding='utf-8',errors='strict'))
                else:
                    candidate.update(status='not_executed',decoded_text=value)
        except NotImplementedError:
            candidate['status'] = 'unsupported_literal'
        except (ValueError, UnicodeError, binascii.Error):
            candidate['status'] = 'invalid_encoding'
        return candidate

    @staticmethod
    def _set_units(candidate, units):
        candidate['code_units'] = units
        raw = b''.join(unit.to_bytes(2,'little') for unit in units)
        try:
            candidate.update(status='decoded_literal_candidate',decoded_text=raw.decode('utf-16-le',errors='strict'))
        except UnicodeError:
            # Retain unpaired surrogates as units, never silently drop them.
            candidate['status'] = 'utf16_code_units'

    @staticmethod
    def _literal(argument):
        if len(argument) < 2 or argument[0] not in ('"',"'") or argument[-1] != argument[0]:
            raise NotImplementedError
        quote, body = argument[0], argument[1:-1]
        output, position = [], 0
        escapes = {'n':'\n','r':'\r','t':'\t','b':'\b','f':'\f','v':'\v',
                   '\\':'\\',"'":"'",'"':'"'}
        while position < len(body):
            char = body[position]
            if char in (quote,'\n','\r','\u2028','\u2029'):
                raise NotImplementedError
            if char != '\\':
                output.append(char)
                position += 1
                continue
            position += 1
            if position >= len(body):
                raise NotImplementedError
            escape = body[position]
            if escape in escapes:
                output.append(escapes[escape])
                position += 1
            elif escape in ('x','u'):
                width = 2 if escape == 'x' else 4
                digits = body[position+1:position+1+width]
                if len(digits) != width or not re.fullmatch(r'[0-9a-fA-F]+',digits):
                    raise NotImplementedError
                output.append(chr(int(digits,16)))
                position += width + 1
            else:
                # No guessed octal, line continuations, templates or expressions.
                raise NotImplementedError
        return ''.join(output).encode('utf-16-le',errors='surrogatepass').decode('utf-16-le',errors='strict')
