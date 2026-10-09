"""Offline URL inventory: observed/refanged targets and derived candidates."""
import base64
import json
import re
from html.parser import HTMLParser
from ..deobfuscate.url import http_url_status


def _has_base64_url_scheme(value):
    # All supported schemes start with ASCII h/H, encoded as a/S. Inspect at
    # most 12 Base64 characters (9 bytes), independent of the token length.
    if value[:1] not in {'a', 'S'}:
        return False
    prefix = value[:12]
    try:
        decoded = base64.b64decode(prefix + '=' * (-len(prefix) % 4), altchars=b'-_', validate=True)
    except (ValueError, UnicodeError):
        return False
    # A scheme-like marker only: malformed/unresolved inputs must still reach
    # the decoder and remain non-target evidence, as with the legacy prefix.
    return decoded.lower().startswith((b'http', b'hxxp'))


def extract_text_url_candidates(text):
    # Bare domain-like prose, addresses and punctuation are not network URLs.
    candidates = re.findall(r'(?:https?|hxxps?)://[^\s<>"\']+', text, flags=re.IGNORECASE)
    # Encoded whole URL candidates require a scheme-like prefix. Final syntax
    # validation and bounded decoding are handled by URLDeobfuscator.
    for token in re.findall(r'[^\s<>"\']+', text):
        if (re.match(r'(?:h(?:tt|xx)ps?%|%(?:25){0,3}(?:68|48)|\\x(?:68|48)|aHR0c)', token, re.IGNORECASE)
                or _has_base64_url_scheme(token)):
            candidates.append(token)
    return list(dict.fromkeys(candidates))


class _HtmlURLCandidateParser(HTMLParser):
    """Inspect parsed attributes and hidden text without execution."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.candidates = []
        self.raw_text = False

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style'}:
            self.raw_text = True
        for name, value in attrs:
            # Namespace URIs identify XML vocabularies; they are not links.
            if name == 'xmlns' or name.startswith('xmlns:'):
                continue
            if value:
                self.candidates.extend(extract_text_url_candidates(value))

    def handle_data(self, value):
        # Visible text has already been joined across markup by MIME analysis.
        # Scanning individual data chunks would invent truncated URL targets.
        if self.raw_text:
            self.candidates.extend(extract_text_url_candidates(value))

    def handle_endtag(self, tag):
        if tag in {'script', 'style'}:
            self.raw_text = False

    def handle_comment(self, value):
        self.candidates.extend(extract_text_url_candidates(value))


def extract_mime_url_candidates(mime_result, subject=''):
    """Inspect original decoded body representations, never attachments or rewritten HTML.

    Parse HTML so character references are interpreted once, matching MIME URL
    extraction; scanning raw markup would invent a second target containing &amp;.
    Script text remains literal, and no JavaScript is executed.
    """
    candidates = extract_text_url_candidates(mime_result['body_text'])
    candidates.extend(extract_text_url_candidates(subject))
    for html_part in mime_result['html_parts']:
        # Independent MIME documents must never inherit malformed parser state.
        parser = _HtmlURLCandidateParser()
        parser.feed(html_part)
        parser.close()
        candidates.extend(parser.candidates)
    candidates.extend(extract_text_url_candidates(mime_result['javascript']))
    return list(dict.fromkeys(candidates))


def build_url_evidence(observed, results):
    """Only valid observed/refanged top-level URLs enter the network inventory.

    Nested candidates and visual skeletons remain inspectable evidence. They
    never become observed URLs or automatic detonation/enrichment targets.
    """
    targets, evidence, seen = [], [], set()
    seen_evidence = set()

    def add_evidence(record):
        key = json.dumps(record, sort_keys=True)
        if key not in seen_evidence:
            seen_evidence.add(key)
            evidence.append(record)

    observed = list(dict.fromkeys(observed))
    observed_set = set(observed)
    for value in observed:
        status, reason = http_url_status(value)
        record = {'url':value, 'provenance':'observed', 'status':status,
            'reason':reason, 'network_target':status == 'completed'}
        if status != 'completed':
            record.update(source_url=value, decoding_attempts=[])
        add_evidence(record)
        if status == 'completed':
            targets.append(value)
            seen.add(value)
    for result in results:
        value = result.get('network_url')
        if (result.get('status') == 'completed' and result.get('network_target') is True
                and value and http_url_status(value)[0] == 'completed'):
            if value not in seen:
                seen.add(value)
                targets.append(value)
            # An unchanged observation is already inventoried above. Derived
            # sources must remain evidence even when their target is shared.
            if value in observed_set and result['url_provenance'] == 'observed':
                continue
            record = {'url':value, 'source_url':result['original_url'],
                'provenance':result['url_provenance'], 'status':'completed', 'network_target':True,
                'transformations':result.get('transformations', [])}
        else:
            # Recovery failure is evidence too. Keep the source as the record
            # URL; intermediate decoded values are only in decoding_attempts.
            source = result['original_url']
            record = {'url':source, 'source_url':source,
                'provenance':'observed' if source in observed_set else 'text_url_candidate',
                'status':result['status'], 'reason':result.get('reason'), 'network_target':False,
                'decoding_attempts':result.get('decoding_attempts', [])}
        add_evidence(record)
    return targets, evidence
