"""Offline URL inventory: observed/refanged targets and derived candidates."""
import re
from ..deobfuscate.url import http_url_status


def extract_text_url_candidates(text):
    # Bare domain-like prose, addresses and punctuation are not network URLs.
    candidates = re.findall(r'(?:https?|hxxps?)://[^\s<>"\']+', text, flags=re.IGNORECASE)
    # Encoded whole URL candidates require a scheme-like prefix. Final syntax
    # validation and bounded decoding are handled by URLDeobfuscator.
    for token in re.findall(r'[^\s<>"\']+', text):
        if re.match(r'(?:h(?:tt|xx)ps?%|%(?:25){0,3}(?:68|48)|\\x(?:68|48)|aHR0c)', token, re.IGNORECASE):
            candidates.append(token)
    return list(dict.fromkeys(candidates))


def build_url_evidence(observed, results):
    """Only valid observed/refanged top-level URLs enter the network inventory.

    Nested candidates and visual skeletons remain inspectable evidence. They
    never become observed URLs or automatic detonation/enrichment targets.
    """
    targets, evidence, seen = [], [], set()
    observed = list(dict.fromkeys(observed))
    for value in observed:
        status, reason = http_url_status(value)
        evidence.append({'url':value, 'provenance':'observed', 'status':status,
            'reason':reason, 'network_target':status == 'completed'})
        if status == 'completed':
            targets.append(value)
            seen.add(value)
    for result in results:
        value = result.get('network_url')
        if (result.get('status') == 'completed' and result.get('network_target') is True
                and value and value not in seen and http_url_status(value)[0] == 'completed'):
            seen.add(value)
            targets.append(value)
            evidence.append({'url':value, 'source_url':result['original_url'],
                'provenance':result['url_provenance'], 'status':'completed', 'network_target':True,
                'transformations':result.get('transformations', [])})
    return targets, evidence
