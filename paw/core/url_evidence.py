"""Offline URL inventory: observed/refanged targets and derived candidates."""
import json
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
    seen_evidence = set()
    observed = list(dict.fromkeys(observed))
    observed_set = set(observed)
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
            key = json.dumps(record, sort_keys=True)
            if key not in seen_evidence:
                seen_evidence.add(key)
                evidence.append(record)
    return targets, evidence
