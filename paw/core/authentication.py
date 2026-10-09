"""RFC 8601 header claims, RFC 7489 alignment, RFC 8617 ARC structure.

No receiver is trusted from its self-declared authserv-id. Offline by design.
"""
import re
import tldextract
from email.utils import getaddresses
from .network_policy import network_allowed

RESULTS = {'pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy'}


def _sections(raw):
    sections, output, depth, quoted, escaped = [], [], 0, False, False
    for char in str(raw):
        if escaped:
            if not depth: output.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
            if not depth: output.append(char)
        elif char == '"' and not depth:
            quoted = not quoted
            output.append(char)
        elif char == '(' and not quoted:
            depth += 1
            if depth == 1: output.append(' ')
        elif char == ')' and not quoted:
            if not depth: raise ValueError('Unbalanced comment')
            depth -= 1
        elif not depth:
            if char == ';' and not quoted:
                sections.append(''.join(output).strip())
                output = []
            else: output.append(char)
    if depth or quoted or escaped: raise ValueError('Unterminated header')
    return sections + [''.join(output).strip()]


def parse_authentication_results(raw, header_index=0):
    record = {'header_index': header_index, 'raw': str(raw), 'authserv_id': None,
              'status': 'parsed', 'trusted': False, 'methods': [], 'errors': []}
    try:
        parts = _sections(raw)
        identity = parts[0].split()
        if not identity or len(parts) < 2: raise ValueError('Missing service or result')
        record['authserv_id'] = identity[0].strip('"').lower()
        for part in parts[1:]:
            if part.lower() == 'none': continue
            match = re.match(r'([a-z][a-z0-9_-]*)(?:/[0-9]+)?\s*=\s*([a-z]+)\b', part, re.I)
            if not match:
                if part: record['errors'].append('Malformed result clause')
                continue
            method, result = match.group(1).lower(), match.group(2).lower()
            properties = {}
            for prop in re.finditer(r'\b([a-z][\w.-]*)\s*=\s*("(?:\\.|[^"\\])*"|[^\s;]+)', part[match.end():], re.I):
                key, value = prop.group(1).lower(), prop.group(2).strip('"')
                if '.' not in key: continue  # Consume quoted reason before inspecting properties.
                if key in properties: record['errors'].append('Duplicate property: ' + key)
                properties[key] = value
            record['methods'].append({'method': method, 'result': result, 'properties': properties})
            if result not in RESULTS: record['errors'].append('Unknown result: ' + result)
        if record['errors']: record['status'] = 'invalid'
    except ValueError as exc: record.update(status='invalid', errors=[str(exc)])
    return record


def normalize_domain(value):
    try: value = (value or '').strip().rstrip('.').lower().encode('idna').decode('ascii')
    except (UnicodeError, AttributeError): return None
    if len(value) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value): return None
    if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in value.split('.')): return None
    return value


def _extract_domain(addr):
    addresses = getaddresses([str(addr or '')])
    if len(addresses) != 1: return None
    address = addresses[0][1]
    return normalize_domain(address.rsplit('@', 1)[1]) if address.count('@') == 1 else None


def domain_alignment(identifier, from_domain, mode='r'):
    identifier, from_domain = normalize_domain(identifier), normalize_domain(from_domain)
    if not identifier or not from_domain or mode not in {'r', 's'}: return None
    if identifier == from_domain: return True
    if mode == 's': return False
    extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    first, second = extractor(identifier), extractor(from_domain)
    if not first.suffix or not second.suffix: return None
    return (first.domain, first.suffix) == (second.domain, second.suffix)


def parse_dmarc_record(text):
    tags = {}
    for section in text.split(';'):
        if not section.strip(): continue
        if '=' not in section: return {'status': 'invalid', 'policy': None, 'reason': 'Malformed tag'}
        key, value = (part.strip() for part in section.split('=', 1))
        key = key.lower()
        if key in tags: return {'status': 'invalid', 'policy': None, 'reason': 'Duplicate tag'}
        tags[key] = value
    if not text.lstrip().startswith('v=DMARC1') or tags.get('v') != 'DMARC1' or tags.get('p') not in {'none', 'reject', 'quarantine'}:
        return {'status': 'invalid', 'policy': None, 'reason': 'Invalid version or policy'}
    if tags.get('adkim', 'r') not in {'r', 's'} or tags.get('aspf', 'r') not in {'r', 's'}:
        return {'status': 'invalid', 'policy': None, 'reason': 'Invalid alignment mode'}
    return {'status': 'available', 'policy': tags['p'], 'adkim': tags.get('adkim', 'r'),
            'aspf': tags.get('aspf', 'r'), 'raw': text}


def fetch_dmarc_policy(from_domain):
    if not network_allowed(): return {'policy': None, 'status': 'skipped', 'reason': 'no-egress'}
    domain = normalize_domain(from_domain)
    if not domain: return {'policy': None, 'status': 'unavailable', 'reason': 'No valid From domain'}
    import dns.resolver
    query = '_dmarc.' + domain
    try:
        answers = dns.resolver.resolve(query, 'TXT', lifetime=3)
        records = [b''.join(answer.strings).decode('ascii') for answer in answers]
        candidates = [text for text in records if text.lstrip().startswith('v=DMARC1')]
        if len(candidates) != 1:
            return {'status': 'invalid' if candidates else 'not_found', 'policy': None, 'query': query,
                    'reason': 'Multiple records' if candidates else 'No record at queried domain'}
        return dict(parse_dmarc_record(candidates[0]), query=query, source='live_dns',
                    limitation='Exact-domain lookup only; organizational-domain discovery not implemented')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {'status': 'not_found', 'policy': None, 'query': query,
                'reason': 'No record at queried domain; organizational-domain fallback not evaluated'}
    except Exception as exc:
        return {'status': 'error', 'policy': None, 'query': query, 'reason': type(exc).__name__}


def parse_arc_chain(headers):
    arc, groups, errors = headers.get('arc') or {}, {}, []
    for name in ('seals', 'message_signatures', 'auth_results'):
        groups[name] = {}
        for raw in arc.get(name) or []:
            match = re.search(r'(?:^|;)\s*i\s*=\s*(\d+)\s*(?:;|$)', str(raw), re.I)
            if not match or int(match.group(1)) < 1:
                errors.append('Invalid ARC instance in ' + name)
                continue
            instance = int(match.group(1))
            if instance in groups[name]: errors.append('Duplicate ARC instance in ' + name)
            groups[name][instance] = str(raw)
    instances = set().union(*(set(group) for group in groups.values()))
    maximum = max(instances, default=0)
    if maximum > 50: errors.append('ARC chain exceeds 50 sets')
    expected = set(range(1, min(maximum, 51) + 1))
    if instances and any(set(group) != expected for group in groups.values()): errors.append('Incomplete/non-contiguous ARC sets')
    last_cv = None
    for instance, seal in groups['seals'].items():
        match = re.search(r'(?:^|;)\s*cv\s*=\s*(none|pass|fail)\s*(?:;|$)', seal, re.I)
        cv = match.group(1).lower() if match else None
        if instance == maximum: last_cv = cv
        if (instance == 1 and cv != 'none') or (instance > 1 and cv not in {'pass', 'fail'}): errors.append('Invalid ARC cv')
    return {'last_auth_result': groups['auth_results'].get(maximum), 'cv': last_cv, 'max_set': maximum,
            'structure_status': 'invalid' if errors else 'parsed' if instances else 'unavailable', 'errors': errors,
            'verification': {'status': 'not_evaluated', 'result': None,
                             'reason': 'ARC signatures and sealer trust not independently verified'}}


def infer_alignment(headers, from_addr, return_path, dmarc_policy=None):
    records = headers.get('authentication_results') or []
    selected = records[0] if len(records) == 1 and records[0].get('status') == 'parsed' else None
    methods = selected['methods'] if selected else []
    def one(name):
        values = [method for method in methods if method['method'] == name]
        return values[0] if len(values) == 1 else {}
    spf, dmarc = one('spf'), one('dmarc')
    signatures = [method for method in methods if method['method'] == 'dkim']
    from_domain = _extract_domain(from_addr) if headers.get('from_header_count', 1) == 1 else None
    policy = fetch_dmarc_policy(from_domain) if dmarc_policy is None else dmarc_policy
    known = policy.get('status') == 'available'
    identity = spf.get('properties', {}).get('smtp.mailfrom') or ''
    mailfrom = _extract_domain(identity) if '@' in identity else normalize_domain(identity)
    # Return-Path is preserved separately, never substituted for authenticated MAIL FROM.
    spf_aligned = domain_alignment(mailfrom, from_domain, policy.get('aspf', 'r')) if known else None
    dkim_domains = [normalize_domain(method['properties'].get('header.d')) for method in signatures]
    dkim_domains = [domain for domain in dkim_domains if domain]
    checks = [domain_alignment(method['properties'].get('header.d'), from_domain, policy.get('adkim', 'r'))
              if known else None for method in signatures if method['result'] == 'pass']
    dkim_aligned = True if True in checks else False if checks and all(value is False for value in checks) else None
    passed = (spf.get('result') == 'pass' and spf_aligned is True) or dkim_aligned is True
    reported_alignment = True if passed else None
    if known and selected and not passed and from_domain:
        spf_failed = spf.get('result') in {'fail', 'softfail', 'none'} or (spf.get('result') == 'pass' and spf_aligned is False)
        dkim_failed = bool(signatures) and all(method['result'] in {'fail', 'none'} or
            (method['result'] == 'pass' and domain_alignment(method['properties'].get('header.d'), from_domain, policy.get('adkim', 'r')) is False)
            for method in signatures)
        if spf_failed and dkim_failed: reported_alignment = False
    reason = 'No authentication headers' if not records else 'Header provenance is not established'
    if len(records) > 1: reason = 'Multiple authentication headers; no trusted receiver selected'
    verification = {'status': 'not_evaluated', 'result': None, 'reason': reason}
    return {'status': 'reported_only' if records else 'unavailable', 'trusted': False,
        'source': 'message_headers', 'reason': reason, 'reported_records': records, 'from_domain': from_domain,
        'spf': {'result': spf.get('result'), 'mailfrom': mailfrom, 'return_path_domain': _extract_domain(return_path),
                'aligned': spf_aligned, 'verification': dict(verification)},
        'dkim': {'present': headers.get('dkim_signature_present'), 'aligned': dkim_aligned, 'd_list': dkim_domains,
                 'reported_signatures': signatures, 'verification': dict(verification)},
        'dmarc': {'inferred_result': dmarc.get('result'), 'reported_result': dmarc.get('result'), 'policy': policy,
                  'aligned': None, 'reported_alignment': reported_alignment, 'verification': dict(verification)},
        'arc': parse_arc_chain(headers), 'received_spf_result': None,
        'received_spf_claims': headers.get('received_spf') or []}


def authentication_report(auth):
    value = lambda item: 'not evaluable' if item is None else str(item)
    def verification(name):
        check = auth.get(name, {}).get('verification') or {}
        return f"{check.get('status', 'not_evaluated')} ({value(check.get('result'))})"
    return ('## Authentication and coverage\n\n'
        'Authentication-Results and ARC are unverified header claims; no receiver trust is assumed.\n\n'
        f"- SPF reported: {value(auth.get('spf', {}).get('result'))}; independent verification: {verification('spf')}.\n"
        f"- DKIM signature present: {value(auth.get('dkim', {}).get('present'))}; independent verification: {verification('dkim')}.\n"
        f"- DMARC reported: {value(auth.get('dmarc', {}).get('reported_result'))}; independent verification: {verification('dmarc')}.\n"
        f"- DMARC policy lookup: {auth.get('dmarc', {}).get('policy', {}).get('status', 'unavailable')}.\n"
        f"- ARC structure: {auth.get('arc', {}).get('structure_status', 'unavailable')}; signatures/trust: not evaluated.\n"
        f"- Limitation: {auth.get('reason')}.\n")
