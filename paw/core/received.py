
import re, socket, datetime, ipaddress
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any
from .trust_boundary import classify_hop
from .network_policy import network_allowed
from .authentication import normalize_domain
from .ip_observations import classify_ip

MAX_RECEIVED_CHARACTERS = 65536
IP_TOKEN_CHARACTER = r'[\w.:%/\[\]-]'


def _ip_token_boundaries(line, start, stop):
    return not (start and re.fullmatch(IP_TOKEN_CHARACTER,line[start-1])) and not (
        stop < len(line) and re.fullmatch(IP_TOKEN_CHARACTER,line[stop]))


def _bracket_regions(line):
    """Protect complete literals and incomplete/nested bracket fragments alike."""
    regions = []
    depth, start, nested, malformed = 0, None, False, False
    for index,char in enumerate(line):
        if char == '[':
            if not depth:
                start, nested = index, False
            else:
                nested = True
            depth += 1
        elif char == ']':
            if not depth:
                malformed = True
                regions.append((index,index+1,False))
            else:
                depth -= 1
                if not depth:
                    bounded = _ip_token_boundaries(line,start,index+1)
                    regions.append((start,index+1,not nested and bounded))
                    malformed = malformed or nested or not bounded
    if depth:
        regions.append((start,len(line),False))
        malformed = True
    return regions,malformed


def _structure(line):
    """Locate supported clauses outside comments/quotes/literals, preserving offsets."""
    visible = list(line)
    depth, quoted, escaped, bracket, angle = 0, False, False, False, False
    date_start = None
    issues = []
    for index,char in enumerate(line):
        if escaped:
            visible[index] = ' '
            escaped = False
        elif depth:
            visible[index] = ' '
            if char == '\\': escaped = True
            elif char == '(': depth += 1
            elif char == ')': depth -= 1
        elif quoted:
            visible[index] = ' '
            if char == '\\': escaped = True
            elif char == '"': quoted = False
        elif bracket:
            visible[index] = ' '
            if char == ']': bracket = False
        elif angle:
            visible[index] = ' '
            if char == '>': angle = False
            elif char == '"': quoted = True
        elif char == '(':
            visible[index] = ' '
            depth = 1
        elif char == '"':
            visible[index] = ' '
            quoted = True
        elif char == '[':
            visible[index] = ' '
            bracket = True
        elif char == '<':
            visible[index] = ' '
            angle = True
        elif char == ')':
            issues.append('Unbalanced Received comment')
        elif char == ';':
            date_start = index
            break
    if depth or quoted or escaped or bracket or angle:
        issues.append('Unterminated Received comment, quote or literal')
    end = len(line) if date_start is None else date_start
    # Candidate scanning also recognizes literals inside comments. Validate
    # those brackets here, so malformed fragments cannot establish a sender IP.
    if _bracket_regions(line[:end])[1]:
        issues.append('Malformed Received address brackets or token boundaries; selection unsupported')
    masked = ''.join(visible[:end])
    tokens = list(re.finditer(r'(?<!\S)(from|by|with|id|for|via)(?=\s|$)',masked,re.I))
    if tokens and masked[:tokens[0].start()].strip():
        issues.append('Unsupported text before Received clauses')
    clauses = []
    for index,token in enumerate(tokens):
        stop = tokens[index+1].start() if index+1 < len(tokens) else end
        clauses.append({'name':token.group(1).lower(),'keyword_start':token.start(),
                        'value_span':[token.end(),stop]})
    return clauses,date_start,issues


def _first_token(value):
    depth = 0
    escaped = False
    start = None
    for index,char in enumerate(value):
        if depth:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '(': depth += 1
            elif char == ')': depth -= 1
            continue
        if char == '(':
            if start is not None: return value[start:index]
            depth = 1
        elif char.isspace():
            if start is not None: return value[start:index]
        elif start is None:
            start = index
    return value[start:] if start is not None else ''


def _ip_candidates(line, clauses, date_start):
    output,protected = [],[]
    for start,stop,complete in _bracket_regions(line)[0]:
        protected.append((start,stop))
        ip = _valid_ip(line[start+1:stop-1]) if complete else None
        if ip: output.append({'ip':ip,'source_span':[start,stop]})
    bracket_index = 0
    for match in re.finditer(rf'(?<!{IP_TOKEN_CHARACTER})(?:IPv6:)?[0-9a-f:.]+(?!{IP_TOKEN_CHARACTER})',line,re.I):
        while bracket_index < len(protected) and protected[bracket_index][1] <= match.start():
            bracket_index += 1
        if bracket_index < len(protected) and protected[bracket_index][0] <= match.start():
            continue
        ip = _valid_ip(match.group())
        if ip: output.append({'ip':ip,'source_span':list(match.span())})
    output.sort(key=lambda item:item['source_span'][0])
    for candidate in output:
        start,stop = candidate['source_span']
        candidate.update(scope='other',text=line[start:stop],source='Received header string',verified=False)
        for clause in clauses:
            if clause['value_span'][0] <= start and stop <= clause['value_span'][1]:
                candidate['scope'] = clause['name']
                break
        if date_start is not None and start > date_start:
            candidate['scope'] = 'date'
    return output


def _host_observation(value, clause):
    kind = 'unavailable'
    if value:
        if _valid_ip(value.strip('[]')):
            kind = 'address_literal'
        else:
            domain = normalize_domain(value)
            kind = ('domain' if '.' in domain else 'single_label') if domain else 'unsupported'
    return {'kind':kind,'source':'Received '+clause+' clause','verified':False,
            'limitation':'Hostname syntax does not establish receiver ownership or malicious activity'}


def _valid_ip(s: str):
    """Return normalized IP string if s is a valid IPv4/IPv6, else None."""
    try:
        if '%' in s: return None  # Scoped interface identifiers are outside SMTP literal scope.
        if s.lower().startswith('ipv6:'): s = s[5:]
        ip = ipaddress.ip_address(s)
        # return compressed form for IPv6, str for IPv4
        return ip.compressed
    except Exception:
        return None


def _extract_helo(s: str):
    m = re.search(r"helo=([^\s;]+)", s, flags=re.IGNORECASE)
    return m.group(1) if m else ""

def _parse_date(s: str, date_start):
    # Use the delimiter outside quoted strings/comments, not their semicolons.
    if date_start is not None:
        dt = s[date_start+1:].strip()
        try:
            parsed = parsedate_to_datetime(dt)
            return parsed if parsed.tzinfo is not None else None
        except Exception:
            return None
    return None

def normalize_received(received_lines: List[str]) -> Dict[str, Any]:
    hops = []
    for header_index,raw in enumerate(received_lines):
        line = str(raw)
        clauses,date_start,issues = _structure(line) if len(line) <= MAX_RECEIVED_CHARACTERS else ([],None,['Received field exceeds supported length'])
        def values(name):
            return [line[slice(*clause['value_span'])].strip() for clause in clauses if clause['name'] == name]
        from_values,by_values = values('from'),values('by')
        fr = from_values[0] if len(from_values) == 1 else ''
        from_host = _first_token(fr)
        by = _first_token(by_values[0]) if len(by_values) == 1 else ''
        from_observation = _host_observation(from_host,'from')
        by_observation = _host_observation(by,'by')
        if from_observation['kind'] == 'unsupported': issues.append('From hostname/address syntax outside supported scope')
        if by_observation['kind'] == 'unsupported': issues.append('By hostname/address syntax outside supported scope')
        pair = [clause['name'] for clause in clauses if clause['name'] in {'from','by'}]
        supported = not issues and pair == ['from','by'] and bool(from_host and by)
        if pair != ['from','by']: issues.append('A single ordered From/By clause pair is unavailable')
        if pair == ['from','by'] and not (from_host and by): issues.append('From or By host token unavailable')
        with_values = values('with')
        withp = _first_token(with_values[0]) if len(with_values) == 1 else ''
        helo = _extract_helo(fr)
        candidates = _ip_candidates(line,clauses,date_start) if len(line) <= MAX_RECEIVED_CHARACTERS else []
        sender_ips = list(dict.fromkeys(c['ip'] for c in candidates if c['scope'] == 'from'))
        ip = sender_ips[0] if supported and len(sender_ips) == 1 else None
        if supported and len(sender_ips) > 1:
            issues.append('Multiple distinct From-clause IP claims; none selected')
        ip_status = 'parsed' if ip else 'unsupported' if not supported or len(sender_ips)>1 else 'unavailable'
        dt = _parse_date(line,date_start) if date_start is not None and not any('Unbalanced' in issue or 'Unterminated' in issue for issue in issues) else None
        if dt is None: issues.append('Received timestamp or explicit timezone unavailable')
        fqdn_ok = by_observation['kind'] == 'domain' if by else None
        ptr = None
        if ip and network_allowed():
            try:
                ptr = socket.gethostbyaddr(ip)[0]
            except Exception:
                ptr = ""
        hops.append({
            "raw": line,
            'header_index':header_index,
            'from_host':from_host,'from_observation':from_observation,'by_observation':by_observation,
            'ip_candidates':candidates,
            'ip_observation':{'status':ip_status,'source':'Received from clause',
                              'scope':'single_unique_address_candidate','verified':False,
                              'classification':classify_ip(ip) if ip else None},
            'parsing':{'status':'partial' if issues else 'parsed','issues':issues,
                       'scope':'bounded_smtp_from_by_clauses','source_span_unit':'Unicode code points',
                       'available_characters':len(line),'limit_characters':MAX_RECEIVED_CHARACTERS},
            "by": by, "from": fr, "with": withp, "helo": helo,
            "ip": ip, "date": dt.isoformat() if dt else None,
            "fqdn_ok": fqdn_ok, "ptr": ptr
        })
        # Add role classification
        hops[-1]["role"] = classify_hop(hops[-1])
        hops[-1]['role_observation'] = {'role':hops[-1]['role'],'verified':False,
            'source':'provider_hostname_heuristic','limitation':'Provider names do not establish the recipient trust boundary'}
    # Received headers are prepended. Keep chain order; never sort by untrusted dates.
    hops_sorted = list(reversed(hops))
    # compute skew
    prev_dt = None
    for h in hops_sorted:
        cur = datetime.datetime.fromisoformat(h["date"]) if h["date"] else None
        if prev_dt and cur:
            h["skew_s"] = int((cur - prev_dt).total_seconds())
        else:
            h["skew_s"] = 0
        prev_dt = cur if cur else prev_dt
        h["helo_ptr_match"] = (
            None if not network_allowed() or not h.get('ptr') or not h.get('helo') else
            bool(h.get("ptr")) and bool(h.get("helo")) and
            h["ptr"].split(".")[0].lower() == h["helo"].split(".")[0].lower()
        )
    # origin candidate: first hop not belonging to local MX (caller will filter)
    return {"ordered_hops": hops_sorted, "received_schema_version":2,
            "status": 'partial' if any(h['parsing']['status']=='partial' for h in hops) else "parsed" if hops else "unavailable",
            "order_source": "Received header position", "verified": False}
