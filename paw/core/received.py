
import re, socket, datetime, ipaddress
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any
from .trust_boundary import classify_hop
from .network_policy import network_allowed

FQDN_RE = re.compile(r"(?=^.{4,253}$)(^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\.?$)")

def _valid_ip(s: str):
    """Return normalized IP string if s is a valid IPv4/IPv6, else None."""
    try:
        ip = ipaddress.ip_address(s)
        # return compressed form for IPv6, str for IPv4
        return ip.compressed
    except Exception:
        return None


def _extract_ip_candidates(s: str):
    cands = []
    # IPv4 ovunque (evita di catturare numeri attaccati)
    for m in re.finditer(r"(?:^|[^0-9])((?:\d{1,3}\.){3}\d{1,3})(?!\d)", s):
        cands.append(m.group(1))
    # IPv6 tra parentesi quadre: [2001:db8::1]
    for m in re.finditer(r"\[([0-9a-fA-F:]+)\]", s):
        cands.append(m.group(1))
    # IPv6/IPv4 tra parentesi tonde: (...), incluso "IPv6:..."
    for m in re.finditer(r"\((?:IPv6:)?([0-9a-fA-F:\.]+)\)", s, flags=re.IGNORECASE):
        cands.append(m.group(1))
    # Literal con prefisso IPv6:
    for m in re.finditer(r"IPv6:([0-9a-fA-F:]+)", s, flags=re.IGNORECASE):
        cands.append(m.group(1))
    # IPv6 "nudo" (prudente): almeno 2 segmenti
    for m in re.finditer(r"\b([0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{0,4}:){1,6}[0-9a-fA-F]{0,4})\b", s):
        cands.append(m.group(1))
    # Valida e deduplica preservando l'ordine
    seen = set()
    out = []
    for c in cands:
        v = _valid_ip(c)
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out

def _extract_by(s: str):
    m = re.search(r"by\s+([^\s;()]+)", s, flags=re.IGNORECASE)
    return m.group(1) if m else ""

def _extract_from(s: str):
    m = re.search(r"from\s+([^\s;()]+(?:\s+\([^)]+\))?)", s, flags=re.IGNORECASE)
    return m.group(1) if m else ""

def _extract_with(s: str):
    m = re.search(r"with\s+([A-Z0-9-]+)", s, flags=re.IGNORECASE)
    return m.group(1) if m else ""

def _extract_helo(s: str):
    m = re.search(r"helo=([^\s;]+)", s, flags=re.IGNORECASE)
    return m.group(1) if m else ""

def _parse_date(s: str):
    # date often at end of Received line after ';'
    parts = s.split(';')
    if len(parts) >= 2:
        dt = parts[-1].strip()
        try:
            parsed = parsedate_to_datetime(dt)
            return parsed if parsed.tzinfo is not None else None
        except Exception:
            return None
    return None

def normalize_received(received_lines: List[str]) -> Dict[str, Any]:
    hops = []
    for line in received_lines:
        by = _extract_by(line) or ""
        fr = _extract_from(line) or ""
        withp = _extract_with(line) or ""
        helo = _extract_helo(line) or ""
        ips = _extract_ip_candidates(line)
        ip = ips[0] if ips else None
        # fallback: cattura "from host ( ... )" nel caso peggiore
        if not ip:
            m = re.search(r"from\s+[^\s;()]+(?:\s+\(([^)]+)\))", line, flags=re.IGNORECASE)
            if m:
                for tok in re.split(r"[\s,;]", m.group(1)):
                    v = _valid_ip(tok.strip("[]"))
                    if v:
                        ip = v
                        break
        dt = _parse_date(line)
        fqdn_ok = bool(FQDN_RE.match(by)) if by else None
        ptr = None
        if ip and network_allowed():
            try:
                ptr = socket.gethostbyaddr(ip)[0]
            except Exception:
                ptr = ""
        hops.append({
            "raw": line,
            "by": by, "from": fr, "with": withp, "helo": helo,
            "ip": ip, "date": dt.isoformat() if dt else None,
            "fqdn_ok": fqdn_ok, "ptr": ptr
        })
        # Add role classification
        hops[-1]["role"] = classify_hop(hops[-1])
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
    return {"ordered_hops": hops_sorted, "status": "parsed" if hops else "unavailable",
            "order_source": "Received header position", "verified": False}
