
import requests, socket, json, tldextract, dns.resolver
from ipwhois import IPWhois
from .network_policy import network_allowed

def ip_rdap(ip: str):
    if not network_allowed():
        return {'status': 'skipped', 'reason': 'no-egress'}
    try:
        iw = IPWhois(ip)
        res = iw.lookup_rdap(asn_methods=["whois", "http"])
        abuse = []
        for ent in (res.get("entities") or []):
            roles = res.get("objects", {}).get(ent, {}).get("roles", [])
            contact = res.get("objects", {}).get(ent, {}).get("contact", {})
            emails = contact.get("email", [])
            if "abuse" in roles or "security" in roles:
                for e in emails:
                    if isinstance(e, dict) and e.get("value"):
                        abuse.append({"type": "email", "value": e["value"]})
                    elif isinstance(e, str):
                        abuse.append({"type": "email", "value": e})
        return {
            "asn": int(res.get("asn") or 0),
            "asn_org": res.get("asn_description") or "",
            "cc": (res.get("network", {}).get("country") or res.get("asn_country_code") or "").upper(),
            "asn_cc": (res.get("asn_country_code") or "").upper(),
            "abuse": abuse
        }
    except Exception as e:
        return {"error": str(e)}

def domain_rdap(domain: str):
    out = {"domain": domain, "registrar": None, "created": None, "ns": [], "mx": []}
    if not network_allowed():
        return dict(out, status='skipped', reason='no-egress')
    try:
        # RDAP aggregator
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            out["registrar"] = (data.get("registrar") or {}).get("name")
            events = data.get("events") or []
            created = None
            for ev in events:
                if ev.get("eventAction") == "registration":
                    created = ev.get("eventDate")
            out["created"] = created
    except Exception:
        pass
    # NS/MX via DNS authoritative resolvers
    try:
        answers = dns.resolver.resolve(domain, "NS")
        out["ns"] = sorted([str(r.target).rstrip(".") for r in answers])
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "MX")
        out["mx"] = sorted([str(r.exchange).rstrip(".") for r in answers])
    except Exception:
        pass
    return out

def nrd_days(created_iso: str):
    from datetime import datetime, timezone
    if not created_iso: return None
    try:
        dt = datetime.fromisoformat(created_iso.replace("Z","+00:00"))
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except Exception:
        return None
