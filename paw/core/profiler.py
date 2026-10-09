
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

def observe_domain_age(created_iso, reference_time=None):
    from datetime import datetime, timezone
    record = {'age_schema_version':1,'status':'unavailable','verified':False,
              'source':'supplied_registration_timestamp',
              'scope':'elapsed_whole_days_from_timezone_aware_timestamp',
              'created':created_iso if isinstance(created_iso,str) else None,
              'created_utc':None,'reference_time':None,'age_days':None,
              'reason_code':'timestamp_unavailable','reason':'Registration timestamp unavailable'}
    try:
        reference = datetime.now(timezone.utc) if reference_time is None else (
            datetime.fromisoformat(reference_time.replace('Z','+00:00')) if isinstance(reference_time,str) else reference_time)
        if not isinstance(reference,datetime) or reference.tzinfo is None or reference.utcoffset() is None:
            raise ValueError('Timezone-aware reference required')
        reference = reference.astimezone(timezone.utc)
        record['reference_time'] = reference.isoformat()
    except (TypeError, ValueError, AttributeError, OverflowError):
        record.update(status='invalid',reason_code='invalid_reference_time',reason='Timezone-aware reference unavailable')
        return record
    if created_iso is None or (isinstance(created_iso,str) and not created_iso):
        return record
    try:
        if not isinstance(created_iso,str):
            raise ValueError('Registration timestamp must be a string')
        dt = datetime.fromisoformat(created_iso.replace("Z","+00:00"))
        if dt.tzinfo is None or dt.utcoffset() is None:
            record.update(status='invalid',reason_code='timezone_missing',reason='Registration timezone unavailable; not guessed')
            return record
        dt = dt.astimezone(timezone.utc)
        record['created_utc'] = dt.isoformat()
        if dt > reference:
            record.update(status='invalid',reason_code='future_timestamp',reason='Registration timestamp is after the reference time')
            return record
        record.update(status='observed_unverified',age_days=(reference-dt).days,
                      reason_code='interval_observed',reason='Reported registration interval; registration source not independently verified')
    except (TypeError, ValueError, AttributeError, OverflowError):
        record.update(status='invalid',reason_code='invalid_timestamp',reason='Registration timestamp cannot be parsed')
    return record


def nrd_days(created_iso: str, reference_time=None):
    """Nullable legacy adapter; future/unusable registration dates are not age zero."""
    return observe_domain_age(created_iso,reference_time=reference_time)['age_days']
