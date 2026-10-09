
import re
import math


COMPONENT_SOURCES = {
    'header_observations': 'Received/header diagnostics; the header chain is unverified',
    'verified_authentication_failures': 'Only completed independent verification reporting fail',
    'sender_domain_heuristics': 'From/Reply-To spelling and optional domain metadata; not proof of malicious ownership',
    'deobfuscation_heuristics': 'Transformation heuristics; ordinary encoding also transforms, not proof of phishing',
    'dynamic_observations': 'Detonation/canary metadata; not attribution to an actor',
    'profile_modifier': 'Selected analysis profile; not independently observed evidence',
    'received_non_monotonic_dates': 'Claimed Received timestamps; unverified structural observation',
    'received_private_ip_before_boundary': 'Parsed Received IPs and heuristic boundary; unverified observation',
    'received_invalid_fqdn': 'Received by-host syntax; unverified structural observation',
    'legacy_base': 'Legacy caller numeric value; no independent evidence established',
    'additional_signals': 'Caller-provided signal; requires its own evidence and context',
}


def _finite_number(value):
    if isinstance(value, bool):
        raise ValueError('Score values must be finite numbers')
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError('Score values must be finite numbers') from exc
    if not math.isfinite(value):
        raise ValueError('Score values must be finite numbers')
    return value


def _score_metadata(raw, components, profile):
    raw = _finite_number(raw)
    decision_score = max(0.0, min(1.0, raw))
    malicious, suspicious = {'strict': (.68, .52), 'conservative': (.76, .58)}.get(profile, (.72, .55))
    # Tolerance only for floating-point noise at an exact mathematical boundary.
    def reaches(threshold):
        return decision_score >= threshold or math.isclose(decision_score, threshold, rel_tol=0, abs_tol=1e-12)
    decision = ('Likely malicious infrastructure' if reaches(malicious) else
                'Suspicious or compromised account' if reaches(suspicious) else 'Inconclusive')
    return {'score_schema_version': 2,
            'score': round(decision_score, 2), 'raw_score': raw, 'decision_score': decision_score,
            'score_components': components, 'component_sources': {
                name: COMPONENT_SOURCES.get(name, 'Caller-provided signal; requires its own evidence and context')
                for name in components},
            'decision': decision, 'profile': profile,
            'thresholds': {'suspicious': suspicious, 'malicious': malicious},
            'decision_basis': 'Unrounded clamped sum; score is rounded to two decimals for display',
            'decision_scope': 'heuristic_attribution_review', 'calibrated': False}


def validate_deobfuscation_weight(value):
    if isinstance(value, bool):
        raise ValueError('Deobfuscation weight must be finite and between 0 and 1')
    value = float(value)
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError('Deobfuscation weight must be finite and between 0 and 1')
    return value

def brand_label(domain: str):
    # Leftmost label
    if not domain: return ""
    return domain.split(".")[0].lower()

def levenshtein(a: str, b: str):
    if a == b: return 0
    if len(a) == 0: return len(b)
    if len(b) == 0: return len(a)
    v0 = list(range(len(b)+1))
    v1 = [0]*(len(b)+1)
    for i in range(len(a)):
        v1[0] = i+1
        for j in range(len(b)):
            cost = 0 if a[i]==b[j] else 1
            v1[j+1] = min(v1[j]+1, v0[j+1]+1, v0[j]+cost)
        v0, v1 = v1, v0
    return v0[len(b)]

def bk_similarity(label: str, brand: str):
    if not label or not brand: return 0.0
    L = max(len(label), len(brand))
    if L == 0: return 0.0
    d = levenshtein(label, brand)
    return max(0.0, 1.0 - (d / L))

def is_mixed_script(domain: str):
    # Simple heuristic: presence of non-ASCII letters suggests potential mixed script (not perfect)
    try:
        domain.encode('ascii')
        return False
    except Exception:
        return True

def extract_display_name(from_header: str):
    """Extract display name from From header."""
    if not from_header:
        return ""
    # Match "Display Name" <email> or just email
    m = re.match(r'^\s*"([^"]+)"\s*<[^>]+>|\s*([^<\s]+)\s*<[^>]+>|^([^@\s]+)@', from_header)
    if m:
        return (m.group(1) or m.group(2) or m.group(3) or "").strip()
    return ""

def risky_tlds():
    """Return set of risky TLDs."""
    return {".click", ".icu", ".cfd", ".rest", ".tk", ".gq", ".ml", ".ga", ".cf"}

def _extract_domain(addr: str):
    """Extract domain from email address."""
    if not addr: return ""
    m = re.search(r"<([^>]+)>", addr)
    email_ = m.group(1) if m else addr
    m2 = re.search(r"@([^>]+)$", email_.strip())
    return (m2.group(1) if m2 else "").strip().lower()

def score_case(hop_diag: dict, auth: dict, dominfo: dict, brand_seeds=None, suspicious_asn=False, ns_mx_recurrent=False, profile="default", headers=None, detonation_endpoints=None, canary_ips=None, det_summary=None, origin_domain="", deobfuscation_weight: float = 0.30):
    deobfuscation_weight = validate_deobfuscation_weight(deobfuscation_weight)
    brand_seeds = brand_seeds or ["apple","google","microsoft","paypal"]
    
    # Apply profile adjustments
    profile_modifier = 0.0
    if profile == "strict":
        profile_modifier = 0.05
    elif profile == "conservative":
        profile_modifier = -0.05
    
    # Header integrity
    header_score = 0.0
    authentication_score = 0.0
    if hop_diag.get("skew_s", 0) > 600: header_score += 0.2
    if hop_diag.get("helo_ptr_match") is False: header_score += 0.1
    if hop_diag.get("fqdn_ok") is False: header_score += 0.1
    # Only independently verified failures affect authentication risk.
    # Missing evidence and untrusted receiver claims are coverage limitations.
    for method, weight in [('spf', 0.4), ('dkim', 0.2), ('dmarc', 0.2), ('arc', 0.25)]:
        verification = (auth.get(method) or {}).get('verification') or {}
        if verification.get('status') == 'completed' and verification.get('result') == 'fail':
            header_score += weight
            authentication_score += weight
    # Domain signals
    domain_score = 0.0
    nrd = dominfo.get("nrd_days")
    if nrd is not None and nrd < 30: domain_score += 0.15
    if nrd is not None and nrd < 7: domain_score += 0.20
    if suspicious_asn: domain_score += 0.3
    if ns_mx_recurrent: domain_score += 0.2
    
    # Brand & Identity heuristics
    from_domain = dominfo.get("domain", "")
    label = brand_label(from_domain)
    bk = max(bk_similarity(label, b) for b in brand_seeds) if label else 0.0
    exact_brand_subdomain = False
    if bk == 1.0:
        import tldextract
        registered = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())(from_domain)
        exact_brand_subdomain = bool(registered.suffix and registered.domain != label)
    if 0.7 <= bk < 1.0 or exact_brand_subdomain: domain_score += 0.2
    # This is a structural heuristic, never proof of official brand ownership.
    
    # Display-Name lookalike
    if headers:
        display_name = extract_display_name(headers.get("from", ""))
        if display_name and label:
            display_brand = brand_label(display_name.lower().replace(" ", ""))
            if display_brand and display_brand != label:
                # Check if display name contains known brand
                for brand in brand_seeds:
                    if brand in display_name.lower() and bk_similarity(display_brand, brand) >= 0.8:
                        domain_score += 0.20
                        break
        
        # Reply-To mismatch
        reply_to = headers.get("reply_to", "")
        if reply_to:
            reply_domain = _extract_domain(reply_to)
            if reply_domain and reply_domain != from_domain:
                # Check if it's not a punycode variant or subdomain
                if not (reply_domain.endswith("." + from_domain) or from_domain.endswith("." + reply_domain)):
                    domain_score += 0.15
    
    # TLD risk
    if from_domain:
        tld = "." + from_domain.split(".")[-1] if "." in from_domain else ""
        if tld in risky_tlds():
            domain_score += 0.10
    
    if is_mixed_script(dominfo.get("domain","")): domain_score += 0.2

    # Integrate deobfuscation analysis (if available) to penalize heavy obfuscation
    # headers["deobfuscation_analysis"] is expected to be a dict (or a JSON string) with
    # keys like 'deobfuscated_artifacts' containing 'text','html','urls' each having a
    # 'suspicion_score' in [0.0, 1.0]. We compute a small weighted aggregate and add
    # it to domain_score multiplied by deobfuscation_weight (configurable).
    deob_contribution = 0.0
    if headers:
        try:
            deob = headers.get("deobfuscation_analysis")
            if deob and isinstance(deob, str):
                import json as _json
                deob = _json.loads(deob)
            if deob and isinstance(deob, dict):
                da = deob.get("deobfuscated_artifacts", {})
                # weights for parts (tunable)
                w_text, w_urls, w_html = 0.6, 0.25, 0.15
                text_s = (da.get("text") or {}).get("suspicion_score", 0.0)
                html_s = (da.get("html") or {}).get("suspicion_score", 0.0)
                text_s = 0.0 if text_s is None else text_s
                html_s = 0.0 if html_s is None else html_s
                urls = da.get("urls") or []
                urls_s = 0.0
                if isinstance(urls, list) and urls:
                    # use max url suspicion as representative
                    try:
                        urls_s = max(_finite_number(0.0 if u.get('suspicion_score') is None else u['suspicion_score']) for u in urls)
                    except (TypeError, AttributeError):
                        urls_s = 0.0

                deob_score = (w_text * _finite_number(text_s) + w_urls * _finite_number(urls_s) + w_html * _finite_number(html_s))
                # clamp
                if deob_score < 0.0: deob_score = 0.0
                if deob_score > 1.0: deob_score = 1.0
                # apply into domain score
                deob_contribution = deob_score * float(deobfuscation_weight)
                domain_score += deob_contribution
        except (ValueError, OverflowError) as exc:
            raise ValueError('Invalid deobfuscation score metadata') from exc
        except Exception:
            # fail silently on any malformed deob structure
            pass
    
    # Detonation/Canary bonuses
    campaign_score = 0.0
    # Downloads bonus
    if det_summary and det_summary.get("downloads"):
        campaign_score += 0.15
    # External endpoints bonus
    if detonation_endpoints:
        for ep in detonation_endpoints:
            host = ep.get("host", "")
            if host and origin_domain and not host.endswith("." + origin_domain) and host != origin_domain:
                campaign_score += 0.10
                break  # one time bonus
    # Canary public IPs bonus
    if canary_ips:
        # Simple check: if any IP is not private (basic heuristic)
        for ip in canary_ips:
            if not ip.startswith(("192.168.", "10.", "172.")) and not (ip.startswith("127.") or ip == "localhost"):
                campaign_score += 0.20
                break  # one time bonus

    # Coverage is metadata, never evidence of maliciousness.
    components = {'header_observations': header_score - authentication_score,
                  'verified_authentication_failures': authentication_score,
                  'sender_domain_heuristics': domain_score - deob_contribution,
                  'deobfuscation_heuristics': deob_contribution,
                  'dynamic_observations': campaign_score,
                  'profile_modifier': profile_modifier}
    components = {name: _finite_number(value) for name, value in components.items()}
    total = math.fsum(components.values())
    verification = {method: ((auth.get(method) or {}).get('verification') or {}).get('status', 'not_evaluated')
                    for method in ('spf', 'dkim', 'dmarc', 'arc')}
    missing = [method for method, status in verification.items() if status != 'completed']
    if not dominfo.get('domain'): missing.append('from_domain')
    return {**_score_metadata(total, components, profile),
            "bk_score": round(bk,2), "mixed_flag": is_mixed_script(dominfo.get("domain","")),
            "assessment_status": "partial" if missing else "completed",
            "coverage": {"authentication": verification, "not_evaluated": missing},
            "limitation": "Heuristic evidence score; missing checks do not establish safety"}


def finalize_score(score, profile=None, additional=0.0, additional_components=None):
    """Add signals to the unrounded ledger; displayed score is not an accumulator."""
    displayed = _finite_number(score['score'])
    profile = score.get('profile', 'default') if profile is None else profile
    raw = _finite_number(score.get('raw_score', displayed))
    components = dict(score.get('score_components', {'legacy_base': raw}))
    if any(not isinstance(name, str) or not name for name in components):
        raise ValueError('Score components need nonempty names')
    components = {name: _finite_number(value) for name, value in components.items()}
    if not math.isclose(math.fsum(components.values()), raw, rel_tol=0, abs_tol=1e-12):
        raise ValueError('Score components do not match raw score')
    if 'raw_score' in score and displayed != round(max(0.0, min(1.0, raw)), 2):
        raise ValueError('Display score was modified; add signals through finalize_score')
    additions = dict(additional_components or {})
    for name, value in additions.items():
        if not isinstance(name, str) or not name:
            raise ValueError('Additional score components need nonempty names')
        components[name] = math.fsum((components.get(name, 0.0), _finite_number(value)))
    additional = _finite_number(additional)
    if additional:
        components['additional_signals'] = math.fsum((components.get('additional_signals', 0.0), additional))
    score.update(_score_metadata(math.fsum(components.values()), components, profile))
    return score
