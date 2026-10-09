
import re
import math
from email import policy
from .authentication import normalize_domain
from .mailbox_domains import reply_domain_observation


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

# These contributions are established by score_case (or the legacy adapter),
# never by caller-provided additions. Received additions remain unverified.
ENGINE_OWNED_COMPONENTS = frozenset({
    'header_observations', 'verified_authentication_failures',
    'sender_domain_heuristics', 'deobfuscation_heuristics',
    'dynamic_observations', 'profile_modifier', 'legacy_base',
})


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
    decision = ('Likely malicious infrastructure' if decision_score >= malicious else
                'Suspicious or compromised account' if decision_score >= suspicious else 'Inconclusive')
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
    """Read one defect-free mailbox's actual display name, never its local part."""
    if not from_header:
        return ""
    try:
        # Parsed HeaderRegistry objects retain original defects that a rendered
        # string/reparse could hide. Direct callers also support RFC 2047 words.
        parsed = from_header if hasattr(from_header,'addresses') else policy.default.header_factory('From',str(from_header))
        if parsed.defects or len(parsed.addresses) != 1:
            return ""
        if len(parsed.groups) != 1 or parsed.groups[0].display_name is not None:
            return ""
        address = parsed.addresses[0]
        if not address.username or not address.domain:
            return ""
        return address.display_name
    except (ValueError, TypeError, AttributeError, IndexError):
        return ""

def risky_tlds():
    """Return set of risky TLDs."""
    return {".click", ".icu", ".cfd", ".rest", ".tk", ".gq", ".ml", ".ga", ".cf"}

def _extract_domain(addr: str):
    """Compatibility adapter: one structured Reply-To domain, never a regex guess."""
    return reply_domain_observation(addr,count=1 if addr else 0)['domain'] or ''


def _from_domain_available(headers, normalized_domain):
    if not normalized_domain or headers.get('from_header_count',1) != 1:
        return False
    if any(isinstance(issue,dict) and str(issue.get('field','')).lower() == 'from'
           for issue in headers.get('header_field_defects') or []):
        return False
    identity = headers.get('from_identity')
    if identity is not None and (not isinstance(identity,dict) or identity.get('status') != 'parsed'):
        return False
    value = headers.get('from')
    # Legacy callers may supply just dominfo; full mail parsing always records
    # occurrence/identity metadata. Validate any supplied From before comparison.
    if value is None:
        return identity is None
    try:
        field = value if hasattr(value,'addresses') else policy.default.header_factory('From',str(value))
        if field.defects or len(field.groups) != 1 or field.groups[0].display_name is not None or len(field.addresses) != 1:
            return False
        address = field.addresses[0]
        return bool(address.username and normalize_domain(address.domain) == normalized_domain)
    except (ValueError, TypeError, AttributeError, IndexError):
        return False


def _reply_to_comparison(headers, from_domain):
    headers = headers or {}
    normalized_from = normalize_domain(from_domain)
    reply_to = headers.get('reply_to','')
    defects = [issue for issue in headers.get('header_field_defects') or []
               if isinstance(issue,dict) and str(issue.get('field','')).lower() == 'reply-to']
    count = headers.get('reply_to_header_count',1 if reply_to else 0)
    # Prefer original parser observations: JSON rendering may erase defects.
    reply = headers.get('reply_to_domain')
    if not isinstance(reply,dict) or count != 1 or defects:
        reply = reply_domain_observation(reply_to,count=count,field_defects=defects)
    reply_domain = normalize_domain(reply.get('domain')) if reply.get('status') == 'parsed' else None
    observation = {'status':'not_evaluated','result':None,'verified':False,
                   'source':'message_headers','from_domain':normalized_from,
                   'reply_domain':reply_domain,'reply_to':reply,'contribution':0.0,
                   'scope':'normalized_domain_equality_or_label_suffix'}
    from_available = _from_domain_available(headers,normalized_from)
    if not from_available:
        observation['reason'] = 'Unambiguous normalized From domain unavailable'
    elif not reply_domain:
        observation['reason'] = reply.get('reason','Reply-To domain unavailable')
    else:
        related = (reply_domain == normalized_from or reply_domain.endswith('.'+normalized_from)
                   or normalized_from.endswith('.'+reply_domain))
        observation.update(status='completed',result='same_or_subdomain' if related else 'different',
            contribution=0.0 if related else 0.15,
            reason='Unverified structural domain comparison; ownership not established')
    return observation

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
    reply_observation = _reply_to_comparison(headers,from_domain)
    domain_score += reply_observation['contribution']
    if headers:
        # Persisted JSON no longer carries HeaderRegistry objects. Respect its
        # original occurrence/defect metadata instead of trusting rendered text.
        from_name_available = headers.get('from_header_count',1) == 1 and not any(
            isinstance(issue,dict) and str(issue.get('field','')).lower() == 'from'
            for issue in headers.get('header_field_defects') or [])
        if headers.get('from_identity'):
            from_name_available = from_name_available and headers['from_identity'].get('status') == 'parsed'
        display_name = extract_display_name(headers.get("from", "")) if from_name_available else ""
        if display_name and label:
            display_brand = brand_label(display_name.lower().replace(" ", ""))
            if display_brand and display_brand != label:
                # Check if display name contains known brand
                for brand in brand_seeds:
                    if brand in display_name.lower() and bk_similarity(display_brand, brand) >= 0.8:
                        domain_score += 0.20
                        break
        
    
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
    if reply_observation['status'] != 'completed': missing.append('reply_to_comparison')
    return {**_score_metadata(total, components, profile),
            'sender_domain_observations': {'reply_to_comparison':reply_observation},
            "bk_score": round(bk,2), "mixed_flag": is_mixed_script(dominfo.get("domain","")),
            "assessment_status": "partial" if missing else "completed",
            "coverage": {"authentication": verification, "not_evaluated": missing},
            "limitation": "Heuristic evidence score; missing checks do not establish safety"}


def finalize_score(score, profile=None, additional=0.0, additional_components=None):
    """Add signals to the unrounded ledger; displayed score is not an accumulator."""
    displayed = _finite_number(score['score'])
    profile = score.get('profile', 'default') if profile is None else profile
    if score.get('score_schema_version') == 2 and profile != score.get('profile'):
        raise ValueError('Cannot change a version-2 score profile; recompute with score_case')
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
        if name in ENGINE_OWNED_COMPONENTS:
            raise ValueError('Additional signals cannot use engine-owned score components')
        components[name] = math.fsum((components.get(name, 0.0), _finite_number(value)))
    additional = _finite_number(additional)
    if additional:
        components['additional_signals'] = math.fsum((components.get('additional_signals', 0.0), additional))
    score.update(_score_metadata(math.fsum(components.values()), components, profile))
    return score
