import re
import ipaddress
from typing import List, Dict, Any
from .ip_observations import classify_ip
from .received_timing import observe_received_timing

def analyze_received_anomalies(hops: list, reference_time=None) -> dict:
    """Analyze Received headers for forgery indicators."""
    anomalies = {
        "non_monotonic_dates": None,
        "private_ip_before_boundary": None,
        "invalid_fqdn_count": 0,
        "impossible_negative_skew": None,
        "ip_fqdn_mismatch": False,
        "suspicious_relay_chain": None,
        "missing_auth_headers": False,
        "timestamp_manipulation": None,
        "spoofing_patterns": [],
        "auth_failures": []
    }
    anomalies['receiver_boundary'] = {'status':'not_evaluated','verified':False,
        'reason':'Recipient trust boundary not independently established; provider names are heuristic'}
    anomalies['ip_observations'] = [{'header_index':hop.get('header_index'),
        'ip':hop['ip'],'category':classify_ip(hop['ip'])['category'],
        'source':'Received header claim','verified':False} for hop in hops if hop.get('ip')]
    timing = observe_received_timing(hops,reference_time)
    anomalies['timing_observations'] = timing
    if any(pair['result']=='backward' for pair in timing['adjacent_pairs']):
        anomalies['non_monotonic_dates'] = True
    elif timing['comparison_status']=='completed':
        anomalies['non_monotonic_dates'] = False

    if not hops:
        anomalies.update(status='not_evaluated', reason='No Received headers')
        return anomalies

    # Address categories and provider-name roles cannot establish a trusted
    # receiver boundary. Keep syntax counts descriptive, never infer malice.
    for hop in hops:
        if hop.get("fqdn_ok") is False:
            anomalies["invalid_fqdn_count"] += 1

    # Advanced spoofing detection
    anomalies.update(_detect_advanced_spoofing(hops))

    anomalies.update(status='heuristic_observations', verified=False)
    return anomalies


def received_score_components(anomalies):
    """Header timestamp, hostname and address claims are descriptive only."""
    return {'received_non_monotonic_dates': 0.0,
            'received_private_ip_before_boundary': 0.0,
            'received_invalid_fqdn': 0.0}

def _detect_advanced_spoofing(hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Detect advanced header spoofing patterns."""
    results = {
        "ip_fqdn_mismatch": False,
        "spoofing_patterns": [],
        "auth_failures": []
    }

    # Check IP-FQDN consistency
    for hop in hops:
        ip = hop.get("ip")
        fqdn = hop.get("fqdn")
        if ip and fqdn:
            if _validate_ip_fqdn_consistency(ip, fqdn) is False:
                results["ip_fqdn_mismatch"] = True
                results["spoofing_patterns"].append("ip_fqdn_mismatch")

    # Check for authentication failures
    auth_failures = _check_authentication_failures(hops)
    if auth_failures:
        results["auth_failures"] = auth_failures
        results["spoofing_patterns"].append("auth_failures")

    return results

def _validate_ip_fqdn_consistency(ip: str, fqdn: str) -> bool:
    """Validate if IP and FQDN are consistent."""
    try:
        # Basic validation - check if FQDN resolves to IP or vice versa
        from .network_policy import network_allowed
        if not network_allowed(): return None
        import socket
        resolved_ips = socket.gethostbyname_ex(fqdn)[2]
        return ip in resolved_ips
    except:
        # If resolution fails, check for obvious mismatches
        if fqdn and not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', fqdn):
            return False
        return None

def _check_authentication_failures(hops: List[Dict[str, Any]]) -> List[str]:
    """Check for authentication-related failures."""
    failures = []

    # This would integrate with actual auth checking
    # For now, check for common auth headers
    auth_indicators = ["spf", "dkim", "dmarc"]

    for hop in hops:
        # Look for auth-related information in hop data
        for key, value in hop.items():
            if any(indicator in key.lower() for indicator in auth_indicators):
                if "fail" in str(value).lower() or "none" in str(value).lower():
                    failures.append(f"{key}: {value}")

    return failures

def _is_private_ip(ip: str) -> bool:
    """Check if IP is private."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except:
        return False

def analyze_header_forgery_indicators(email_headers: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive header forgery analysis."""
    results = {
        "forgery_score": 0,
        "indicators": [],
        "confidence": "low"
    }

    # Analyze Received headers
    received_hops = email_headers.get("received", [])
    if received_hops:
        anomalies = analyze_received_anomalies(received_hops)
        forgery_indicators = []

        if anomalies["non_monotonic_dates"]:
            forgery_indicators.append("Non-monotonic timestamps")
            results["forgery_score"] += 2

        if anomalies["private_ip_before_boundary"]:
            forgery_indicators.append("Private IP before boundary")
            results["forgery_score"] += 1

        if anomalies["invalid_fqdn_count"] > 0:
            forgery_indicators.append(f"Invalid FQDNs: {anomalies['invalid_fqdn_count']}")
            results["forgery_score"] += anomalies["invalid_fqdn_count"]

        if anomalies["impossible_negative_skew"]:
            forgery_indicators.append("Impossible time skew")
            results["forgery_score"] += 3

        if anomalies["ip_fqdn_mismatch"]:
            forgery_indicators.append("IP-FQDN mismatch")
            results["forgery_score"] += 2

        if anomalies["suspicious_relay_chain"]:
            forgery_indicators.append("Suspicious relay chain")
            results["forgery_score"] += 2

        if anomalies["timestamp_manipulation"]:
            forgery_indicators.append("Timestamp manipulation")
            results["forgery_score"] += 3

        if anomalies["auth_failures"]:
            forgery_indicators.append(f"Auth failures: {len(anomalies['auth_failures'])}")
            results["forgery_score"] += len(anomalies["auth_failures"])

        results["indicators"] = forgery_indicators

    # Determine confidence level
    if results["forgery_score"] >= 5:
        results["confidence"] = "high"
    elif results["forgery_score"] >= 2:
        results["confidence"] = "medium"

    return results
