import datetime
import re
import ipaddress
from typing import List, Dict, Any
from .ip_observations import classify_ip

def analyze_received_anomalies(hops: list) -> dict:
    """Analyze Received headers for forgery indicators."""
    anomalies = {
        "non_monotonic_dates": False,
        "private_ip_before_boundary": None,
        "invalid_fqdn_count": 0,
        "impossible_negative_skew": False,
        "ip_fqdn_mismatch": False,
        "suspicious_relay_chain": False,
        "missing_auth_headers": False,
        "timestamp_manipulation": False,
        "spoofing_patterns": [],
        "auth_failures": []
    }
    anomalies['receiver_boundary'] = {'status':'not_evaluated','verified':False,
        'reason':'Recipient trust boundary not independently established; provider names are heuristic'}
    anomalies['ip_observations'] = [{'header_index':hop.get('header_index'),
        'ip':hop['ip'],'category':classify_ip(hop['ip'])['category'],
        'source':'Received header claim','verified':False} for hop in hops if hop.get('ip')]

    if not hops:
        anomalies.update(status='not_evaluated', reason='No Received headers')
        return anomalies

    # Check for non-monotonic dates
    prev_date = None
    for hop in hops:
        date_str = hop.get("date")
        if date_str:
            try:
                current_date = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                if prev_date and current_date < prev_date:
                    anomalies["non_monotonic_dates"] = True
                    break
                prev_date = current_date
            except:
                pass

    # Address categories and provider-name roles cannot establish a trusted
    # receiver boundary. Keep syntax counts descriptive, never infer malice.
    for hop in hops:
        if hop.get("fqdn_ok") is False:
            anomalies["invalid_fqdn_count"] += 1

    # Check for impossible negative skew (time going backwards)
    for hop in hops:
        skew = hop.get("skew_s", 0)
        if skew < -300:  # More than 5 minutes backwards
            anomalies["impossible_negative_skew"] = True
            break

    # Advanced spoofing detection
    anomalies.update(_detect_advanced_spoofing(hops))

    anomalies.update(status='heuristic_observations', verified=False)
    return anomalies


def received_score_components(anomalies):
    """Only retain the existing timestamp signal; hostname/IP categories are descriptive."""
    return {'received_non_monotonic_dates': .1 if anomalies.get('non_monotonic_dates') else 0.0,
            'received_private_ip_before_boundary': 0.0,
            'received_invalid_fqdn': 0.0}

def _detect_advanced_spoofing(hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Detect advanced header spoofing patterns."""
    results = {
        "ip_fqdn_mismatch": False,
        "suspicious_relay_chain": False,
        "timestamp_manipulation": False,
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

    # Detect suspicious relay chaining patterns
    if _detect_suspicious_relay_chain(hops):
        results["suspicious_relay_chain"] = True
        results["spoofing_patterns"].append("suspicious_relay_chain")

    # Check for timestamp manipulation
    if _detect_timestamp_manipulation(hops):
        results["timestamp_manipulation"] = True
        results["spoofing_patterns"].append("timestamp_manipulation")

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

def _detect_suspicious_relay_chain(hops: List[Dict[str, Any]]) -> bool:
    """Detect suspicious patterns in relay chaining."""
    if len(hops) < 2:
        return False

    # Check for rapid successive hops (potential spoofing)
    for i in range(len(hops) - 1):
        current = hops[i]
        next_hop = hops[i + 1]

        current_time = current.get("date")
        next_time = next_hop.get("date")

        if current_time and next_time:
            try:
                dt1 = datetime.datetime.fromisoformat(current_time.replace('Z', '+00:00'))
                dt2 = datetime.datetime.fromisoformat(next_time.replace('Z', '+00:00'))

                # If time difference is suspiciously small (< 1 second)
                if abs((dt2 - dt1).total_seconds()) < 1:
                    return True
            except:
                pass

    # Check for identical IPs in different hops (unusual)
    ips = [hop.get("ip") for hop in hops if hop.get("ip")]
    if len(ips) != len(set(ips)):
        return True

    return False

def _detect_timestamp_manipulation(hops: List[Dict[str, Any]]) -> bool:
    """Detect timestamp manipulation patterns."""
    timestamps = []
    for hop in hops:
        date_str = hop.get("date")
        if date_str:
            try:
                dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                timestamps.append(dt)
            except:
                pass

    if len(timestamps) < 2:
        return False

    # Check for unrealistic time jumps
    for i in range(len(timestamps) - 1):
        diff = abs((timestamps[i + 1] - timestamps[i]).total_seconds())
        if diff > 3600:  # More than 1 hour jump
            return True

    # Check for future timestamps
    now = datetime.datetime.now(datetime.timezone.utc)
    for ts in timestamps:
        if ts.tzinfo is not None and ts > now + datetime.timedelta(hours=1):  # More than 1 hour in future
            return True

    return False

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
