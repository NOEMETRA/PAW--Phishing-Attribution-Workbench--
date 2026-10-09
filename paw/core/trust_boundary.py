KNOWN_MX_SUFFIXES = ("outlook.com", "office365.com", "protection.outlook.com", "gmail.com", "google.com", "yahoodns.net", "yahoo.com", "proton.me", "protonmail.ch")

def classify_hop(h: dict) -> str:
    """Classify hop role based on MX boundaries and IP characteristics."""
    by_domain = h.get("by", "").lower()
    from_domain = h.get('from_host',h.get("from", "")).lower()
    
    # Extract just the domain from "from" field (e.g., "intelcouncil.com (23.94.26.11)" -> "intelcouncil.com")
    # Split on whitespace and take first token
    from_domain_parts = from_domain.split()
    from_domain_clean = from_domain_parts[0] if from_domain_parts else from_domain

    # Check if both sender and receiver are recipient MX infrastructure
    by_is_recipient_mx = False
    from_is_recipient_mx = False

    for suffix in KNOWN_MX_SUFFIXES:
        if by_domain.rstrip('.').endswith("." + suffix) or by_domain.rstrip('.') == suffix:
            by_is_recipient_mx = True
        if from_domain_clean.rstrip('.').endswith("." + suffix) or from_domain_clean.rstrip('.') == suffix:
            from_is_recipient_mx = True

    # If receiver is recipient MX but sender is NOT, this is an ingress hop (external email entering)
    if by_is_recipient_mx and not from_is_recipient_mx:
        return "external_ingress"

    # If both are recipient MX, this is internal routing
    if by_is_recipient_mx and from_is_recipient_mx:
        return "recipient_mx_internal"

    # Check if this is an internet origin candidate (public IP from non-MX domain)
    ip = h.get("ip")
    if ip and _is_public_ip(ip) and not from_is_recipient_mx:
        return "internet_origin_candidate"

    return "neutral"

def _is_public_ip(ip: str) -> bool:
    """Check if IP is public (not private/reserved)."""
    from .ip_observations import classify_ip
    try:
        return classify_ip(ip)['category'] == 'public'
    except:
        return False
