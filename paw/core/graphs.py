def _mermaid_label(value):
    """Keep source text inside one quoted Mermaid label, never graph syntax."""
    return ''.join(f'#{ord(char)};' if char in '#"&<>`\\' or not char.isprintable()
                   else char for char in str(value))


def attribution_graph(hops, origin_idx, from_domain_info):
    lines = ["graph TD", '  Email["Email / unverified Received header observations"]',
             '  Scope["Header order, oldest first; roles are hostname heuristics; no verified sender or attacker"]',
             '  Email -.-> Scope']
    prev = "Email"
    for i,h in enumerate(hops, start=1):
        label = f"{h.get('ip','?')} / {h.get('by','')}"
        label += f" / Received header index {h.get('header_index', '?')}"
        # This role is a hostname heuristic, not a verified receiver boundary.
        if h.get("role") == "recipient_mx_internal":
            label += " [MX-internal heuristic]"
        node = f"Hop{i}"
        # The caller passes the selected hop, not another occurrence of its IP.
        if i == origin_idx:
            label += " / UNVERIFIED TRANSMITTING CANDIDATE"
        lines.append(f'  {prev} --> {node}["{_mermaid_label(label)}"]')
        prev = node
    fd = from_domain_info or {}
    dom_label = f"{fd.get('domain','?')} | Reg: {fd.get('registrar','?')} | Created: {fd.get('created','?')}"
    lines.append(f'  Email --> FromDomain["{_mermaid_label(dom_label)}"]')
    return "\n".join(lines)

def domain_graph(dominfo):
    ns = ", ".join(dominfo.get("ns", [])) or "-"
    mx = ", ".join(dominfo.get("mx", [])) or "-"
    created = dominfo.get("created","?")
    reg = dominfo.get("registrar","?")
    d = dominfo.get("domain") or "Domain unavailable"
    lines = ["graph LR"]
    lines.append(f'  D["{_mermaid_label(d)}"] --> R["Registrar: {_mermaid_label(reg)}"]')
    lines.append(f'  D --> C["Created: {_mermaid_label(created)}"]')
    lines.append(f'  D --> NS["NS: {_mermaid_label(ns)}"]')
    lines.append(f'  D --> MX["MX: {_mermaid_label(mx)}"]')
    return "\n".join(lines)

def detonation_box(det_sum: dict) -> str:
    if not det_sum: return ""
    from .reporting import publication_json
    return ('## Detonation (stored observations)\n'
            'Supplied metadata; acquisition and authenticity are not established here. '
            'No actor, maliciousness or safety conclusion.\n\n' + publication_json(det_sum))

def canary_box(canary_ips: list[str], canary_visitors: list[dict] = None) -> str:
    if not canary_ips and not canary_visitors: return ""
    from .reporting import publication_json
    return ('## Canary (stored observations)\n'
            'Supplied values; visitor identity, visits, risk and authenticity are not evaluated.\n\n'
            + publication_json({'ip_values':canary_ips, 'visitor_records':canary_visitors}))
