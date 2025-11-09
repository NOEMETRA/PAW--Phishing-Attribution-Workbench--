
import os, json, datetime
from ..util.fsutil import write_text
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate

def generate_abuse_package(case_dir, Lang="en"):
    # Decide template based on decision stored in report/technical.json (if any) or score.json
    score_path = os.path.join(case_dir, "report", "score.json")
    headers_path = os.path.join(case_dir, "headers.json")
    origin_path = os.path.join(case_dir, "origin.json")
    domains_path = os.path.join(case_dir, "domains.json")
    with open(headers_path, "r", encoding="utf-8") as f: headers = json.load(f)
    with open(origin_path, "r", encoding="utf-8") as f: origin = json.load(f)
    with open(domains_path, "r", encoding="utf-8") as f: doms = json.load(f)
    score = {}
    if os.path.exists(score_path):
        with open(score_path, "r", encoding="utf-8") as f: score = json.load(f)
    decision = score.get("decision","Inconclusive")
    case_id = os.path.basename(case_dir).replace("case-","")
    # Fill context
    ctx = {
        "ip": origin.get("ip",""),
        "asn": origin.get("asn",0),
        "asn_org": origin.get("org",""),
        "country": origin.get("cc",""),
        "domain": doms.get("from_domain",{}).get("domain",""),
        "registrar": doms.get("from_domain",{}).get("registrar",""),
        "created_utc": doms.get("from_domain",{}).get("created",""),
        "ns_list": ", ".join(doms.get("from_domain",{}).get("ns",[])),
        "mx_list": ", ".join(doms.get("from_domain",{}).get("mx",[])),
        "origin_ip": origin.get("ip",""),
        "origin_time": origin.get("time_utc",""),
        "helo": origin.get("helo",""),
        "ptr": origin.get("ptr",""),
        "skew": origin.get("skew_s",0),
        "spf_result": (headers.get("auth_results") or {}).get("spf"),
        "dkim_present": "present" if (headers.get("auth_results") or {}).get("dkim") else "none",
        "dkim_d": ",".join([d.get("d") for d in (headers.get("auth_results") or {}).get("dkim") or []]),
        "dmarc_result": (headers.get("auth_results") or {}).get("dmarc"),
        "nrd_days": doms.get("from_domain",{}).get("nrd_days",""),
        "bk_score": score.get("bk_score",""),
        "mixed_flag": score.get("mixed_flag",""),
        "case_id": case_id,
        "generated_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root_hash": _read_root(case_dir),
        "from_addr": headers.get("from",""),
        "from_domain": doms.get("from_domain",{}).get("domain","")
    }
    # Backwards-compatibility: some templates expect 'your_mx' (first MX of target domain)
    try:
        mx_list = doms.get('from_domain', {}).get('mx', []) or []
        ctx['your_mx'] = mx_list[0] if len(mx_list) > 0 else ''
    except Exception:
        ctx['your_mx'] = ''
    tmpl_dir = os.path.join(os.path.dirname(__file__), "..","templates")
    if decision.startswith("Likely malicious"):
        tmpl = "abuse_en_takedown.txt" if Lang.startswith("en") else "abuse_it_takedown.txt"
    else:
        tmpl = "abuse_en_compromised.txt" if Lang.startswith("en") else "abuse_it_compromised.txt"
    with open(os.path.join(tmpl_dir, tmpl), "r", encoding="utf-8") as f:
        body = f.read().format(**ctx)
    out_txt = os.path.join(case_dir, "package", f"abuse_email_{Lang}.txt")
    os.makedirs(os.path.join(case_dir,"package"), exist_ok=True)
    write_text(out_txt, body)
    return out_txt

def generate_arf_package(case_dir, reporter_email="abuse@example.com", recipient_email="abuse@target.org"):
    """Generate ARF (Abuse Reporting Format) package per RFC 5965"""
    # Load case data
    headers_path = os.path.join(case_dir, "headers.json")
    origin_path = os.path.join(case_dir, "origin.json")
    domains_path = os.path.join(case_dir, "domains.json")
    received_path = os.path.join(case_dir, "received_path.json")
    score_path = os.path.join(case_dir, "report", "score.json")
    
    with open(headers_path, "r", encoding="utf-8") as f: headers = json.load(f)
    with open(origin_path, "r", encoding="utf-8") as f: origin = json.load(f)
    with open(domains_path, "r", encoding="utf-8") as f: doms = json.load(f)
    with open(received_path, "r", encoding="utf-8") as f: received_data = json.load(f)
    
    score = {}
    if os.path.exists(score_path):
        with open(score_path, "r", encoding="utf-8") as f: score = json.load(f)
    
    case_id = os.path.basename(case_dir).replace("case-","")
    
    # Get arrival date from first received hop
    arrival_date = ""
    ordered_hops = received_data.get("ordered_hops", [])
    if ordered_hops:
        arrival_date = ordered_hops[0].get("date", "")
    
    # Create ARF message
    msg = MIMEMultipart('report', report_type='feedback-report')
    msg['From'] = reporter_email
    msg['To'] = recipient_email
    msg['Subject'] = f"Abuse Report - {origin.get('ip','unknown')} - Case {case_id}"
    msg['Date'] = formatdate()
    msg['Message-ID'] = f"<arf-{case_id}@{reporter_email.split('@')[1]}>"
    
    # Human-readable part
    human_part = MIMEText(f"""Abuse Report for IP {origin.get('ip','unknown')}

This is an automated abuse report generated by PAW (Python Abuse Workflow).

Case ID: {case_id}
Origin IP: {origin.get('ip','unknown')}
ASN: {origin.get('asn','unknown')}
Organization: {origin.get('org','unknown')}
Country: {origin.get('cc','unknown')}
From Domain: {doms.get('from_domain',{}).get('domain','unknown')}

Decision: {score.get('decision','Inconclusive')}
Score: {score.get('bk_score','unknown')}

Please investigate this activity.
""", 'plain')
    msg.attach(human_part)
    
    # Machine-readable part (ARF feedback-report)
    feedback_report = {
        "version": "1.0",
        "user-agent": "PAW/1.0",
        "feedback-type": "abuse",
        "arrival-date": arrival_date,
        "incident": {
            "identifier": case_id,
            "date": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": {
                "ip": origin.get("ip",""),
                "asn": origin.get("asn",""),
                "country": origin.get("cc",""),
                "organization": origin.get("org","")
            },
            "category": "spam" if score.get("decision","").startswith("Likely malicious") else "other",
            "description": f"Automated analysis detected potential abuse from {origin.get('ip','unknown')}"
        },
        "reported-from": {
            "domain": doms.get("from_domain",{}).get("domain",""),
            "email": headers.get("from","")
        },
        "authentication-results": headers.get("auth_results", {}),
        "original-mail": headers.get("raw_headers", "")
    }
    
    arf_part = MIMEApplication(json.dumps(feedback_report, indent=2), 'json', name='feedback-report.json')
    arf_part.add_header('Content-Disposition', 'attachment', filename='feedback-report.json')
    msg.attach(arf_part)
    
    # Attach original message if available
    eml_path = os.path.join(case_dir, "evidence", "original.eml")
    if os.path.exists(eml_path):
        with open(eml_path, "rb") as f:
            eml_data = f.read()
        eml_part = MIMEApplication(eml_data, 'octet-stream', name='original.eml')
        eml_part.add_header('Content-Disposition', 'attachment', filename='original.eml')
        msg.attach(eml_part)
    
    # Write ARF message
    arf_out = os.path.join(case_dir, "package", "arf_report.eml")
    os.makedirs(os.path.join(case_dir,"package"), exist_ok=True)
    write_text(arf_out, msg.as_string())
    
    return arf_out

def generate_xarf_package(case_dir, reporter_email="abuse@example.com"):
    """Generate X-ARF (extended ARF) JSON package"""
    # Load case data
    headers_path = os.path.join(case_dir, "headers.json")
    origin_path = os.path.join(case_dir, "origin.json")
    domains_path = os.path.join(case_dir, "domains.json")
    received_path = os.path.join(case_dir, "received_path.json")
    score_path = os.path.join(case_dir, "report", "score.json")
    
    with open(headers_path, "r", encoding="utf-8") as f: headers = json.load(f)
    with open(origin_path, "r", encoding="utf-8") as f: origin = json.load(f)
    with open(domains_path, "r", encoding="utf-8") as f: doms = json.load(f)
    with open(received_path, "r", encoding="utf-8") as f: received_data = json.load(f)
    
    score = {}
    if os.path.exists(score_path):
        with open(score_path, "r", encoding="utf-8") as f: score = json.load(f)
    
    case_id = os.path.basename(case_dir).replace("case-","")
    
    # Get arrival date from first received hop
    arrival_date = ""
    ordered_hops = received_data.get("ordered_hops", [])
    if ordered_hops:
        arrival_date = ordered_hops[0].get("date", "")
    
    # X-ARF JSON structure
    xarf_report = {
        "x-arf-version": "1.0",
        "schema": "io.paw.abuse-report",
        "category": "abuse",
        "report-id": case_id,
        "reporter": reporter_email,
        "reported-time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "arrival-date": arrival_date,
        "source": {
            "ip": origin.get("ip",""),
            "asn": origin.get("asn",""),
            "country": origin.get("cc",""),
            "organization": origin.get("org",""),
            "ptr": origin.get("ptr",""),
            "helo": origin.get("helo","")
        },
        "reported-from": {
            "domain": doms.get("from_domain",{}).get("domain",""),
            "email": headers.get("from",""),
            "registrar": doms.get("from_domain",{}).get("registrar",""),
            "created": doms.get("from_domain",{}).get("created",""),
            "nameservers": doms.get("from_domain",{}).get("ns",[]),
            "mx": doms.get("from_domain",{}).get("mx",[])
        },
        "authentication": headers.get("auth_results", {}),
        "scoring": {
            "decision": score.get("decision","Inconclusive"),
            "bk_score": score.get("bk_score",""),
            "mixed_flag": score.get("mixed_flag","")
        },
        "evidence": {
            "root_hash": _read_root(case_dir),
            "headers": headers.get("raw_headers", "")
        }
    }
    
    # Write X-ARF JSON
    xarf_out = os.path.join(case_dir, "package", "xarf_report.json")
    os.makedirs(os.path.join(case_dir,"package"), exist_ok=True)
    with open(xarf_out, "w", encoding="utf-8") as f:
        json.dump(xarf_report, f, indent=2)
    
    return xarf_out

def _read_root(case_dir):
    p = os.path.join(case_dir, "evidence", "merkle_root.bin")
    if not os.path.exists(p): return ""
    with open(p,"rb") as f: return f.read().decode("utf-8","ignore")
