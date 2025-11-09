
import os, json, uuid, shutil, hashlib, time, ipaddress, re
from ..util.timeutil import utc_now_iso
from ..util.hashutil import blake3_hex, file_blake3_hex
from ..util.fsutil import ensure_dir, write_json, write_text, sanitize_case_id, read_json
from .parser_mail import parse_mail
from .received import normalize_received
from .auth import infer_alignment
from .profiler import ip_rdap, domain_rdap, nrd_days
from .scoring import score_case
from ..deobfuscate.core import DeobfuscationEngine

# Rich imports for beautiful terminal output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn

def check_domain_reputation(domain):
    """Check domain reputation using various sources."""
    if not domain:
        return {"score": 0, "category": "unknown", "sources": []}
    
    reputation = {"score": 0, "category": "clean", "sources": []}
    
    # Check for suspicious keywords in domain
    suspicious_keywords = [
        'secure', 'login', 'verify', 'account', 'update', 'confirm', 'alert', 'warning',
        'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'support',
        'notification', 'service', 'help', 'contact', 'admin'
    ]
    
    domain_lower = domain.lower()
    for keyword in suspicious_keywords:
        if keyword in domain_lower:
            reputation["score"] += 1
            reputation["sources"].append(f"keyword:{keyword}")
    
    # Check for numbers in domain (often used in phishing)
    import re
    if re.search(r'\d', domain):
        reputation["score"] += 1
        reputation["sources"].append("contains_numbers")
    
    # Check domain age (very new domains are suspicious)
    try:
        from .profiler import domain_rdap
        rdap = domain_rdap(domain)
        created = rdap.get("created")
        if created:
            from datetime import datetime
            created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
            now = datetime.now(created_date.tzinfo)
            age_days = (now - created_date).days
            
            if age_days < 30:
                reputation["score"] += 5  # Very suspicious
                reputation["sources"].append(f"very_new_domain:{age_days}d")
            elif age_days < 365:
                reputation["score"] += 2  # Moderately suspicious
                reputation["sources"].append(f"new_domain:{age_days}d")
    except:
        pass
    
    # Determine category based on score
    if reputation["score"] >= 5:
        reputation["category"] = "high_risk"
    elif reputation["score"] >= 2:
        reputation["category"] = "medium_risk"
    elif reputation["score"] > 0:
        reputation["category"] = "low_risk"
    else:
        reputation["category"] = "clean"
    
    return reputation

def check_ip_reputation(ip):
    """Check IP reputation using various sources."""
    if not ip:
        return {"score": 0, "category": "unknown", "sources": []}
    
    reputation = {"score": 0, "category": "clean", "sources": []}
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a cloud provider IP (often used for phishing infrastructure)
        cloud_ranges = [
            # AWS
            ipaddress.ip_network('52.0.0.0/8'),
            ipaddress.ip_network('54.0.0.0/8'),
            # Azure
            ipaddress.ip_network('13.64.0.0/11'),
            ipaddress.ip_network('20.0.0.0/8'),
            # Google Cloud
            ipaddress.ip_network('35.184.0.0/13'),
            # DigitalOcean
            ipaddress.ip_network('104.236.0.0/16'),
        ]
        
        for cloud_range in cloud_ranges:
            if ip_obj in cloud_range:
                reputation["score"] += 1
                reputation["sources"].append("cloud_provider")
                break
        
        # Check for TOR exit nodes (suspicious)
        tor_exits = [
            '185.220.101.0/24',  # Example TOR range
            '185.220.102.0/24',
        ]
        for tor_range in tor_exits:
            if ip_obj in ipaddress.ip_network(tor_range):
                reputation["score"] += 5
                reputation["sources"].append("tor_exit_node")
                break
        
        # Check RDAP for additional info
        try:
            from .profiler import ip_rdap
            rdap = ip_rdap(ip)
            if rdap:
                # Check if it's a residential IP (less suspicious)
                if rdap.get("type") == "residential":
                    reputation["score"] -= 1
                    reputation["sources"].append("residential_ip")
                
                # Check ASN country (historical registration - informational)
                asn_country = rdap.get("asn_cc")
                if asn_country:
                    reputation["sources"].append(f"asn_registered_in:{asn_country}")
                    # Only penalize if ASN is registered in high-spam countries AND physical location is also suspicious
                    physical_country = rdap.get("cc")
                    if asn_country in ['CN', 'RU', 'IN', 'BR'] and physical_country in ['CN', 'RU', 'IN', 'BR']:
                        reputation["score"] += 1
                        reputation["sources"].append(f"high_spam_asn_and_location:{asn_country}")
                    elif asn_country in ['CN', 'RU', 'IN', 'BR']:
                        reputation["sources"].append(f"high_spam_asn_only:{asn_country}")

        except:
            pass
            
    except Exception as e:
        reputation["sources"].append(f"error:{str(e)}")
    
    # Determine category based on score
    if reputation["score"] >= 5:
        reputation["category"] = "high_risk"
    elif reputation["score"] >= 2:
        reputation["category"] = "medium_risk"
    elif reputation["score"] > 0:
        reputation["category"] = "low_risk"
    elif reputation["score"] < 0:
        reputation["category"] = "trusted"
    else:
        reputation["category"] = "clean"
    
    return reputation

def inject_canary_link(case_id: str, headers: dict, body_text: str) -> str:
    """Inject a canary link into email body for URL-less phishing detection."""
    try:
        # Generate unique canary URL for this case
        canary_token = hashlib.sha256(f"{case_id}:{utc_now_iso()}".encode()).hexdigest()[:16]
        canary_url = f"http://localhost:8787/c/{canary_token}"
        
        # Create attractive link text based on email content
        subject = headers.get("subject", "").lower()
        link_text = "Verify Your Account"
        
        # Customize link text based on email content
        if "password" in body_text.lower() or "login" in body_text.lower():
            link_text = "Reset Your Password"
        elif "account" in body_text.lower():
            link_text = "Access Your Account"
        elif "verify" in body_text.lower():
            link_text = "Complete Verification"
        elif "urgent" in subject:
            link_text = "Take Action Now"
        
        # Inject the link into the email body
        # Find a good place to insert it (after common phishing phrases)
        injection_points = [
            "Click here",
            "Follow this link",
            "Visit:",
            "Go to:",
            "Access here:",
            "Login here:"
        ]
        
        modified_body = body_text
        link_injected = False
        
        for point in injection_points:
            if point in modified_body and not link_injected:
                # Replace the injection point with our canary link
                link_html = f'<a href="{canary_url}">{link_text}</a>'
                modified_body = modified_body.replace(point, f'{point} {link_html}', 1)
                link_injected = True
                break
        
        # If no good injection point found, append at the end
        if not link_injected:
            modified_body += f"\n\n{link_text}: {canary_url}"
        
        # Update the body in headers for processing
        headers["_modified_body"] = modified_body
        
        return canary_url
        
    except Exception as e:
        print(f"[canary] failed to inject canary link: {e}")
        return ""

def trace_campaign_origin(headers: dict, hops: list) -> dict:
    """Trace the true origin of phishing campaigns beyond the transmitting server."""
    origin_analysis = {
        "campaign_origin": {},
        "sending_patterns": [],
        "infrastructure_hints": [],
        "attribution_confidence": "low"
    }
    
    # Analyze email headers for campaign patterns
    subject = headers.get("subject", "").lower()
    from_addr = headers.get("from", "").lower()
    
    # 1. Check for known phishing campaign patterns
    campaign_patterns = {
        "business_email_compromise": [
            "wire transfer", "invoice", "payment", "urgent payment", "overdue",
            "account payable", "ceo", "cfo", "director", "newsletter", "announcement"
        ],
        "credential_phishing": [
            "verify account", "login required", "password reset", "security alert",
            "account suspension", "unusual activity"
        ],
        "package_delivery": [
            "package delivery", "shipping notification", "tracking", "fedex", "dhl", "ups"
        ],
        "banking_fraud": [
            "bank account", "credit card", "transaction alert", "security breach"
        ]
    }
    
    detected_campaigns = []
    for campaign_type, patterns in campaign_patterns.items():
        if any(pattern in subject or pattern in from_addr for pattern in patterns):
            detected_campaigns.append(campaign_type)
    
    # Additional BEC detection based on From address patterns
    if "business_email_compromise" not in detected_campaigns:
        # Check for corporate-sounding email addresses
        from_domain = ""
        m = re.search(r"@([^>]+)", from_addr)
        if m:
            from_domain = m.group(1).strip().lower()
            # Corporate domains often have company-like names
            corporate_indicators = ["labs", "tech", "solutions", "systems", "group", "inc", "ltd", "corp"]
            if any(indicator in from_domain for indicator in corporate_indicators):
                detected_campaigns.append("business_email_compromise")
                origin_analysis["infrastructure_hints"].append(f"Corporate domain {from_domain} suggests business email compromise")
    
    if detected_campaigns:
        origin_analysis["campaign_origin"]["detected_types"] = detected_campaigns
        origin_analysis["attribution_confidence"] = "medium"
    
    # 2. Analyze sending infrastructure patterns
    sending_patterns = []
    
    # Identify the first non-Microsoft hop as potential origin
    first_non_ms_hop = None
    for hop in reversed(hops):  # Start from the end (origin)
        from_domain = hop.get("from", "").split("(")[0].strip().lower()
        if not any(ms_domain in from_domain for ms_domain in ["outlook.com", "microsoft", "office365"]):
            first_non_ms_hop = hop
            break
    
    if first_non_ms_hop:
        origin_ip = first_non_ms_hop.get("ip", "")
        origin_domain = first_non_ms_hop.get("from", "").split("(")[0].strip()
        
        if origin_ip:
            sending_patterns.append("non_ms_origin_server")
            origin_analysis["infrastructure_hints"].append(f"Non-Microsoft origin server: {origin_domain} ({origin_ip})")
            origin_analysis["campaign_origin"]["likely_source"] = f"compromised_server_{origin_domain}"
            origin_analysis["attribution_confidence"] = "high"
            
            # 🚀 NUOVO: Analisi ricorsiva dell'infrastruttura compromessa
            recursive_analysis = analyze_compromised_infrastructure(origin_domain, origin_ip)
            if recursive_analysis:
                origin_analysis["infrastructure_chain"] = recursive_analysis
                origin_analysis["attribution_confidence"] = "very_high"
    
    # Check for cloud provider patterns
    for hop in hops:
        ip = hop.get("ip", "")
        if ip:
            # AWS ranges
            if ipaddress.ip_address(ip) in ipaddress.ip_network('52.0.0.0/8') or \
               ipaddress.ip_address(ip) in ipaddress.ip_network('54.0.0.0/8'):
                sending_patterns.append("aws_ec2_sending")
                origin_analysis["infrastructure_hints"].append("AWS infrastructure commonly used for spam/phishing")
            
            # Azure ranges  
            elif ipaddress.ip_address(ip) in ipaddress.ip_network('13.64.0.0/11'):
                sending_patterns.append("azure_sending")
                origin_analysis["infrastructure_hints"].append("Azure infrastructure - possible compromised account")
            
            # Google Cloud ranges
            elif ipaddress.ip_address(ip) in ipaddress.ip_network('35.184.0.0/13'):
                sending_patterns.append("gcp_sending")
                origin_analysis["infrastructure_hints"].append("Google Cloud - check for compromised service accounts")
    
    # 3. Check for compromised mail server patterns
    from_domain = ""
    m = re.search(r"@([^>]+)", from_addr)
    if m:
        from_domain = m.group(1).strip().lower()
        
        # Known compromised domains or suspicious patterns
        suspicious_domains = [
            "outlook.com", "hotmail.com", "gmail.com", "yahoo.com",  # Free email providers
            "protonmail.com", "tutanota.com"  # Privacy-focused (often abused)
        ]
        
        if any(domain in from_domain for domain in suspicious_domains):
            sending_patterns.append("compromised_free_email")
            origin_analysis["infrastructure_hints"].append(f"From domain {from_domain} suggests compromised email account")
            origin_analysis["attribution_confidence"] = "high"
    
    # 4. Time-based analysis
    received_dates = []
    for hop in hops:
        if hop.get("date"):
            try:
                # Parse various date formats
                date_str = hop["date"]
                if date_str.endswith(" +0000"):
                    date_str = date_str.replace(" +0000", " +00:00")
                elif " +0000" in date_str:
                    date_str = date_str.replace(" +0000", "+00:00")
                
                from email.utils import parsedate_to_datetime
                parsed_date = parsedate_to_datetime(date_str)
                received_dates.append(parsed_date)
            except:
                pass
    
    if len(received_dates) >= 2:
        time_diffs = []
        for i in range(1, len(received_dates)):
            diff = (received_dates[i] - received_dates[i-1]).total_seconds()
            time_diffs.append(diff)
        
        avg_delay = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        
        if avg_delay < 10:  # Very fast relay
            sending_patterns.append("fast_relay_suspicious")
            origin_analysis["infrastructure_hints"].append("Unusually fast email relay - possible direct sending")
        elif avg_delay > 300:  # Slow relay
            sending_patterns.append("slow_relay_bulk")
            origin_analysis["infrastructure_hints"].append("Slow relay pattern - typical of bulk email campaigns")
    
    # 5. Geographic analysis
    countries = []
    for hop in hops:
        ip = hop.get("ip", "")
        if ip:
            try:
                rdap = ip_rdap(ip)
                if rdap and rdap.get("cc"):
                    countries.append(rdap["cc"])
            except:
                pass
    
    unique_countries = list(set(countries))
    if len(unique_countries) > 2:
        sending_patterns.append("multi_country_relay")
        origin_analysis["infrastructure_hints"].append(f"Email relayed through {len(unique_countries)} countries: {', '.join(unique_countries)}")
        origin_analysis["attribution_confidence"] = "high"
    
    origin_analysis["sending_patterns"] = sending_patterns
    
    # 6. Final attribution attempt
    if origin_analysis["attribution_confidence"] == "high":
        if "compromised_free_email" in sending_patterns:
            origin_analysis["campaign_origin"]["likely_source"] = "compromised_email_account"
        elif "multi_country_relay" in sending_patterns:
            origin_analysis["campaign_origin"]["likely_source"] = "professional_phishing_service"
        elif any("aws" in p or "azure" in p or "gcp" in p for p in sending_patterns):
            origin_analysis["campaign_origin"]["likely_source"] = "cloud_compromised_infrastructure"
    
    return origin_analysis

def analyze_phishing_content(body_text, subject, from_addr):
    """Analyze email content for phishing indicators."""
    analysis = {
        "phishing_score": 0,
        "indicators": [],
        "urgency_words": [],
        "threat_words": [],
        "suspicious_patterns": []
    }
    
    text_to_analyze = (body_text + " " + subject + " " + from_addr).lower()
    
    # Urgency indicators
    urgency_indicators = [
        'urgent', 'immediate', 'action required', 'time sensitive', 'deadline', 
        'expires', 'limited time', 'act now', 'do not delay', 'critical',
        'warning', 'alert', 'attention', 'important', 'priority'
    ]
    
    for indicator in urgency_indicators:
        if indicator in text_to_analyze:
            analysis["phishing_score"] += 1
            analysis["urgency_words"].append(indicator)
    
    # Threat indicators  
    threat_indicators = [
        'account suspended', 'account blocked', 'account locked', 'security breach',
        'unauthorized access', 'suspicious activity', 'verify your account',
        'confirm your identity', 'password expired', 'login failed',
        'payment declined', 'billing issue', 'refund', 'chargeback',
        'account is suspended', 'account has been suspended', 'suspended account'
    ]
    
    for indicator in threat_indicators:
        if indicator in text_to_analyze:
            analysis["phishing_score"] += 2
            analysis["threat_words"].append(indicator)
    
    # Suspicious patterns
    patterns = [
        r'\b\d{4,}\b',  # Reference numbers
        r'\bID[:#]\s*\w+',  # ID references
        r'\bref[:#]\s*\w+',  # Reference numbers
        r'\bcustomer\s+support\b',
        r'\btechnical\s+support\b',
        r'\bsecurity\s+team\b'
    ]
    
    import re
    for pattern in patterns:
        if re.search(pattern, text_to_analyze, re.IGNORECASE):
            analysis["phishing_score"] += 1
            analysis["suspicious_patterns"].append(pattern)
    
    # Language analysis - mixed languages can be suspicious
    if any(word in text_to_analyze for word in ['konto', 'vil', 'blive', 'bekræft']) and \
       any(word in text_to_analyze for word in ['account', 'verify', 'confirm', 'login']):
        analysis["phishing_score"] += 2
        analysis["indicators"].append("mixed_languages")
    
    return analysis

from .graphs import attribution_graph, domain_graph, detonation_box, canary_box
from .evidence import merkle_root, write_index
from .stix import make_stix
from .abuse import generate_abuse_package, generate_arf_package, generate_xarf_package
from .rekor import anchor_case
from ..intelligence.criminal_hunter import CriminalHunter
from ..intelligence.infrastructure_mapper import InfrastructureMapper
from ..intelligence.enrich_last_hunt import safe_getcert, grab_banner, reverse_dns, whois_lookup, asn_lookup
from ..intelligence.threat_intel import ThreatIntelligence

def trace_sources(src, lang, stix, abuse, anchor, no_egress, profile="default", deob_weight: float = 0.30):
    if os.path.isfile(src):
        trace_one(src, lang, stix, abuse, anchor, no_egress, profile, deob_weight)
    else:
        for f in os.listdir(src):
            if f.endswith(('.eml', '.msg')):
                trace_one(os.path.join(src, f), lang, stix, abuse, anchor, no_egress, profile, deob_weight)

def trace_one(eml_path, lang, stix, abuse, anchor, no_egress, profile="default", deob_weight: float = 0.30):
    case_id = sanitize_case_id(utc_now_iso().replace(":","").replace("Z","Z-") + str(uuid.uuid4())[:4])
    case_dir = os.path.join(os.getcwd(), "cases", "case-" + case_id)
    ensure_dir(case_dir)
    
    # Ingest
    with open(eml_path,"rb") as f: b = f.read()
    eml_hash = blake3_hex(b)
    shutil.copy2(eml_path, os.path.join(case_dir,"input.eml"))
    manifest = {"case_id": case_id, "created_utc": utc_now_iso(), "inputs":[{"path":"input.eml","blake3": eml_hash, "size": len(b)}], "policy":{"no_egress": bool(no_egress)}, "deobfuscation_weight": float(deob_weight)}
    write_json(os.path.join(case_dir,"manifest.json"), manifest)
    # PGP sign manifest if keys available
    if os.environ.get("PAW_PGP_PRIV"):
        try:
            from .signature import sign_file_pgp
            manifest_path = os.path.join(case_dir, "manifest.json")
            sig_path = os.path.join(case_dir, "evidence", "manifest.json.asc")
            sign_file_pgp(manifest_path, os.environ["PAW_PGP_PRIV"], os.environ.get("PAW_PGP_PASS"), sig_path)
            print(f"[pgp] manifest signed: {sig_path}")
        except Exception as e:
            print(f"[pgp] signing failed: {e}")
    # Parse headers
    headers = parse_mail(eml_path)
    
    # Extract URLs from email body
    import email
    from email import policy
    from email.parser import BytesParser
    with open(eml_path, "rb") as f:
        b = f.read()
    msg = BytesParser(policy=policy.default).parsebytes(b)
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif part.get_content_type() == "text/html":
                import re
                html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                # Remove HTML tags for URL extraction
                body_text += re.sub(r'<[^>]+>', '', html)
    else:
        body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
    
    # Extract URLs using regex
    import re
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, body_text)
    # Also check subject and other headers
    subj_urls = re.findall(url_pattern, headers.get("subject", ""))
    from_urls = re.findall(url_pattern, headers.get("from", ""))
    urls.extend(subj_urls + from_urls)
    # Deduplicate
    urls = list(set(urls))
    headers["urls"] = urls
    
    # Deobfuscate content to reveal hidden URLs and malicious content
    deobfuscation_engine = DeobfuscationEngine()
    
    # Combine all text content for analysis
    full_text = body_text
    if headers.get("subject"):
        full_text += " " + headers["subject"]
    
    # Extract potential URLs from text for deobfuscation analysis
    potential_urls = []
    # Look for URL-like patterns in the text (including obfuscated ones)
    import re
    url_patterns = [
        r'https?://[^\s<>"\']+',  # Standard URLs
        r'hxxps?://[^\s<>"\']+',  # Obfuscated hxxp/hxxps
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*',  # Domain-like patterns
        r'%[0-9A-Fa-f]{2}.*?[^\s<>"\']*',  # Percent-encoded sequences
    ]
    for pattern in url_patterns:
        matches = re.findall(pattern, full_text)
        for match in matches:
            # Skip email addresses (contain @ and look like user@domain)
            if '@' in match and re.match(r'^[^@]+@[^@]+\.[^@]+$', match):
                continue
            # Skip obvious email domains in context
            if any(email_domain in match.lower() for email_domain in ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com']):
                continue
            potential_urls.append(match)
    
    # Also add any URLs that contain suspicious characters (but not email addresses)
    words = re.findall(r'\S+', full_text)
    for word in words:
        if any(char in word for char in ['%', '!', '€', '£']) and len(word) > 10:
            # Skip if it looks like an email address
            if '@' in word and re.match(r'^[^@]+@[^@]+\.[^@]+$', word):
                continue
            potential_urls.append(word)
    
    deobfuscation_artifacts = {
        "text": full_text,
        "urls": list(set(potential_urls + urls)),  # Include both extracted and regex-found URLs
        "html": "",  # Will be populated if HTML is found
        "javascript": "",  # Will be populated if JS is found
        "attachments": []
    }
    
    # Extract HTML and JavaScript content for deeper analysis
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                deobfuscation_artifacts["html"] = html_content
            elif part.get_content_type() in ["application/javascript", "text/javascript"]:
                js_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                deobfuscation_artifacts["javascript"] = js_content
    
    deobfuscation_results = deobfuscation_engine.analyze_artifacts(deobfuscation_artifacts)
    headers["deobfuscation_analysis"] = deobfuscation_results
    # Persist deobfuscation results in the case directory for downstream analysis
    try:
        write_json(os.path.join(case_dir, "deobfuscation_results.json"), deobfuscation_results)
    except Exception as e:
        print(f"[deobfuscate] failed to write deobfuscation_results.json: {e}")
    
    # Add any newly discovered URLs from deobfuscation
    deobfuscated = deobfuscation_results.get("deobfuscated_artifacts", {})
    if deobfuscated.get("urls"):
        for url_data in deobfuscated["urls"]:
            final_url = url_data.get("final_url")
            # Skip email addresses - don't report them as discovered URLs
            if url_data.get("is_email", False):
                continue
            if final_url and final_url not in urls:
                urls.append(final_url)
                print(f"[deobfuscate] discovered hidden URL: {final_url}")
        headers["urls"] = urls
    
    # Analyze content for phishing indicators
    subject = headers.get("subject", "")
    from_addr = headers.get("from", "")
    phishing_analysis = analyze_phishing_content(body_text, subject, from_addr)
    headers["phishing_analysis"] = phishing_analysis
    
    # ML scoring for canary injection decision
    from .ml_scorer import score_email_for_canary
    ml_score = score_email_for_canary({
        'subject': subject,
        'body': body_text,
        'from': from_addr
    })
    headers["ml_score"] = ml_score
    
    # Inject canary link if recommended and no URLs found
    if ml_score.get('recommendations', {}).get('inject_canary') and not urls:
        canary_url = inject_canary_link(case_id, headers, body_text)
        if canary_url:
            urls.append(canary_url)
            headers["urls"] = urls
            headers["canary_injected"] = True
            print(f"[canary] injected canary link for URL-less phishing: {canary_url}")
    
    # Analyze domain reputation for found URLs
    if urls:
        domain_analysis = []
        for url in urls:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    reputation = check_domain_reputation(domain)
                    domain_analysis.append({
                        "url": url,
                        "domain": domain,
                        "reputation": reputation
                    })
            except Exception as e:
                domain_analysis.append({
                    "url": url,
                    "domain": "error",
                    "reputation": {"score": 0, "category": "error", "sources": [str(e)]}
                })
        headers["domain_analysis"] = domain_analysis
    
    write_json(os.path.join(case_dir,"headers.json"), headers)
    # Automatic detonation if URLs found
    if urls:
        print(f"[detonate] found {len(urls)} URLs, starting automatic detonation...")
        try:
            from ..detonate.runner import run_detonation
            case_id_short = os.path.basename(case_dir)
            for url in urls:
                print(f"[detonate] detonating {url}...")
                run_detonation(url=url, case_id=case_id_short, timeout=35, capture_pcap=False, headless=True, observe_only=True)
        except Exception as e:
            print(f"[detonate] automatic detonation failed: {e}")
        
        # Automatic canary deployment
        print(f"[canary] starting automatic canary server for {len(urls)} URLs...")
        try:
            import subprocess
            case_id_short = os.path.basename(case_dir)
            # Calculate unique port based on case_id hash
            port = 8787 + (hash(case_id_short) % 1000)
            # Start canary server in background
            cmd = ["python", "-m", "paw", "canary", "--case", case_id_short, "--port", str(port)]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[canary] canary server started on port {port} for case {case_id_short}")
        except Exception as e:
            print(f"[canary] automatic canary deployment failed: {e}")
    # Scan attachments if present
    atts = []
    if "_msg_obj" in headers:
        try:
            from .attach import scan_attachments
            atts = scan_attachments(headers["_msg_obj"])
            write_json(os.path.join(case_dir,"attachments.json"), atts)
        except Exception as e:
            print(f"[attach] scanning failed: {e}")
    # Normalize Received
    norm = normalize_received(headers.get("received") or [])
    hops = norm.get("ordered_hops") or []
    write_json(os.path.join(case_dir,"received_path.json"), {"ordered_hops": hops})
    # Choose origin candidate: prefer first hop with public IP NOT 'recipient_mx_internal'
    def _is_public_ip(s):
        try:
            ip = ipaddress.ip_address(s)
            return ip.is_global
        except Exception:
            return False

    origin = {}
    # Prefer external_ingress hops (email entering MX protection)
    for h in hops:
        if h.get("ip") and _is_public_ip(h["ip"]) and h.get("role") == "external_ingress":
            origin = h
            break
    # Fallback: internet_origin_candidate hops
    if not origin:
        for h in hops:
            if h.get("ip") and _is_public_ip(h["ip"]) and h.get("role") == "internet_origin_candidate":
                origin = h
                break
    # Fallback: any public IP not recipient_mx_internal
    if not origin:
        for h in hops:
            if h.get("ip") and _is_public_ip(h["ip"]) and h.get("role") != "recipient_mx_internal":
                origin = h
                break
    # Fallback: any public IP
    if not origin:
        for h in hops:
            if h.get("ip") and _is_public_ip(h["ip"]):
                origin = h
                break
    # Fallback: any IP
    if not origin and hops:
        for h in hops:
            if h.get("ip"):
                origin = h
                break
    # Last resort: first hop
    if not origin and hops:
        origin = hops[0]
    # Auth alignment (from Authentication-Results)
    auth = infer_alignment(headers, headers.get("from",""), headers.get("return_path",""))
    write_json(os.path.join(case_dir,"auth.json"), auth)
    # Analyze received path for campaign origin
    campaign_origin = trace_campaign_origin(headers, hops)
    write_json(os.path.join(case_dir,"campaign_origin.json"), campaign_origin)
    
    # Profile IP RDAP
    ip = origin.get("ip") or ""
    ip_res = ip_rdap(ip) if ip else {}
    origin_out = {"ip": ip, "asn": ip_res.get("asn"), "org": ip_res.get("asn_org"), "cc": ip_res.get("cc"), "abuse": ip_res.get("abuse", []),
                  "time_utc": origin.get("date"), "helo": origin.get("helo"), "ptr": origin.get("ptr"), "skew_s": origin.get("skew_s",0),
                  "reputation": check_ip_reputation(ip)}
    write_json(os.path.join(case_dir,"transmitting_server.json"), origin_out)
    # Create origin.json alias for compatibility with abuse package
    write_json(os.path.join(case_dir,"origin.json"), origin_out)
    # Merge detonation endpoints → infra hints
    det_sum = os.path.join(case_dir, "detonation", "summary.json")
    if os.path.exists(det_sum):
        det = read_json(det_sum) or {}
        endpoints = det.get("endpoints", [])
        write_json(os.path.join(case_dir,"detonation_endpoints.json"), endpoints)
        
        # Automatic OSINT on detonation IPs (C2 infrastructure mapping)
        if endpoints:
            print("[osint] analyzing detonation infrastructure...")
            c2_analysis = []
            for ep in endpoints:
                ips = ep.get("ips", [])
                if ips:  # Check if ips list is not empty
                    ep_ip = ips[0]  # Take first IP
                    if ep_ip:
                        # RDAP lookup for ASN/Org info
                        rdap = ip_rdap(ep_ip) if ep_ip else {}
                        # Reverse DNS for additional domains
                        try:
                            import socket
                            ptr_records = socket.gethostbyaddr(ep_ip)[0] if ep_ip else ""
                        except:
                            ptr_records = ""
                        
                        c2_analysis.append({
                            "host": ep.get("host"),
                            "ip": ep_ip,
                            "asn": rdap.get("asn"),
                            "org": rdap.get("asn_org"),
                            "country": rdap.get("cc"),
                            "asn_country": rdap.get("asn_cc"),
                            "ptr": ptr_records,
                            "abuse_contacts": rdap.get("abuse", []),
                            "reputation": check_ip_reputation(ep_ip)
                        })
            write_json(os.path.join(case_dir,"c2_infrastructure.json"), c2_analysis)
            print(f"[osint] analyzed {len(c2_analysis)} infrastructure endpoints")

            # 🚀 NUOVO: Analisi del phishing kit estratto per pattern C2
            kit_dir = os.path.join(case_dir, "detonation", "phishing_kit")
            if os.path.exists(kit_dir):
                print("[kit] analyzing extracted phishing kit for C2 patterns...")
                kit_content = {}

                # Carica i file estratti
                for filename in os.listdir(kit_dir):
                    filepath = os.path.join(kit_dir, filename)
                    if os.path.isfile(filepath):
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            if filename.endswith('.html'):
                                kit_content.setdefault('html', []).append(content)
                            elif filename.endswith('.js'):
                                kit_content.setdefault('javascript', []).append(content)
                            elif filename.endswith('.css'):
                                kit_content.setdefault('css', []).append(content)
                        except Exception as e:
                            print(f"[kit] error reading {filename}: {e}")

                # Analizza il contenuto del kit
                if kit_content:
                    kit_analysis = analyze_phishing_kit_content(kit_content)
                    write_json(os.path.join(case_dir, "phishing_kit_analysis.json"), kit_analysis)
                    print(f"[kit] analyzed kit with risk level: {kit_analysis.get('risk_level', 'unknown')}")

                    # Integra nell'analisi della campagna
                    campaign_origin = read_json(os.path.join(case_dir, "campaign_origin.json")) or {}
                    if kit_analysis.get('c2_servers') or kit_analysis.get('exfiltration_endpoints'):
                        campaign_origin.setdefault('infrastructure_chain', {})
                        campaign_origin['infrastructure_chain']['kit_c2_analysis'] = kit_analysis
                        campaign_origin['attribution_confidence'] = 'very_high'
                        write_json(os.path.join(case_dir, "campaign_origin.json"), campaign_origin)
                        print("[kit] integrated kit analysis into campaign origin")

            # 🚀 NUOVO: Integrazione Criminal Hunter per analisi infrastrutturale avanzata
            print("[criminal_hunter] starting advanced infrastructure analysis...")
            try:
                hunter = CriminalHunter()
                
                # Analizza tutti gli endpoint C2 trovati
                criminal_intel = []
                for ep in endpoints:
                    host = ep.get("host", "")
                    if host:
                        try:
                            hunt_result = hunter.hunt_from_domain(host)
                            if hunt_result:
                                criminal_intel.append({
                                    "target_domain": host,
                                    "criminal_analysis": hunt_result
                                })
                                print(f"[criminal_hunter] analyzed infrastructure for {host}")
                        except Exception as e:
                            print(f"[criminal_hunter] failed to analyze {host}: {e}")
                
                if criminal_intel:
                    write_json(os.path.join(case_dir, "criminal_intelligence.json"), criminal_intel)
                    print(f"[criminal_hunter] completed analysis for {len(criminal_intel)} domains")
                    
                    # Integra nell'attribution matrix se disponibile
                    matrix_file = os.path.join(case_dir, "attribution_matrix.json")
                    if os.path.exists(matrix_file):
                        matrix_data = read_json(matrix_file) or {}
                        matrix_data["criminal_intelligence"] = criminal_intel
                        write_json(matrix_file, matrix_data)
                        print("[criminal_hunter] integrated into attribution matrix")
                        
            except Exception as e:
                print(f"[criminal_hunter] failed: {e}")

            # 🚀 NUOVO: Integrazione Enrich Last Hunt per arricchimento SSL e banner
            print("[enrich_last_hunt] starting SSL certificate and banner enrichment...")
            try:
                hunt_enrichments = []
                
                # Arricchisci tutti gli IP dell'infrastruttura C2
                for ep in endpoints:
                    ips = ep.get("ips", [])
                    host = ep.get("host", "")
                    
                    for enrich_ip in ips:
                        try:
                            # Ottieni certificato SSL
                            cert_data = safe_getcert(host, port=443)
                            
                            # Ottieni banner dei servizi comuni
                            banners = {}
                            common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
                            for port in common_ports:
                                banner = grab_banner(enrich_ip, port)
                                if banner and not banner.startswith('{"'):
                                    banners[str(port)] = banner
                            
                            # Reverse DNS
                            rdns = reverse_dns(enrich_ip)
                            
                            # WHOIS e ASN lookup
                            whois_data = whois_lookup(host) if host else {}
                            asn_data = asn_lookup(enrich_ip)
                            
                            enrichment = {
                                "ip": enrich_ip,
                                "host": host,
                                "ssl_certificate": cert_data,
                                "service_banners": banners,
                                "reverse_dns": rdns,
                                "whois": whois_data,
                                "asn_info": asn_data
                            }
                            
                            hunt_enrichments.append(enrichment)
                            print(f"[enrich_last_hunt] enriched {enrich_ip} ({host})")
                            
                        except Exception as e:
                            hunt_enrichments.append({
                                "ip": enrich_ip,
                                "host": host,
                                "error": str(e)
                            })
                
                if hunt_enrichments:
                    # Clean hunt_enrichments to remove non-serializable data
                    def clean_for_json(obj):
                        if isinstance(obj, dict):
                            return {k: clean_for_json(v) for k, v in obj.items() if not isinstance(v, bytes)}
                        elif isinstance(obj, list):
                            return [clean_for_json(item) for item in obj]
                        elif isinstance(obj, (str, int, float, bool)) or obj is None:
                            return obj
                        else:
                            return str(obj)  # Convert other types to string
                    
                    clean_enrichments = clean_for_json(hunt_enrichments)
                    write_json(os.path.join(case_dir, "hunt_enrichments.json"), clean_enrichments)
                    print(f"[enrich_last_hunt] completed enrichment for {len(clean_enrichments)} endpoints")
                    
                    # Integra nell'attribution matrix
                    matrix_file = os.path.join(case_dir, "attribution_matrix.json")
                    if os.path.exists(matrix_file):
                        matrix_data = read_json(matrix_file) or {}
                        matrix_data["hunt_enrichments"] = hunt_enrichments
                        write_json(matrix_file, matrix_data)
                        print("[enrich_last_hunt] integrated into attribution matrix")
                        
            except Exception as e:
                print(f"[enrich_last_hunt] failed: {e}")

            # 🚀 INFRASTRUCTURE MAPPER: Eseguito DOPO enrich_last_hunt per avere SSL/banners disponibili
            print("[infrastructure_mapper] starting advanced network mapping (post-enrichment)...")
            try:
                mapper = InfrastructureMapper()
                
                # Raccogli tutti gli IP dall'analisi C2
                all_ips = []
                for ep in endpoints:
                    ips = ep.get("ips", [])
                    if isinstance(ips, list):
                        all_ips.extend(ips)
                
                # Rimuovi duplicati
                all_ips = list(set(all_ips))
                
                if all_ips and len(all_ips) > 0:
                    # Prendi il dominio principale dalla campagna
                    target_domain = ""
                    for ep in endpoints:
                        host = ep.get("host", "")
                        if host and "." in host:
                            target_domain = host
                            break
                    
                    # Fallback: usa il primo URL detonato
                    if not target_domain and urls and isinstance(urls, list) and len(urls) > 0:
                        from urllib.parse import urlparse
                        try:
                            parsed = urlparse(urls[0])
                            target_domain = parsed.netloc or ""
                        except:
                            pass
                    
                    if target_domain:
                        try:
                            infra_map = mapper.comprehensive_map(target_domain, all_ips)
                            if infra_map:
                                write_json(os.path.join(case_dir, "infrastructure_mapping.json"), infra_map)
                                print(f"[infrastructure_mapper] completed mapping for {len(all_ips)} IPs with enriched data")
                                
                                # Integra nell'attribution matrix
                                matrix_file = os.path.join(case_dir, "attribution_matrix.json")
                                if os.path.exists(matrix_file):
                                    matrix_data = read_json(matrix_file) or {}
                                    matrix_data["infrastructure_mapping"] = infra_map
                                    write_json(matrix_file, matrix_data)
                                    print("[infrastructure_mapper] integrated into attribution matrix")
                        except Exception as map_err:
                            print(f"[infrastructure_mapper] comprehensive_map failed: {map_err}")
                    else:
                        print("[infrastructure_mapper] No target domain found, skipping mapping")
                else:
                    print("[infrastructure_mapper] No IPs found for mapping, skipping")
                            
            except Exception as e:
                print(f"[infrastructure_mapper] failed: {e}")

    # Merge canary hits → attacker_visit
    hits = os.path.join(case_dir, "canary", "hits.jsonl")
    if os.path.exists(hits):
        ips = set()
        canary_visitors = []
        with open(hits,"r",encoding="utf-8") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    visitor_ip = j.get("ip")
                    if visitor_ip:
                        ips.add(visitor_ip)
                        canary_visitors.append({
                            "ip": visitor_ip,
                            "timestamp": j.get("ts"),
                            "user_agent": j.get("ua"),
                            "url": j.get("url"),
                            "reputation": check_ip_reputation(visitor_ip)
                        })
                except Exception: pass
        write_json(os.path.join(case_dir,"canary_ips.json"), sorted([cip for cip in ips if cip]))
        write_json(os.path.join(case_dir,"canary_visitors.json"), canary_visitors)
    # From domain info
    from_addr = headers.get("from","")
    import re
    m = re.search(r"@([^>]+)", from_addr or "")
    from_domain = (m.group(1).strip().lower() if m else "")
    dominfo = {"from_domain": {"domain": from_domain}}
    if from_domain:
        dr = domain_rdap(from_domain)
        nd = nrd_days(dr.get("created"))
        dr["nrd_days"] = nd
        dominfo["from_domain"] = dr
    write_json(os.path.join(case_dir,"domains.json"), dominfo)
    
    # 🚀 NUOVO: Correlazione automatica Threat Intelligence
    print("[threat_intel] starting automatic threat intelligence correlation...")
    try:
        ti = ThreatIntelligence()

        # Raccogli tutti i domini e IP dall'analisi precedente
        all_domains = []
        all_ips = []

        # Da campaign_origin
        campaign_data = read_json(os.path.join(case_dir, "campaign_origin.json")) or {}
        if campaign_data.get("domain"):
            all_domains.append(campaign_data["domain"])

        # Da domains.json
        domains_data = read_json(os.path.join(case_dir, "domains.json")) or {}
        from_domain = domains_data.get("from_domain", {}).get("domain")
        if from_domain:
            all_domains.append(from_domain)

        # Da detonation_endpoints
        det_endpoints = read_json(os.path.join(case_dir, "detonation_endpoints.json")) or []
        for ep in det_endpoints:
            host = ep.get("host")
            if host:
                all_domains.append(host)
            ips = ep.get("ips", [])
            all_ips.extend(ips)

        # Da c2_infrastructure
        c2_infra = read_json(os.path.join(case_dir, "c2_infrastructure.json")) or []
        for infra in c2_infra:
            c2_ip = infra.get("ip")
            if c2_ip:
                all_ips.append(c2_ip)

        # Rimuovi duplicati
        all_domains = list(set(all_domains))
        all_ips = list(set(all_ips))

        # Correlazione threat intelligence
        threat_correlations = {}
        if all_domains or all_ips:
            for domain in all_domains:
                if domain:
                    try:
                        domain_intel = ti.enrich_indicators(domain, [])
                        threat_correlations[f"domain_{domain}"] = domain_intel
                        print(f"[threat_intel] correlated intelligence for domain: {domain}")
                    except Exception as e:
                        print(f"[threat_intel] failed to correlate domain {domain}: {e}")

            # Correlazione per IP (raggruppa per evitare troppe chiamate API)
            if all_ips:
                try:
                    ip_intel = ti.enrich_indicators("", all_ips)
                    threat_correlations["ip_intelligence"] = ip_intel
                    print(f"[threat_intel] correlated intelligence for {len(all_ips)} IPs")
                except Exception as e:
                    print(f"[threat_intel] failed to correlate IPs: {e}")

        if threat_correlations:
            write_json(os.path.join(case_dir, "threat_intelligence.json"), threat_correlations)
            print(f"[threat_intel] completed correlation with {len(threat_correlations)} intelligence sources")

            # Integra nell'attribution matrix
            matrix_file = os.path.join(case_dir, "attribution_matrix.json")
            if os.path.exists(matrix_file):
                matrix_data = read_json(matrix_file) or {}
                matrix_data["threat_intelligence"] = threat_correlations
                write_json(matrix_file, matrix_data)
                print("[threat_intel] integrated into attribution matrix")

    except Exception as e:
        print(f"[threat_intel] failed: {e}")
    
    # 🚀 NUOVO: Crea Attribution Matrix Unificata
    print("[attribution_matrix] creating unified attribution matrix...")
    try:
        attribution_matrix = {
            "case_id": os.path.basename(case_dir),
            "timestamp": utc_now_iso(),
            "intelligence_modules": {
                "criminal_hunter": read_json(os.path.join(case_dir, "criminal_intelligence.json")) or {},
                "infrastructure_mapper": read_json(os.path.join(case_dir, "infrastructure_mapping.json")) or {},
                "enrich_last_hunt": read_json(os.path.join(case_dir, "hunt_enrichments.json")) or {},
                "threat_intelligence": read_json(os.path.join(case_dir, "threat_intelligence.json")) or {},
                "c2_infrastructure": read_json(os.path.join(case_dir, "c2_infrastructure.json")) or {},
                "phishing_kit_analysis": read_json(os.path.join(case_dir, "phishing_kit_analysis.json")) or {}
            },
            "campaign_analysis": {
                "campaign_origin": read_json(os.path.join(case_dir, "campaign_origin.json")) or {},
                "detonation_endpoints": read_json(os.path.join(case_dir, "detonation_endpoints.json")) or [],
                "domains": read_json(os.path.join(case_dir, "domains.json")) or {},
                "transmitting_server": read_json(os.path.join(case_dir, "transmitting_server.json")) or {}
            },
            "operator_hypothesis": {
                "confidence": 0.0,
                "hypothesis": "Analysis in progress",
                "evidence_count": 0
            }
        }
        
        write_json(os.path.join(case_dir, "attribution_matrix.json"), attribution_matrix)
        print("[attribution_matrix] unified matrix created successfully")
        
    except Exception as e:
        print(f"[attribution_matrix] failed to create: {e}")
    
    # Header forgery analysis
    from .header_forgery import analyze_received_anomalies
    anomalies = analyze_received_anomalies(hops)
    write_json(os.path.join(case_dir,"received_anomalies.json"), anomalies)
    # Score
    suspicious_asn = False  # could be enhanced with local list
    ns_mx_recurrent = False # could be enhanced with local list
    hop_diag = {"skew_s": origin.get("skew_s",0), "helo_ptr_match": origin.get("helo_ptr_match", True), "fqdn_ok": origin.get("fqdn_ok", True)}
    # Load detonation/canary data for scoring bonuses
    detonation_endpoints = []
    canary_ips = []
    det_summary = {}
    
    det_endpoints_path = os.path.join(case_dir,"detonation_endpoints.json")
    if os.path.exists(det_endpoints_path):
        detonation_endpoints = read_json(det_endpoints_path) or []
    
    canary_ips_path = os.path.join(case_dir,"canary_ips.json")
    if os.path.exists(canary_ips_path):
        canary_ips = read_json(canary_ips_path) or []
    
    det_summary_path = os.path.join(case_dir,"detonation","summary.json")
    if os.path.exists(det_summary_path):
        det_summary = read_json(det_summary_path) or {}
    score = score_case(hop_diag, auth, {"domain":from_domain, "nrd_days": dominfo["from_domain"].get("nrd_days")}, brand_seeds=None, suspicious_asn=suspicious_asn, ns_mx_recurrent=ns_mx_recurrent, profile=profile, headers=headers, detonation_endpoints=detonation_endpoints, canary_ips=canary_ips, det_summary=det_summary, origin_domain=from_domain, deobfuscation_weight=deob_weight)
    # Integrate forgery anomalies into scoring
    if anomalies.get("non_monotonic_dates"):
        score["score"] = round(score["score"] + 0.1, 2)
    if anomalies.get("private_ip_before_boundary"):
        score["score"] = round(score["score"] + 0.1, 2)
    if anomalies.get("invalid_fqdn_count", 0) >= 1:
        score["score"] = round(score["score"] + 0.05, 2)
    write_json(os.path.join(case_dir,"report/score.json"), score)
    # Index case in database
    try:
        from .index import upsert_case
        upsert_case(case_dir, origin_out, headers, dominfo["from_domain"], score)
        
        # Check for campaign patterns (boost score if similar cases exist)
        from .index import query_recent
        campaign_boost = 0.0
        origin_ip = origin_out.get("ip", "")
        if origin_ip:
            recent_ip_cases = query_recent("ip", origin_ip, 30)
            if len(recent_ip_cases) >= 2:
                campaign_boost = 0.20
                print(f"[campaign] IP {origin_ip} has {len(recent_ip_cases)} recent cases, boosting score by +0.20")
        
        if campaign_boost > 0:
            score["score"] = round(score["score"] + campaign_boost, 2)
            score["decision"] = "Campaign pattern detected - " + score["decision"]
            # Re-save updated score
            write_json(os.path.join(case_dir,"report/score.json"), score)
            
    except Exception as e:
        print(f"[index] failed to index case: {e}")
    # Graphs
    graphs_dir = os.path.join(case_dir,"graphs")
    ensure_dir(graphs_dir)
    # Find origin hop index (1-based)
    origin_idx = 1
    for i, h in enumerate(hops, start=1):
        if h.get("ip") == origin.get("ip"):
            origin_idx = i
            break
    mmd1 = attribution_graph(hops, origin_idx, dominfo.get("from_domain"))
    write_text(os.path.join(graphs_dir,"attribution.mmd"), mmd1)
    mmd2 = domain_graph(dominfo.get("from_domain"))
    write_text(os.path.join(graphs_dir,"domain.mmd"), mmd2)
    # Reports (simple)
    rep_dir = os.path.join(case_dir,"report")
    ensure_dir(rep_dir)
    exec_md = f"> TRANSMITTING SERVER: **{ip}** — AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\\n> *Note: This IP may belong to a compromised server or cloud service used by the attacker*\\n> Recipient MX chain hops marked as [MX-internal].\\n\\n# Attribution Summary\\n\\n**Transmitting Server**: {ip} / AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\\n\\n**From Domain**: {from_domain}\\nRegistrar: {dominfo['from_domain'].get('registrar')}\\nCreated: {dominfo['from_domain'].get('created')} (NRD: {dominfo['from_domain'].get('nrd_days')}d)\\nNS: {', '.join(dominfo['from_domain'].get('ns',[]))}\\nMX: {', '.join(dominfo['from_domain'].get('mx',[]))}\\n\\n**Auth**: SPF={auth['spf']['result']} | DKIM present={auth['dkim']['present']} aligned={auth['dkim']['aligned']} d={','.join(auth['dkim']['d_list'])} | DMARC={auth['dmarc']['inferred_result']}\\n\\n**Decision**: {score['decision']} (score={score['score']})\\n"
    # Add detonation/canary sections if they exist
    det = {}
    can_ips = []
    
    det_summary_path = os.path.join(case_dir,"detonation","summary.json")
    if os.path.exists(det_summary_path):
        det = read_json(det_summary_path) or {}
    
    canary_ips_path = os.path.join(case_dir,"canary_ips.json")
    if os.path.exists(canary_ips_path):
        can_ips = read_json(canary_ips_path) or []
    
    canary_visitors_path = os.path.join(case_dir,"canary_visitors.json")
    canary_visitors = read_json(canary_visitors_path) if os.path.exists(canary_visitors_path) else []
    
    exec_md += "\\n" + detonation_box(det) + "\\n\\n" + canary_box(can_ips, canary_visitors)
    write_text(os.path.join(rep_dir,"executive.md"), exec_md)
    tech_md = "# Technical Details\\n\\n## Received Path\\n"
    for i,h in enumerate(hops, start=1):
        tech_md += f"- Hop {i}: by={h.get('by')} from={h.get('from')} ip={h.get('ip')} date={h.get('date')} helo={h.get('helo')} ptr={h.get('ptr')} skew_s={h.get('skew_s')} fqdn_ok={h.get('fqdn_ok')} helo_ptr_match={h.get('helo_ptr_match')} role={h.get('role')}\\n"
    tech_md += "\\n## Auth Alignment\\n"
    tech_md += json.dumps(auth, indent=2) + "\\n"
    tech_md += "\\n## Forgery Checks\\n"
    tech_md += json.dumps(anomalies, indent=2) + "\n"
    # Include deobfuscation analysis details (if available)
    try:
        tech_md += "\n## Deobfuscation Configuration\n"
        tech_md += f"- deobfuscation_weight: {float(deob_weight)}\n\n"
        tech_md += "## Deobfuscation Analysis\n"
        tech_md += json.dumps(headers.get("deobfuscation_analysis", {}), indent=2) + "\n"
    except Exception:
        tech_md += "\n## Deobfuscation Analysis\nCould not include deobfuscation details.\n"
    # Add Rekor section if anchored
    rekor_anchor_path = os.path.join(case_dir, "evidence", "rekor_anchor.json")
    rekor_proof_path = os.path.join(case_dir, "evidence", "rekor_proof.json")
    if os.path.exists(rekor_anchor_path):
        tech_md += "\\n## Rekor\\n"
        with open(rekor_anchor_path, "r", encoding="utf-8") as f:
            anchor_data = json.load(f)
        tech_md += f"Entry UUID: {anchor_data.get('entry_uuid')}\\n"
        tech_md += f"Log Index: {anchor_data.get('logIndex')}\\n"
        tech_md += f"Integrated Time: {anchor_data.get('integratedTime')}\\n"
        if os.path.exists(rekor_proof_path):
            with open(rekor_proof_path, "r", encoding="utf-8") as f:
                proof_data = json.load(f)
            tech_md += f"Inclusion verified: {proof_data.get('treeSize') is not None}\\n"
        tech_md += "\\n"
    # Add attachments section
    if atts:
        tech_md += "\\n## Attachments (metadata-only)\\n"
        tech_md += "| Filename | Size | MIME | Macro | SHA256 |\\n"
        tech_md += "|----------|------|------|-------|--------|\\n"
        for att in atts:
            tech_md += f"| {att['filename']} | {att['size']} | {att['mime']} | {'Yes' if att['ole_macro'] else 'No'} | {att['sha256'][:16]}... |\\n"
        tech_md += "\\n"
    write_text(os.path.join(rep_dir,"technical.md"), tech_md)
    # STIX
    if stix:
        stix_bundle = make_stix(case_id, ip, from_domain, ip_res.get("asn_org",""))
        write_json(os.path.join(rep_dir,"stix.json"), stix_bundle)
    # Evidence index + root
    ev_dir = os.path.join(case_dir,"evidence"); ensure_dir(ev_dir)
    # Index files to include
    index_files = {
        "input.eml": None,
        "manifest.json": None,
        "headers.json": None,
        "deobfuscation_results.json": None,
        "received_path.json": None,
        "auth.json": None,
        "transmitting_server.json": None,
        "domains.json": None,
        "graphs/attribution.mmd": None,
        "graphs/domain.mmd": None,
        "report/executive.md": None,
        "report/technical.md": None
    }
    if stix: index_files["report/stix.json"] = None
    if atts: index_files["attachments.json"] = None  # Include attachments if present
    for rel in list(index_files.keys()):
        index_files[rel] = file_blake3_hex(os.path.join(case_dir, rel))
    write_json(os.path.join(ev_dir,"merkle_index.json"), index_files)
    # Simple root: blake3 of concatenated hashes (deterministic order)
    concat = "".join(v for k,v in sorted(index_files.items()))
    import blake3 as _b3
    root = _b3.blake3(concat.encode()).hexdigest()
    write_text(os.path.join(ev_dir,"merkle_root.bin"), root)
    # Abuse package
    if abuse:
        out = generate_abuse_package(case_dir, "it" if lang.startswith("it") else "en")
        # Generate ARF (RFC 5965) and X-ARF packages
        generate_arf_package(case_dir)
        generate_xarf_package(case_dir)
        # create subject file as helper
        subj = f"[Abuse][Phishing] Case {case_id} – Origin {ip}/AS{ip_res.get('asn')} – Domain {from_domain}"
        write_text(os.path.join(case_dir, "package", "subject.txt"), subj)
    # Rekor anchor (optional)
    if anchor:
        REKOR_URL = os.environ.get('PAW_REKOR_URL', 'https://rekor.sigstore.dev')
        PRIV = os.environ.get('PAW_REKOR_PRIVKEY_PEM')
        PUB = os.environ.get('PAW_REKOR_PUBKEY_PEM')
        if PRIV and PUB:
            try:
                from .rekor import fetch_inclusion_proof
                outp = anchor_case(case_dir, REKOR_URL, PRIV, PUB)
                print(f"[rekor] anchored: {outp}")
                # Fetch inclusion proof
                with open(outp, "r", encoding="utf-8") as f:
                    anchor_data = json.load(f)
                entry_uuid = anchor_data.get("entry_uuid")
                if entry_uuid:
                    proof = fetch_inclusion_proof(REKOR_URL, entry_uuid)
                    proof_path = os.path.join(case_dir, "evidence", "rekor_proof.json")
                    with open(proof_path, "w", encoding="utf-8") as f:
                        json.dump(proof, f, indent=2)
                    print(f"[rekor] proof fetched: {proof_path}")
            except Exception as e:
                print(f"[rekor] anchor failed: {e}")
        else:
            print('[rekor] skipping: set PAW_REKOR_PRIVKEY_PEM and PAW_REKOR_PUBKEY_PEM to use --anchor')
    
    # Re-check for detonation/canary data and regenerate report if needed
    det_summary_path = os.path.join(case_dir,"detonation","summary.json")
    canary_hits_path = os.path.join(case_dir, "canary", "hits.jsonl")
    if os.path.exists(det_summary_path) or os.path.exists(canary_ips_path) or os.path.exists(canary_hits_path):
        det = read_json(det_summary_path) if os.path.exists(det_summary_path) else {}
        can_ips = read_json(canary_ips_path) if os.path.exists(canary_ips_path) else []
        exec_md = f"> TRANSMITTING SERVER: **{ip}** — AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\\n> *Note: This IP may belong to a compromised server or cloud service used by the attacker*\\n> Recipient MX chain hops marked as [MX-internal].\\n\\n# Attribution Summary\\n\\n**Transmitting Server**: {ip} / AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\\n\\n**From Domain**: {from_domain}\\nRegistrar: {dominfo['from_domain'].get('registrar')}\\nCreated: {dominfo['from_domain'].get('created')} (NRD: {dominfo['from_domain'].get('nrd_days')}d)\\nNS: {', '.join(dominfo['from_domain'].get('ns',[]))}\\nMX: {', '.join(dominfo['from_domain'].get('mx',[]))}\\n\\n**Auth**: SPF={auth['spf']['result']} | DKIM present={auth['dkim']['present']} aligned={auth['dkim']['aligned']} d={','.join(auth['dkim']['d_list'])} | DMARC={auth['dmarc']['inferred_result']}\\n\\n**Decision**: {score['decision']} (score={score['score']})\\n"
        exec_md += "\\n" + detonation_box(det) + "\\n\\n" + canary_box(can_ips)
        write_text(os.path.join(rep_dir,"executive.md"), exec_md)
        print("[trace] report updated with detonation/canary data")

    # Correlazione campagne basata su pattern comuni
    try:
        cases_dir = os.path.dirname(case_dir)
        correlations = correlate_campaigns(cases_dir)
        if correlations.get("campaign_clusters") or correlations.get("attacker_groups"):
            write_json(os.path.join(case_dir, "campaign_correlations.json"), correlations)
            print(f"[correlation] analyzed {len(correlations.get('campaign_clusters', []))} campaign clusters")
    except Exception as e:
        print(f"[correlation] failed: {e}")

    # ===============================
    # REPORT FINALE COMPLETO
    # ===============================
    print("\n" + "="*80)
    print("📋 ANALISI COMPLETA - Phishing Attribution Workbench")
    print("="*80)
    print(f"🆔 Case ID: {case_id}")
    print(f"📅 Data analisi: {utc_now_iso()[:19].replace('T', ' ')}")
    print(f"📧 File analizzato: {os.path.basename(eml_path)}")
    print()

    # Server di trasmissione
    print("🌐 SERVER DI TRASMISSIONE (SMTP Relay)")
    print("-" * 40)
    if ip:
        print(f"📍 IP: {ip}")
        print(f"🏢 ASN: AS{ip_res.get('asn', 'N/A')} {ip_res.get('asn_org', 'N/A')}")
        print(f"🌍 Paese: {ip_res.get('cc', 'N/A')} (ASN: {ip_res.get('asn_cc', 'N/A')})")
        print(f"📧 Abuse: {', '.join([c.get('value', '') for c in ip_res.get('abuse', []) if c.get('type') == 'email'])}")
        print(f"⚖️  Reputazione: {origin_out.get('reputation', {}).get('category', 'unknown')} (score: {origin_out.get('reputation', {}).get('score', 0)})")
    else:
        print("❌ IP non identificato")
    print()

    # Infrastruttura attaccante
    print("🎯 INFRASTRUTTURA ATTACCANTE IDENTIFICATA")
    print("-" * 40)

    # Carica dati dalla detonazione
    c2_infra_path = os.path.join(case_dir, "c2_infrastructure.json")
    if os.path.exists(c2_infra_path):
        c2_infra = read_json(c2_infra_path) or []
        if c2_infra:
            print("🔴 IP ATTACCANTI RILEVATI:")
            for i, infra in enumerate(c2_infra[:5], 1):  # Mostra max 5
                ip_addr = infra.get('ip', 'N/A')
                country = infra.get('country', 'N/A')
                asn = infra.get('asn', 'N/A')
                org = infra.get('org', 'N/A')
                if org and isinstance(org, str):
                    org = org.replace('AS', '').strip()
                else:
                    org = 'N/A'
                domain = infra.get('host', 'N/A')
                rep = infra.get('reputation', {}).get('category', 'unknown')

                flag = "🇱🇻" if country == "LV" else "🇹🇷" if country == "TR" else "🇺🇸" if country == "US" else "🌍"
                risk = "🔴 HIGH" if country in ["LV", "RU", "CN"] else "🟡 MEDIUM" if country in ["TR", "IN", "BR"] else "🟢 LOW"

                print(f"  {i}. {flag} {ip_addr} ({country}) - {risk}")
                print(f"     Dominio: {domain}")
                print(f"     ASN: AS{asn} {org}")
                print(f"     Reputazione: {rep}")
                print()
        else:
            print("✅ Nessun IP attaccante rilevato nella detonazione")
    else:
        print("ℹ️  Detonazione non completata - eseguire detonazione per identificare IP attaccanti")

    # Punteggio e decisione
    print("⚖️  VALUTAZIONE RISCHIO")
    print("-" * 40)
    print(f"📊 Punteggio: {score.get('score', 0):.2f}/1.00")
    print(f"🎯 Decisione: {score.get('decision', 'N/A')}")
    print(f"📈 Categoria: {score.get('category', 'N/A')}")
    print()

    # Raccomandazioni
    print("🎯 RACCOMANDAZIONI AZIONE")
    print("-" * 40)

    # Raccomandazioni per IP attaccanti
    if os.path.exists(c2_infra_path):
        c2_infra = read_json(c2_infra_path) or []
        if c2_infra:
            print("🔴 Takedown prioritari:")
            for infra in c2_infra[:3]:  # Top 3
                ip_addr = infra.get('ip', '')
                country = infra.get('country', '')
                abuse_contacts = infra.get('abuse_contacts', [])
                if abuse_contacts:
                    abuse_emails = [c.get('value', '') for c in abuse_contacts if c.get('type') == 'email']
                    if abuse_emails:
                        print(f"  • {ip_addr} ({country}): {', '.join(abuse_emails[:2])}")

    # Raccomandazioni generali
    print("\n📋 Azioni consigliate:")
    print("  • Segnalare a provider di abuso locali")
    print("  • Implementare regole di blocco IP")
    print("  • Monitorare domini simili")
    print("  • Verificare autenticazione email (SPF/DKIM/DMARC)")

    print("\n" + "="*80)
    print(f"💾 Report salvato in: {case_dir}")
    print("📄 File principali: report/executive.md, report/technical.md")
    print("="*80)

    print(f"[trace] case created: {case_dir}")

    # Print beautiful summary
    print_beautiful_summary(case_dir, case_id, score, ip, ip_res, from_domain, dominfo, auth, lang)

def print_beautiful_summary(case_dir: str, case_id: str, score: dict, ip: str, ip_res: dict, 
                          from_domain: str, dominfo: dict, auth: dict, lang: str = "en"):
    """Print a beautiful terminal summary using rich library."""
    console = Console()
    
    # Get key findings from analysis
    findings = []
    
    # Check for criminal infrastructure
    criminal_intel = read_json(os.path.join(case_dir, "criminal_intelligence.json")) or {}
    if criminal_intel:
        findings.append("🔴 Criminal infrastructure detected")
    
    # Check attribution matrix for high confidence
    attr_matrix = read_json(os.path.join(case_dir, "attribution_matrix.json")) or {}
    operator_hypothesis = attr_matrix.get("operator_hypothesis", {})
    confidence = operator_hypothesis.get("confidence", 0)
    
    # Check anomalies
    anomalies = read_json(os.path.join(case_dir, "received_anomalies.json")) or {}
    if anomalies.get("suspicious_relay_chain"):
        findings.append("🟡 Suspicious relay chain detected")
    
    # Check auth failures
    if auth.get("dmarc", {}).get("inferred_result") == "none":
        findings.append("🟡 DMARC policy: none")
    
    # Determine verdict emoji and color
    score_val = score.get("score", 0)
    if score_val >= 0.8:
        verdict = f"🚨 LIKELY MALICIOUS (Score: {score_val})"
        verdict_color = "red"
    elif score_val >= 0.6:
        verdict = f"⚠️  SUSPICIOUS (Score: {score_val})"
        verdict_color = "yellow"
    else:
        verdict = f"✅ LOW RISK (Score: {score_val})"
        verdict_color = "green"
    
    # Get country flag
    cc = ip_res.get("cc", "")
    flag = {"US": "🇺🇸", "DE": "🇩🇪", "RU": "🇷🇺", "CN": "🇨🇳", "IT": "🇮🇹"}.get(cc, "🌍")
    
    # Create the beautiful output
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]PAW Analysis Complete[/bold cyan]",
        title="🐾 PAW - Phishing Attribution Workbench",
        border_style="cyan",
        box=box.DOUBLE
    ))
    
    # Case info table
    table = Table(box=box.SIMPLE)
    table.add_column("Property", style="dim", width=12)
    table.add_column("Value", style="bold")
    
    table.add_row("Case ID", f"[cyan]{case_id}[/cyan]")
    table.add_row("Verdict", f"[{verdict_color}]{verdict}[/{verdict_color}]")
    
    console.print(table)
    
    # Origin section
    origin_panel = Panel(
        f"IP:  [bold]{ip}[/bold]\n"
        f"ASN: AS{ip_res.get('asn', 'N/A')} ({ip_res.get('asn_org', 'N/A')})\n"
        f"CC:  {flag} {cc}",
        title="📍 Origin",
        border_style="blue"
    )
    console.print(origin_panel)
    
    # Key findings
    if findings:
        findings_text = "\n".join(findings[:4])  # Max 4 findings
        findings_panel = Panel(
            findings_text,
            title="🔍 Key Findings",
            border_style="yellow"
        )
        console.print(findings_panel)
    
    # Operator hypothesis (if high confidence)
    if confidence >= 0.7:
        hypothesis = operator_hypothesis.get("hypothesis", "Analysis in progress")
        hyp_panel = Panel(
            f"{hypothesis}\n\n[bold]Confidence: {int(confidence * 100)}%[/bold]",
            title="🎯 Operator Hypothesis",
            border_style="magenta"
        )
        console.print(hyp_panel)
    
    # Next steps
    next_steps = [
        f"1. Review full report: [link=file://{case_dir}/report/executive.md]cases/.../report/executive.md[/link]",
        f"2. Submit abuse: [link=file://{case_dir}/evidence/abuse_package/]cases/.../evidence/abuse_package/[/link]",
        f"3. Export STIX: [bold cyan]paw export --case {case_id} --format stix[/bold cyan]"
    ]
    
    steps_panel = Panel(
        "\n".join(next_steps),
        title="🚀 Next Steps",
        border_style="green"
    )
    console.print(steps_panel)
    
    console.print()

def update_report(case_dir):
    """Update report with detonation/canary data if available"""
    rep_dir = os.path.join(case_dir, "report")
    if not os.path.exists(rep_dir):
        return
    
    # Load existing data
    score_path = os.path.join(rep_dir, "score.json")
    if not os.path.exists(score_path):
        return
    score = read_json(score_path)
    
    headers_path = os.path.join(case_dir, "headers.json")
    if not os.path.exists(headers_path):
        return
    headers = read_json(headers_path)
    
    origin_path = os.path.join(case_dir, "transmitting_server.json")
    if not os.path.exists(origin_path):
        return
    origin_out = read_json(origin_path)
    
    ip = origin_out.get("ip", "")
    ip_res = origin_out.get("rdap", {})
    
    # Extract from_domain from headers["from"]
    import re
    m = re.search(r'@([^\s>]+)', headers.get("from", ""))
    from_domain = (m.group(1).strip().lower() if m else "")
    
    # Load detonation/canary data
    det_summary_path = os.path.join(case_dir, "detonation", "summary.json")
    det = read_json(det_summary_path) if os.path.exists(det_summary_path) else {}
    
    # Merge canary hits → attacker_visit
    hits = os.path.join(case_dir, "canary", "hits.jsonl")
    canary_ips = []
    canary_visitors = []
    if os.path.exists(hits):
        ips = set()
        with open(hits, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    visitor_ip = j.get("ip")
                    if visitor_ip:
                        ips.add(visitor_ip)
                        canary_visitors.append({
                            "ip": visitor_ip,
                            "timestamp": j.get("ts"),
                            "user_agent": j.get("ua"),
                            "url": j.get("url"),
                            "reputation": check_ip_reputation(visitor_ip)
                        })
                except Exception:
                    pass
        canary_ips = sorted([cip for cip in ips if cip])
        write_json(os.path.join(case_dir, "canary_ips.json"), canary_ips)
        write_json(os.path.join(case_dir, "canary_visitors.json"), canary_visitors)
    
    canary_ips_path = os.path.join(case_dir, "canary_ips.json")
    can_ips = read_json(canary_ips_path) if os.path.exists(canary_ips_path) else []
    
    canary_visitors_path = os.path.join(case_dir, "canary_visitors.json")
    canary_visitors = read_json(canary_visitors_path) if os.path.exists(canary_visitors_path) else []
    
    # Regenerate executive report
    exec_md = f"> TRANSMITTING SERVER: **{ip}** — AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\\n> *Note: This IP may belong to a compromised server or cloud service used by the attacker*\\n> Recipient MX chain hops marked as [MX-internal].\\n\\n# Attribution Summary\\n\\n**Transmitting Server**: {ip} / AS{ip_res.get('asn')} {ip_res.get('asn_org')} ({ip_res.get('cc')})\\n\\n**From Domain**: {from_domain}\\n\\n**Decision**: {score['decision']} (score={score['score']})\\n"
    exec_md += "\\n" + detonation_box(det) + "\\n\\n" + canary_box(can_ips, canary_visitors)
    write_text(os.path.join(rep_dir, "executive.md"), exec_md)
    print(f"[update] report updated for case: {case_dir}")


def analyze_compromised_infrastructure(domain: str, ip: str) -> dict:
    """
    Analizza ricorsivamente l'infrastruttura compromessa per trovare collegamenti upstream.
    Questo va oltre il semplice server compromesso per identificare l'intera catena.
    """
    analysis = {
        "infrastructure_chain": [],
        "upstream_connections": [],
        "threat_intelligence": [],
        "risk_assessment": "unknown"
    }

    try:
        # 1. Analisi DNS per sottodomini correlati
        dns_analysis = analyze_dns_infrastructure(domain)
        if dns_analysis:
            analysis["infrastructure_chain"].extend(dns_analysis)

        # 2. Analisi certificati SSL associati
        ssl_analysis = analyze_ssl_certificates(domain, ip)
        if ssl_analysis:
            analysis["infrastructure_chain"].extend(ssl_analysis)

        # 3. Analisi contenuto web per collegamenti nascosti
        web_analysis = analyze_web_content(domain)
        if web_analysis:
            analysis["upstream_connections"].extend(web_analysis)

        # 4. Correlazione con threat intelligence
        ti_analysis = correlate_threat_intelligence(domain, ip)
        if ti_analysis:
            analysis["threat_intelligence"].extend(ti_analysis)

        # 5. Valutazione rischio complessiva
        analysis["risk_assessment"] = assess_infrastructure_risk(analysis)

    except Exception as e:
        analysis["error"] = str(e)

    return analysis if analysis["infrastructure_chain"] or analysis["upstream_connections"] else None


def analyze_dns_infrastructure(domain: str) -> list:
    """Analizza i record DNS per trovare infrastruttura correlata."""
    findings = []

    try:
        import dns.resolver

        # Cerca sottodomini comuni usati negli attacchi
        subdomains = [
            "mail", "smtp", "webmail", "admin", "cpanel", "plesk", "whm",
            "api", "cdn", "static", "assets", "files", "upload", "download",
            "c2", "command", "control", "callback", "beacon", "exfil"
        ]

        for sub in subdomains:
            try:
                answers = dns.resolver.resolve(f"{sub}.{domain}", "A")
                for rdata in answers:
                    findings.append({
                        "type": "dns_subdomain",
                        "subdomain": f"{sub}.{domain}",
                        "ip": str(rdata),
                        "risk": "high" if sub in ["c2", "command", "control", "callback"] else "medium"
                    })
            except:
                pass

        # Cerca record TXT per configurazioni sospette
        try:
            txt_records = dns.resolver.resolve(domain, "TXT")
            for rdata in txt_records:
                txt_content = str(rdata)
                if any(keyword in txt_content.lower() for keyword in ["spf", "dkim", "dmarc"]):
                    findings.append({
                        "type": "dns_txt_config",
                        "content": txt_content,
                        "risk": "low"
                    })
        except:
            pass

    except ImportError:
        findings.append({
            "type": "dns_error",
            "message": "dnspython not available",
            "risk": "unknown"
        })

    return findings


def analyze_ssl_certificates(domain: str, ip: str) -> list:
    """Analizza certificati SSL per trovare domini correlati."""
    findings = []

    try:
        import ssl
        import socket

        # Connessione SSL per ottenere il certificato
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Estrai Subject Alternative Names (SAN)
                if cert.get("subjectAltName"):
                    for san_type, san_value in cert["subjectAltName"]:
                        if san_type == "DNS" and san_value != domain:
                            findings.append({
                                "type": "ssl_san",
                                "domain": san_value,
                                "risk": "medium"
                            })

                # Controlla issuer per pattern sospetti
                issuer = cert.get("issuer", [])
                issuer_str = str(issuer)
                if any(suspicious in issuer_str.lower() for suspicious in ["letsencrypt", "zerossl"]):
                    findings.append({
                        "type": "ssl_issuer_suspicious",
                        "issuer": issuer_str,
                        "risk": "low"
                    })

    except Exception as e:
        findings.append({
            "type": "ssl_error",
            "message": str(e),
            "risk": "unknown"
        })

    return findings


def analyze_web_content(domain: str) -> list:
    """Analizza il contenuto web per collegamenti upstream."""
    findings = []

    try:
        import requests
        try:
            from bs4 import BeautifulSoup, Comment
        except ImportError:
            findings.append({
                "type": "web_error",
                "message": "beautifulsoup4 not available",
                "risk": "unknown"
            })
            return findings

        import re

        # SSL verification from environment
        verify_ssl = os.getenv('PAW_VERIFY_SSL', 'true').lower() == 'true'

        # Scarica la pagina principale
        response = requests.get(f"https://{domain}", timeout=10, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Cerca collegamenti nascosti in JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Pattern per URL nascosti
                url_patterns = [
                    r'https?://[^\s\'"]+',
                    r'[\w\.-]+\.onion',  # Tor hidden services
                    r'[\w\.-]+\.i2p',   # I2P
                    r'ipfs://[^\s\'"]+', # IPFS
                ]

                for pattern in url_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        if domain not in match:  # Solo collegamenti esterni
                            findings.append({
                                "type": "web_hidden_link",
                                "url": match,
                                "context": "javascript",
                                "risk": "high"
                            })

        # Cerca commenti HTML con informazioni
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            if any(keyword in comment.lower() for keyword in ["c2", "command", "control", "admin"]):
                findings.append({
                    "type": "web_suspicious_comment",
                    "content": str(comment),
                    "risk": "medium"
                })

    except Exception as e:
        findings.append({
            "type": "web_error",
            "message": str(e),
            "risk": "unknown"
        })

    return findings


def correlate_threat_intelligence(domain: str, ip: str) -> list:
    """Correlazione con database di threat intelligence."""
    findings = []

    # Simulazione di controlli threat intelligence
    # In produzione, integrare con API come VirusTotal, AbuseIPDB, etc.

    # Controlli locali basati su pattern noti
    known_malicious_patterns = [
        "c2-server", "phishing-kit", "malware-host",
        "botnet", "ransomware", "exploit"
    ]

    # Controllo reverse DNS per pattern sospetti
    try:
        import socket
        reverse_dns = socket.gethostbyaddr(ip)[0]
        if any(pattern in reverse_dns.lower() for pattern in known_malicious_patterns):
            findings.append({
                "type": "ti_reverse_dns",
                "hostname": reverse_dns,
                "risk": "high"
            })
    except:
        pass

    # Pattern di dominio sospetti
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        findings.append({
            "type": "ti_suspicious_tld",
            "tld": domain.split(".")[-1],
            "risk": "medium"
        })

    return findings


def assess_infrastructure_risk(analysis: dict) -> str:
    """Valuta il rischio complessivo dell'infrastruttura."""
    high_risk_count = sum(1 for item in analysis.get("infrastructure_chain", [])
                         if item.get("risk") == "high")
    high_risk_ti = sum(1 for item in analysis.get("threat_intelligence", [])
                      if item.get("risk") == "high")
    upstream_count = len(analysis.get("upstream_connections", []))

    if high_risk_count >= 2 or high_risk_ti >= 1 or upstream_count >= 3:
        return "critical"
    elif high_risk_count >= 1 or upstream_count >= 1:
        return "high"
    elif len(analysis.get("infrastructure_chain", [])) > 0:
        return "medium"
    else:
        return "low"


def analyze_phishing_kit_content(kit_content: dict) -> dict:
    """
    Analizza il contenuto di un phishing kit per identificare collegamenti C2 upstream.
    Questo va oltre l'analisi statica per trovare pattern dinamici nei toolkit.
    """
    analysis = {
        "c2_servers": [],
        "callback_domains": [],
        "exfiltration_endpoints": [],
        "obfuscated_code": [],
        "suspicious_patterns": [],
        "risk_level": "low"
    }

    try:
        # Analizza HTML content
        if "html" in kit_content:
            html_findings = analyze_html_for_c2(kit_content["html"])
            analysis["c2_servers"].extend(html_findings.get("c2_servers", []))
            analysis["callback_domains"].extend(html_findings.get("callback_domains", []))
            analysis["obfuscated_code"].extend(html_findings.get("obfuscated_code", []))

        # Analizza JavaScript content
        if "javascript" in kit_content:
            js_findings = analyze_javascript_for_c2(kit_content["javascript"])
            analysis["c2_servers"].extend(js_findings.get("c2_servers", []))
            analysis["exfiltration_endpoints"].extend(js_findings.get("exfiltration_endpoints", []))
            analysis["obfuscated_code"].extend(js_findings.get("obfuscated_code", []))

        # Analizza CSS content (può contenere URL nascosti)
        if "css" in kit_content:
            css_findings = analyze_css_for_c2(kit_content["css"])
            analysis["c2_servers"].extend(css_findings.get("c2_servers", []))

        # Pattern analysis complessiva
        all_patterns = analyze_kit_patterns(analysis)
        analysis["patterns"] = all_patterns

        # Valutazione rischio
        analysis["risk_level"] = assess_kit_risk(analysis)

    except Exception as e:
        analysis["error"] = str(e)

    return analysis


def analyze_html_for_c2(html_content: str) -> dict:
    """Analizza HTML per pattern C2."""
    findings = {"c2_servers": [], "callback_domains": [], "obfuscated_code": []}

    try:
        from bs4 import BeautifulSoup, Comment
        import re

        soup = BeautifulSoup(html_content, 'html.parser')

        # Cerca form action URLs
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action and 'http' in action:
                findings["c2_servers"].append({
                    "url": action,
                    "context": "form_action",
                    "risk": "high"
                })

        # Cerca iframe src
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src', '')
            if src and 'http' in src:
                findings["c2_servers"].append({
                    "url": src,
                    "context": "iframe_src",
                    "risk": "high"
                })

        # Cerca commenti con URL
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            urls = re.findall(r'https?://[^\s\'"]+', str(comment))
            for url in urls:
                findings["callback_domains"].append({
                    "url": url,
                    "context": "html_comment",
                    "risk": "medium"
                })

        # Cerca JavaScript inline con pattern sospetti
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                content = script.string
                # Pattern di offuscamento
                if re.search(r'atob\(|eval\(|unescape\(', content):
                    findings["obfuscated_code"].append({
                        "pattern": "javascript_obfuscation",
                        "context": "inline_script",
                        "risk": "high"
                    })

    except Exception as e:
        findings["error"] = str(e)

    return findings


def analyze_javascript_for_c2(js_content: str) -> dict:
    """Analizza JavaScript per pattern C2 e exfiltration."""
    findings = {"c2_servers": [], "exfiltration_endpoints": [], "obfuscated_code": []}

    try:
        import re

        # Pattern semplificato per trovare URL
        url_patterns = [
            r'https?://[^\s\'"]+',  # URL semplice
            r'[\'"](https?://[^\'"]+)[\'"]',  # URL in stringhe
        ]

        all_urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            all_urls.extend(matches)

        # Filtra URL comuni e classifica
        for url in all_urls:
            # Salta CDN e servizi legittimi
            if any(skip in url.lower() for skip in ['google', 'facebook', 'jquery', 'bootstrap', 'cdn']):
                continue

            # Classifica come C2 se contiene pattern sospetti
            if any(suspicious in url.lower() for suspicious in ['cmd', 'exec', 'shell', 'c2', 'control', 'callback']):
                findings["c2_servers"].append({
                    "url": url,
                    "context": "suspicious_url_pattern",
                    "risk": "high"
                })
            elif any(exfil in url.lower() for exfil in ['log', 'track', 'beacon', 'data', 'exfil']):
                findings["exfiltration_endpoints"].append({
                    "url": url,
                    "context": "data_exfiltration",
                    "risk": "high"
                })
            else:
                findings["c2_servers"].append({
                    "url": url,
                    "context": "hardcoded_url",
                    "risk": "medium"
                })

        # Pattern di offuscamento
        obfuscation_indicators = ['eval(', 'atob(', 'btoa(', 'unescape(', 'fromCharCode', '\\x', '\\u']
        for indicator in obfuscation_indicators:
            if indicator in js_content:
                findings["obfuscated_code"].append({
                    "pattern": indicator,
                    "context": "code_obfuscation",
                    "risk": "high"
                })

    except Exception as e:
        findings["error"] = str(e)

    return findings


def analyze_css_for_c2(css_content: str) -> dict:
    """Analizza CSS per URL nascosti."""
    findings = {"c2_servers": []}

    try:
        import re

        # Cerca url() in CSS
        url_pattern = r'url\([\'"]?(https?://[^\'")]+)[\'"]?\)'
        urls = re.findall(url_pattern, css_content, re.IGNORECASE)

        for url in urls:
            findings["c2_servers"].append({
                "url": url,
                "context": "css_url",
                "risk": "low"
            })

    except Exception as e:
        findings["error"] = str(e)

    return findings


def analyze_kit_patterns(kit_content: dict) -> list:
    """Analizza pattern complessivi nel kit."""
    patterns = []

    try:
        all_content = ""
        for content_type, content in kit_content.items():
            if isinstance(content, str):
                all_content += content + "\n"

        # Pattern di campagne note
        campaign_patterns = [
            ("emotet", r'emotet|epoch\d+', "high"),
            ("trickbot", r'trickbot|trickload', "high"),
            ("ryuk", r'ryuk|hermes', "high"),
            ("phishing_generic", r'password|login|verify|account', "medium"),
            ("malware_dropper", r'dropper|loader|shellcode', "high"),
        ]

        for name, pattern, risk in campaign_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                patterns.append({
                    "pattern": name,
                    "regex": pattern,
                    "risk": risk,
                    "context": "content_analysis"
                })

    except Exception as e:
        patterns.append({
            "pattern": "error",
            "error": str(e),
            "risk": "unknown"
        })

    return patterns


def assess_kit_risk(analysis: dict) -> str:
    """Valuta il rischio del phishing kit."""
    c2_count = len(analysis.get("c2_servers", []))
    exfil_count = len(analysis.get("exfiltration_endpoints", []))
    obfuscation_count = len(analysis.get("obfuscated_code", []))
    high_risk_patterns = sum(1 for p in analysis.get("suspicious_patterns", [])
                           if p.get("risk") == "high")

    if exfil_count >= 1 or high_risk_patterns >= 2 or obfuscation_count >= 3:
        return "critical"
    elif c2_count >= 3 or high_risk_patterns >= 1:
        return "high"
    elif c2_count >= 1 or obfuscation_count >= 1:
        return "medium"
    else:
        return "low"


def analyze_kit_patterns(kit_analysis: dict) -> dict:
    """Analizza pattern nel kit per identificare famiglie malware e campagne."""
    patterns = {
        "malware_family": "unknown",
        "campaign_indicators": [],
        "attacker_fingerprint": {},
        "similar_campaigns": []
    }

    try:
        # Pattern di famiglie malware note
        malware_signatures = {
            "phishing_kit_v1": ["login.php", "config.php", "index.html", "jquery.js"],
            "credential_harvester": ["steal.php", "mail.php", "smtp.php"],
            "banking_trojan": ["bank.php", "transfer.php", "balance.php"],
            "ransomware_locker": ["encrypt.php", "decrypt.php", "key.php"],
            "c2_beacon": ["beacon.js", "cmd.php", "shell.php"]
        }

        # Analizza file presenti
        files_found = []
        if "files" in kit_analysis:
            files_found = [f.get("filename", "") for f in kit_analysis["files"]]

        # Identifica famiglia malware
        for family, signatures in malware_signatures.items():
            matches = sum(1 for sig in signatures if any(sig in f for f in files_found))
            if matches >= len(signatures) * 0.6:  # 60% match
                patterns["malware_family"] = family
                break

        # Pattern di campagne
        campaign_patterns = {
            "business_email_compromise": ["invoice", "payment", "wire", "transfer"],
            "credential_theft": ["login", "password", "account", "verify"],
            "tech_support_scam": ["support", "microsoft", "apple", "tech"],
            "investment_scam": ["crypto", "bitcoin", "investment", "profit"]
        }

        # Analizza contenuto per pattern di campagna
        all_content = ""
        if "html_analysis" in kit_analysis:
            all_content += kit_analysis["html_analysis"].get("content", "")
        if "js_analysis" in kit_analysis:
            for finding in kit_analysis["js_analysis"].get("c2_servers", []):
                all_content += finding.get("url", "")

        for campaign, keywords in campaign_patterns.items():
            if any(kw in all_content.lower() for kw in keywords):
                patterns["campaign_indicators"].append(campaign)

        # Fingerprinting attaccante basato su pattern tecnici
        attacker_patterns = {
            "obfuscation_technique": "none",
            "c2_protocol": "http",
            "exfiltration_method": "post",
            "target_industry": "generic"
        }

        # Analizza tecniche di offuscamento
        if "js_analysis" in kit_analysis and kit_analysis["js_analysis"].get("obfuscated_code"):
            obfuscation = kit_analysis["js_analysis"]["obfuscated_code"]
            if any("eval" in str(o) for o in obfuscation):
                attacker_patterns["obfuscation_technique"] = "eval_injection"
            elif any("atob" in str(o) for o in obfuscation):
                attacker_patterns["obfuscation_technique"] = "base64_encoding"

        # Analizza protocollo C2
        if "js_analysis" in kit_analysis:
            c2_servers = kit_analysis["js_analysis"].get("c2_servers", [])
            if any("https" in str(s) for s in c2_servers):
                attacker_patterns["c2_protocol"] = "https"

        patterns["attacker_fingerprint"] = attacker_patterns

        # Campagne simili (basato su fingerprint)
        similar_campaigns = []
        if patterns["malware_family"] != "unknown":
            similar_campaigns.append(f"Campaign using {patterns['malware_family']} toolkit")

        if patterns["campaign_indicators"]:
            for campaign in patterns["campaign_indicators"]:
                similar_campaigns.append(f"Similar {campaign} campaigns")

        patterns["similar_campaigns"] = similar_campaigns

    except Exception as e:
        patterns["error"] = str(e)

    return patterns


def correlate_campaigns(cases_dir: str) -> dict:
    """Correlazione tra campagne basata su pattern comuni."""
    correlations = {
        "campaign_clusters": [],
        "attacker_groups": [],
        "infrastructure_links": []
    }

    try:
        import os
        import json

        # Carica tutti i casi
        cases = []
        if os.path.exists(cases_dir):
            for case_dir in os.listdir(cases_dir):
                case_path = os.path.join(cases_dir, case_dir, "evidence.json")
                if os.path.exists(case_path):
                    with open(case_path, 'r', encoding='utf-8') as f:
                        case_data = json.load(f)
                        cases.append(case_data)

        # Raggruppa per famiglie malware
        malware_families = {}
        for case in cases:
            family = case.get("kit_analysis", {}).get("patterns", {}).get("malware_family", "unknown")
            if family not in malware_families:
                malware_families[family] = []
            malware_families[family].append(case)

        # Identifica cluster di campagne
        for family, family_cases in malware_families.items():
            if len(family_cases) > 1:
                cluster = {
                    "family": family,
                    "case_count": len(family_cases),
                    "common_c2_domains": [],
                    "time_range": "unknown"
                }

                # Estrai domini C2 comuni
                all_c2_domains = []
                for case in family_cases:
                    kit_analysis = case.get("kit_analysis", {})
                    if "js_analysis" in kit_analysis:
                        for c2 in kit_analysis["js_analysis"].get("c2_servers", []):
                            url = c2.get("url", "")
                            if "://" in url:
                                domain = url.split("://")[1].split("/")[0]
                                all_c2_domains.append(domain)

                # Trova domini comuni
                from collections import Counter
                domain_counts = Counter(all_c2_domains)
                common_domains = [d for d, c in domain_counts.items() if c > 1]
                cluster["common_c2_domains"] = common_domains

                correlations["campaign_clusters"].append(cluster)

        # Identifica gruppi attaccanti basati su fingerprint
        attacker_groups = {}
        for case in cases:
            fingerprint = case.get("kit_analysis", {}).get("patterns", {}).get("attacker_fingerprint", {})
            fp_key = str(sorted(fingerprint.items()))

            if fp_key not in attacker_groups:
                attacker_groups[fp_key] = {
                    "fingerprint": fingerprint,
                    "cases": []
                }
            attacker_groups[fp_key]["cases"].append(case.get("case_id", "unknown"))

        correlations["attacker_groups"] = list(attacker_groups.values())

    except Exception as e:
        correlations["error"] = str(e)

    return correlations
