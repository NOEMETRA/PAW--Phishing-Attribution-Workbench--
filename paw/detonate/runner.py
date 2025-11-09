# paw/detonate/runner.py
import os, json, time, shutil, subprocess, socket, hashlib, requests, logging
from contextlib import contextmanager
from datetime import datetime
from urllib.parse import urlparse
from ..util.fsutil import ensure_dir, write_json, read_json
from playwright.sync_api import sync_playwright

# Import enrichment modules
from ..core.trackers import TrackerExtractor
from ..core.tls_fingerprinting import TLSFingerprintAnalyzer
from ..core.redirect_chain import RedirectChainAnalyzer
from ..core.dns_enrichment import DNSEnrichmentAnalyzer
from ..core.ja3_fingerprinting import JA3FingerprintAnalyzer
from ..core.form_analysis import FormAnalyzer
from ..core.attribution_matrix import AttributionMatrix

logger = logging.getLogger(__name__)

BLOCK_METHODS = {"POST","PUT","PATCH","DELETE"}

# SSL verification setting (configurable)
VERIFY_SSL = os.getenv('PAW_VERIFY_SSL', 'true').lower() == 'true'
if not VERIFY_SSL:
    logger.warning("SSL verification is DISABLED - only use for controlled analysis environments")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_phishing_kit(page, det_dir: str, url: str) -> dict:
    """Extract the complete phishing kit from the page."""
    import hashlib
    import requests
    
    kit_dir = os.path.join(det_dir, "phishing_kit")
    os.makedirs(kit_dir, exist_ok=True)
    
    kit_data = {
        "url": url,
        "html_hash": None,
        "resources": [],
        "static_analysis": {},
        "kit_hash": None
    }
    
    try:
        # Save main HTML
        html_content = page.content()
        html_path = os.path.join(kit_dir, "index.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        kit_data["html_hash"] = hashlib.sha256(html_content.encode('utf-8')).hexdigest()
        
        # Extract and download external resources
        resources = []
        
        # Get all script sources
        scripts = page.query_selector_all("script[src]")
        for script in scripts:
            src = script.get_attribute("src")
            if src and src.startswith(("http://", "https://")):
                try:
                    response = requests.get(src, timeout=10, verify=VERIFY_SSL)
                    if response.status_code == 200:
                        filename = os.path.basename(src.split("?")[0]) or f"script_{len(resources)}.js"
                        filepath = os.path.join(kit_dir, filename)
                        with open(filepath, "wb") as f:
                            f.write(response.content)
                        resources.append({
                            "type": "script",
                            "url": src,
                            "local_path": os.path.relpath(filepath, det_dir),
                            "hash": hashlib.sha256(response.content).hexdigest()
                        })
                except Exception as e:
                    resources.append({"type": "script", "url": src, "error": str(e)})
        
        # Get all stylesheet links
        stylesheets = page.query_selector_all("link[rel='stylesheet'][href]")
        for css in stylesheets:
            href = css.get_attribute("href")
            if href and href.startswith(("http://", "https://")):
                try:
                    response = requests.get(href, timeout=10, verify=VERIFY_SSL)
                    if response.status_code == 200:
                        filename = os.path.basename(href.split("?")[0]) or f"style_{len(resources)}.css"
                        filepath = os.path.join(kit_dir, filename)
                        with open(filepath, "wb") as f:
                            f.write(response.content)
                        resources.append({
                            "type": "stylesheet",
                            "url": href,
                            "local_path": os.path.relpath(filepath, det_dir),
                            "hash": hashlib.sha256(response.content).hexdigest()
                        })
                except Exception as e:
                    resources.append({"type": "stylesheet", "url": href, "error": str(e)})
        
        # Get all images
        images = page.query_selector_all("img[src]")
        for img in images:
            src = img.get_attribute("src")
            if src and src.startswith(("http://", "https://")):
                try:
                    response = requests.get(src, timeout=10, verify=VERIFY_SSL)
                    if response.status_code == 200:
                        filename = os.path.basename(src.split("?")[0]) or f"image_{len(resources)}.png"
                        filepath = os.path.join(kit_dir, filename)
                        with open(filepath, "wb") as f:
                            f.write(response.content)
                        resources.append({
                            "type": "image",
                            "url": src,
                            "local_path": os.path.relpath(filepath, det_dir),
                            "hash": hashlib.sha256(response.content).hexdigest()
                        })
                except Exception as e:
                    resources.append({"type": "image", "url": src, "error": str(e)})
        
        kit_data["resources"] = resources
        
        # Perform static analysis on the kit
        kit_data["static_analysis"] = analyze_kit_statically(html_content, resources)
        
        # Calculate overall kit hash (HTML + all resources)
        hasher = hashlib.sha256()
        hasher.update(html_content.encode('utf-8'))
        for res in resources:
            if "hash" in res:
                hasher.update(res["hash"].encode('utf-8'))
        kit_data["kit_hash"] = hasher.hexdigest()
        
    except Exception as e:
        kit_data["error"] = str(e)
    
    return kit_data

def generate_enrichment_files(page, det_dir: str, url: str, network_logs: list = None) -> dict:
    """Generate all enrichment files for attribution analysis"""
    enrichment_data = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'enrichment_files': {}
    }

    try:
        # Get HTML content
        html_content = page.content()

        # 1. Tracker Analysis
        tracker_extractor = TrackerExtractor()
        tracker_data = tracker_extractor.extract_from_html(html_content, url)
        tracker_file = os.path.join(det_dir, "enrichment_trackers.json")
        write_json(tracker_file, tracker_data)
        enrichment_data['enrichment_files']['trackers'] = 'enrichment_trackers.json'

        # 2. TLS Fingerprinting
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            tls_analyzer = TLSFingerprintAnalyzer()
            tls_data = tls_analyzer.analyze_certificate_chain(hostname)
            tls_file = os.path.join(det_dir, "enrichment_tls.json")
            write_json(tls_file, tls_data)
            enrichment_data['enrichment_files']['tls_fingerprints'] = 'enrichment_tls.json'

        # 3. Redirect Chain Analysis
        redirect_analyzer = RedirectChainAnalyzer()
        redirect_data = redirect_analyzer.analyze_redirect_chain(url)
        redirect_file = os.path.join(det_dir, "enrichment_redirects.json")
        write_json(redirect_file, redirect_data)
        enrichment_data['enrichment_files']['redirect_chains'] = 'enrichment_redirects.json'

        # 4. DNS Enrichment
        if hostname:
            dns_analyzer = DNSEnrichmentAnalyzer()
            dns_data = dns_analyzer.analyze_domain_dns(hostname)
            dns_file = os.path.join(det_dir, "enrichment_dns.json")
            write_json(dns_file, dns_data)
            enrichment_data['enrichment_files']['dns_enrichment'] = 'enrichment_dns.json'

        # 5. JA3 Fingerprinting
        if network_logs:
            ja3_analyzer = JA3FingerprintAnalyzer()
            ja3_data = ja3_analyzer.analyze_ja3_from_network_logs(network_logs)
            ja3_file = os.path.join(det_dir, "enrichment_ja3.json")
            write_json(ja3_file, ja3_data)
            enrichment_data['enrichment_files']['ja3_fingerprints'] = 'enrichment_ja3.json'

        # 6. Form Analysis
        form_analyzer = FormAnalyzer()
        form_data = form_analyzer.analyze_forms(html_content, url)
        form_file = os.path.join(det_dir, "enrichment_forms.json")
        write_json(form_file, form_data)
        enrichment_data['enrichment_files']['form_analysis'] = 'enrichment_forms.json'

        # 7. Attribution Matrix
        # Combine all enrichment data
        combined_enrichment = {
            'url': url,
            'trackers': tracker_data,
            'tls_fingerprints': tls_data if hostname else {},
            'dns_enrichment': dns_data if hostname else {},
            'redirect_chains': redirect_data,
            'ja3_fingerprints': ja3_data if network_logs else {},
            'form_analysis': form_data
        }

        attribution_matrix = AttributionMatrix()
        matrix_data = attribution_matrix.generate_attribution_matrix(combined_enrichment)
        matrix_file = os.path.join(det_dir, "attribution_matrix.json")
        write_json(matrix_file, matrix_data)
        enrichment_data['enrichment_files']['attribution_matrix'] = 'attribution_matrix.json'

        enrichment_data['status'] = 'completed'

    except Exception as e:
        enrichment_data['status'] = 'error'
        enrichment_data['error'] = str(e)
        print(f"[enrichment] Error generating enrichment files: {e}")

    return enrichment_data

def analyze_kit_statically(html_content: str, resources: list) -> dict:
    """Perform static analysis on the phishing kit to find fingerprints."""
    analysis = {
        "telegram_ids": [],
        "email_addresses": [],
        "code_comments": [],
        "suspicious_patterns": []
    }
    
    import re
    
    # Search for Telegram IDs in HTML and JS
    telegram_patterns = [
        r'@[\w\d_]{5,}',  # @username format
        r't\.me/[\w\d_]+',  # t.me links
        r'telegram\.me/[\w\d_]+',  # telegram.me links
        r'https?://t\.me/[\w\d_]+'  # full telegram links
    ]
    
    all_content = html_content
    for res in resources:
        if res.get("type") in ["script", "stylesheet"]:
            try:
                with open(os.path.join("cases", res["local_path"]), "r", encoding="utf-8", errors="ignore") as f:
                    all_content += f.read()
            except:
                pass
    
    for pattern in telegram_patterns:
        matches = re.findall(pattern, all_content, re.IGNORECASE)
        analysis["telegram_ids"].extend(matches)
    
    # Search for hardcoded email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, all_content)
    analysis["email_addresses"] = list(set(emails))  # deduplicate
    
    # Search for code comments (potential developer fingerprints)
    comment_patterns = [
        r'/\*.*?\*/',  # CSS/JS block comments
        r'//.*?$',     # JS line comments
        r'<!--.*?-->', # HTML comments
    ]
    
    for pattern in comment_patterns:
        comments = re.findall(pattern, all_content, re.MULTILINE | re.DOTALL)
        analysis["code_comments"].extend([c.strip() for c in comments if len(c.strip()) > 10])
    
    # Look for suspicious patterns
    suspicious = []
    if "password" in all_content.lower():
        suspicious.append("password_field_detected")
    if "login" in all_content.lower():
        suspicious.append("login_form_detected")
    if "submit" in all_content.lower() and "form" in all_content.lower():
        suspicious.append("form_submission_detected")
    if "ajax" in all_content.lower() or "fetch" in all_content.lower():
        suspicious.append("data_exfiltration_detected")
    
    analysis["suspicious_patterns"] = suspicious
    
    return analysis

@contextmanager
def maybe_pcap(out_pcap_path: str):
    """Try to start tcpdump if present. Yields, then stops."""
    proc = None
    try:
        if shutil.which("tcpdump"):
            proc = subprocess.Popen(["tcpdump","-w", out_pcap_path, "-U"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)  # warmup
    except Exception:
        proc = None
    try:
        yield
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=2)
            except Exception: pass

def _extract_urls_from_case(case_id: str):
    case_dir = os.path.join("cases", case_id)
    headers = read_json(os.path.join(case_dir,"headers.json")) or {}
    body_urls = (headers.get("urls") or [])  # se già parsate altrove
    subj = headers.get("subject") or ""
    # fallback: cerca URL minimi in raw headers
    import re
    raw = json.dumps(headers)
    found = re.findall(r"https?://[^\s\"\'<>]+", raw)
    urls = []
    seen=set()
    for u in (body_urls + found):
        if u not in seen:
            seen.add(u); urls.append(u)
    return case_dir, urls

def run_detonation(url: str|None, case_id: str|None, timeout: int=35, capture_pcap: bool=False, headless: bool=True, observe_only: bool=True):
    # Validate required parameters (don't use assert - can be disabled with -O)
    if not url and not case_id:
        raise ValueError("Either --url or --case is required (--url oppure --case richiesto)")
    if case_id:
        case_dir, urls = _extract_urls_from_case(case_id)
        if url: urls.insert(0, url)
    else:
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        case_dir = ensure_dir(f"cases/det-{stamp}")
        urls = [url]

    det_dir = os.path.join(case_dir, "detonation")
    os.makedirs(det_dir, exist_ok=True)
    out_req = os.path.join(det_dir, "requests.jsonl")
    out_log = os.path.join(det_dir, "netlog.json")
    out_pcap = os.path.join(det_dir, "capture.pcap")
    out_sum = os.path.join(det_dir, "summary.json")

    results = {"visited": [], "downloads": [], "errors": []}

    with maybe_pcap(out_pcap if capture_pcap else "/dev/null"):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless, args=[
                "--disable-sync","--disable-background-networking","--no-default-browser-check",
                "--disable-client-side-phishing-detection","--disable-popup-blocking"
            ])
            ctx = browser.new_context(accept_downloads=True, ignore_https_errors=True)
            page = ctx.new_page()

            # request interception: block write methods
            def _on_request(route, request):
                if observe_only and request.method.upper() in BLOCK_METHODS:
                    return route.abort()
                return route.continue_()
            ctx.route("**/*", _on_request)

            # log requests
            f_req = open(out_req, "w", encoding="utf-8")
            network_logs = []  # Collect network logs for enrichment

            def log_request(r):
                log_entry = {
                    "ts": time.time(),
                    "method": r.method,
                    "url": r.url,
                    "headers": dict(r.headers),
                    "type": "request"
                }
                network_logs.append(log_entry)
                f_req.write(json.dumps(log_entry) + "\n")

            def log_response(resp):
                log_entry = {
                    "ts": time.time(),
                    "status": resp.status,
                    "url": resp.url,
                    "content_type": (resp.headers or {}).get("content-type", ""),
                    "type": "response"
                }
                network_logs.append(log_entry)
                f_req.write(json.dumps(log_entry) + "\n")

            page.on("request", log_request)
            page.on("response", log_response)

            # downloads
            def _on_download(d):
                try:
                    path = d.path()  # may raise if not finished
                except Exception:
                    path = None
                fn = d.suggested_filename
                save_to = os.path.join(det_dir, "downloads", fn)
                os.makedirs(os.path.dirname(save_to), exist_ok=True)
                d.save_as(save_to)
                results["downloads"].append({"filename": fn, "path": os.path.relpath(save_to, case_dir)})
            page.on("download", _on_download)

            # visit
            for u in urls:
                try:
                    page.goto(u, wait_until="domcontentloaded", timeout=timeout*1000)
                    results["visited"].append(u)
                    
                    # NEW: Extract full phishing kit
                    kit_data = extract_phishing_kit(page, det_dir, u)
                    if kit_data:
                        results["phishing_kit"] = kit_data

                    # NEW: Generate enrichment files for attribution
                    enrichment_data = generate_enrichment_files(page, det_dir, u, network_logs)
                    if enrichment_data:
                        results["enrichment"] = enrichment_data
                    
                    # let timers/JS fire briefly
                    page.wait_for_timeout(min(5000, timeout*1000))
                except Exception as e:
                    results["errors"].append({"url": u, "err": str(e)})

            # export netlog-like (requests seen)
            f_req.flush(); f_req.close()
            ctx.storage_state(path=os.path.join(det_dir, "storage_state.json"))
            ctx.close(); browser.close()

    # summarize endpoints contacted (from requests.jsonl)
    endpoints = {}
    try:
        with open(out_req,"r",encoding="utf-8") as fr:
            for line in fr:
                try:
                    j = json.loads(line)
                    if "url" in j:
                        host = urlparse(j["url"]).hostname or ""
                        endpoints.setdefault(host, {"count":0,"methods":set(),"cts":set()})
                        endpoints[host]["count"] += 1
                        if "method" in j: endpoints[host]["methods"].add(j["method"])
                        if "ct" in j: endpoints[host]["cts"].add(j["ct"])
                except Exception:
                    pass
    except FileNotFoundError:
        pass

    # resolve endpoints to IPs (A/AAAA) — attribution feed
    import socket
    ep_list = []
    for h,v in endpoints.items():
        ips=[]
        try:
            for fam,_,_,_,sa in socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP):
                ip = sa[0]
                if ip not in ips: ips.append(ip)
        except Exception:
            pass
        ep_list.append({
            "host": h, "ips": ips, "count": v["count"],
            "methods": sorted(list(v["methods"])), "content_types": sorted(list(v["cts"]))
        })

    write_json(out_sum, {
        "visited": results["visited"],
        "downloads": results["downloads"],
        "endpoints": ep_list,
        "phishing_kit": results.get("phishing_kit"),
        "enrichment": results.get("enrichment"),
        "pcap": os.path.basename(out_pcap) if capture_pcap and os.path.exists(out_pcap) else None,
        "observe_only": observe_only,
        "policy": {"observe_only": observe_only, "blocked_methods": sorted(list(BLOCK_METHODS))}
    })

    print(f"[detonate] OK → {det_dir}")