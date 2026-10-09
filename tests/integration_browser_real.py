"""Exercise real Chromium against a controlled loopback HTTP server."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import os
from pathlib import Path
import sys
import threading
import time

repo = Path(__file__).resolve().parents[1]
root = Path(os.environ.get('PAW_VERIFICATION_DIR', str(repo.parent / 'paw-validation'))).resolve()
root.mkdir(parents=True, exist_ok=True)
sys.path.insert(0,str(repo))
from paw.core.runtime import wait_for_gate, mark_stage
wait_for_gate()
from paw.detonate.runner import run_detonation
requests = Counter()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        requests[self.path] += 1
        self.send_response(200)
        if self.path.startswith('/download'):
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="invoice.pdf"')
            self.end_headers()
            self.wfile.write(('Controlled download ' + self.path).encode())
            return
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.end_headers()
        download = ''
        if self.path in ('/page0', '/page1'):
            download = '<a id="download" href="/download' + self.path[-1] + '" download>Download</a><script>setTimeout(()=>document.getElementById("download").click(), 300)</script>'
        self.wfile.write(('<!doctype html><html><title>PAW local validation</title><body>Controlled browser validation' + download + '</body></html>').encode())
    def log_message(self,*args): pass

server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
thread = threading.Thread(target=server.serve_forever,daemon=True)
thread.start()
data = root/'real_browser_run'
data.mkdir(exist_ok=True)
os.chdir(data)
case_id = 'local-browser-validation'
case = data/'cases'/case_id
case.mkdir(parents=True,exist_ok=True)
mark_stage('controlled_browser', case_id)
urls = [f'http://127.0.0.1:{server.server_port}/page{i}' for i in range(3)]
(case/'headers.json').write_text(json.dumps({'urls':urls+urls}),encoding='utf-8')
started = time.perf_counter()
try:
    run_detonation(url=None,case_id=case_id,timeout=2,network_enrichment=False)
    first = json.loads((case/'detonation/summary.json').read_text())
    assert first['visited'] == urls, first
    assert len(first['url_results']) == 3
    assert len({r['artifacts'] for r in first['url_results']}) == 3
    assert len(first['downloads']) == 2, first
    assert {d['filename'] for d in first['downloads']} == {'invoice.pdf'}
    assert len({d['path'] for d in first['downloads']}) == 2
    assert len({d['sha256'] for d in first['downloads']}) == 2
    for download in first['downloads']:
        assert hashlib.sha256((case/download['path']).read_bytes()).hexdigest() == download['sha256']
    assert all(e['ip_resolution_status'] == 'skipped' for e in first['endpoints'])
    assert any('text/html; charset=utf-8' in e['content_types'] for e in first['endpoints'])
    first_run = case/first['run_directory']
    preserved = (first_run/'requests.jsonl').read_bytes()
    run_detonation(url=urls[0],case_id=case_id,timeout=2,network_enrichment=False)
    second = json.loads((case/'detonation/summary.json').read_text())
    assert second['visited'] == [urls[0]]
    assert len(second['runs']) == len(first['runs'])+1
    assert (first_run/'requests.jsonl').read_bytes() == preserved
    assert requests['/page0'] == 2
    assert requests['/page1'] == requests['/page2'] == 1
    report = {'status':'passed','browser':'Real Chromium/Playwright',
        'target':'Controlled local HTTP server; no suspicious external URL opened',
        'input_urls':3,'first_run_visits':len(first['visited']),
        'explicit_url_rerun_visits':len(second['visited']),
        'earlier_evidence_preserved':True,'elapsed_seconds':round(time.perf_counter()-started,3),
        'same_filename_downloads_preserved':True, 'download_hashes_verified':True,
        'content_types_preserved':True, 'ip_resolution_status':'skipped',
        'enrichment':'Explicitly disabled; loopback browser traffic permitted'}
finally:
    server.shutdown()
    server.server_close()
(root/'real_browser_results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
