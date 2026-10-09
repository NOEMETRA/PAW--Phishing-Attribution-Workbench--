"""Real Chromium UI -> real API -> real worker -> actual evidence and downloads."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import uuid
import zipfile
from email.message import EmailMessage
from playwright.sync_api import sync_playwright, expect

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(repo))
root = repo.parent/'paw-validation'
data = root/'gui_runs'/uuid.uuid4().hex
data.mkdir(parents=True)
outputs = repo.parent.parent/'outputs'
outputs.mkdir(exist_ok=True)
env = dict(os.environ,PYTHONPATH=str(repo),PYTHONPYCACHEPREFIX=str(root/'pycache'),PYTHONIOENCODING='utf-8')
with socket.socket() as socket_probe:
    socket_probe.bind(('127.0.0.1',0))
    port = socket_probe.getsockname()[1]
base = f'http://127.0.0.1:{port}'
client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
checks, external, errors = [], [], []
with (data/'server.log').open('wb') as log:
    server = subprocess.Popen([sys.executable,'-X','utf8','-m','paw','gui','--no-browser','--port',str(port),'--data-dir',str(data)],
        cwd=repo,env=env,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    try:
        for _ in range(200):
            if server.poll() is not None: raise RuntimeError('GUI launcher failed: '+(data/'server.log').read_text(encoding='utf-8'))
            try:
                client.open(base+'/health',timeout=1).close()
                break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('GUI service did not become ready')
        # Actual HTTP boundary checks before browser tests.
        for headers in ({'Host':'attacker.invalid'},{'Origin':'https://attacker.invalid'}):
            try: client.open(urllib.request.Request(base+'/health',headers=headers))
            except urllib.error.HTTPError as error: assert error.code==403
            else: raise AssertionError('Cross-origin/host request accepted')
        checks.append({'flow':'Loopback launcher and actual HTTP Host/Origin rejection','status':'passed'})
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=['--disable-background-networking','--disable-sync'])
            context=browser.new_context(viewport={'width':1440,'height':1050},accept_downloads=True)
            page=context.new_page()
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.on('request',lambda request:external.append(request.url) if not request.url.startswith(base+'/') else None)
            page.goto(base)
            expect(page.locator('#connection')).to_have_text('Servizio locale connesso')
            page.screenshot(path=str(outputs/'PAW_GUI_IMPORT.png'),full_page=True)
            sample=next((repo/'inbox').glob('*.eml'))
            page.locator('#email-file').set_input_files(str(sample))
            page.locator('#start-analysis').click()
            expect(page.locator('#case-view')).to_be_visible(timeout=45000)
            expect(page.locator('#case-status')).to_have_text('Completata')
            expect(page.locator('#case-scope')).to_have_text('Analisi locale offline')
            expect(page.locator('#case-coverage')).to_have_text('Parziale')
            expect(page.locator('#job-timeline li')).not_to_have_count(0)
            case_id=page.locator('#case-id').inner_text()
            execution=json.loads((data/'cases'/case_id/'execution.json').read_text())
            assert execution['no_egress'] and not execution['blocked_operations']
            page.locator('#verify-case').click()
            expect(page.locator('#case-integrity')).to_have_text('Verificata',timeout=15000)
            page.screenshot(path=str(outputs/'PAW_GUI_CASO.png'),full_page=True)
            with page.expect_download() as download_event:page.locator('#export-case').click()
            archive=Path(download_event.value.path())
            with zipfile.ZipFile(archive) as exported:
                assert exported.read('input.eml')==sample.read_bytes()
                assert 'evidence/merkle_index.json' in exported.namelist()
            checks.append({'flow':'Chromium import -> actual worker -> coverage -> verify -> real ZIP','status':'passed','case_id':case_id})
            page.locator('#report-button').click()
            expect(page.locator('#report-content')).to_contain_text('Authentication')
            page.locator('#overview-button').click()
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            page.locator('#mobile-cases').click()
            expect(page.locator('#case-list')).to_be_visible()
            page.locator('#mobile-cases').click()
            page.screenshot(path=str(outputs/'PAW_GUI_MOBILE.png'),full_page=True)
            page.set_viewport_size({'width':1440,'height':1050})
            checks.append({'flow':'Mobile layout without horizontal overflow, accessible case archive','status':'passed'})
            # Component contract using actual cryptographic results, not fake API responses.
            sys.path.insert(0,str(repo/'tests'))
            from test_authentication_contracts import RealDkimContracts
            from paw.core.dkim_offline import verify_dkim_offline
            from paw.core.network_policy import offline_policy
            RealDkimContracts.setUpClass()
            with offline_policy():
                passed=verify_dkim_offline(RealDkimContracts.signed,RealDkimContracts.records)
                failed=verify_dkim_offline(RealDkimContracts.signed.replace(b'Original body',b'Tampered body'),RealDkimContracts.records)
            assert passed['result']=='pass' and failed['result']=='fail'
            for result in (passed,failed):
                page.evaluate('value=>renderAuthentication({dkim:{verification:value}})',result)
                expect(page.locator('#authentication-list')).to_contain_text('Esito: '+result['result'])
            assert page.locator('#authentication-list .failed').count()==1
            checks.append({'flow':'Authentication renderer distinguishes actual RSA DKIM pass/fail from completed checks','status':'passed','scope':'Component contract; local-key input is not yet exposed by the GUI'})
            # Real bytes with hostile filenames, headers and HTML: no remote resource rendered.
            email=EmailMessage()
            email['From']='Sender <sender@example.invalid>'
            email['To']='Recipient <recipient@example.invalid>'
            email['Subject']='<img src="https://email-content.invalid/pixel" onerror="window.pawAttack=1">'
            email.set_content('Controlled hostile-content regression, not an original mailbox email.')
            email.add_alternative('<html><img src="https://email-content.invalid/pixel"><script>window.pawAttack=1</script></html>',subtype='html')
            email.add_attachment(b'Actual preserved attachment bytes',maintype='application',subtype='octet-stream',filename='<img src=x onerror=window.pawAttack=1>.pdf')
            page.locator('#new-analysis').click()
            page.locator('#email-file').set_input_files({'name':'<img src=x onerror=window.pawAttack=1>.eml','mimeType':'message/rfc822','buffer':email.as_bytes()})
            page.locator('#start-analysis').click()
            expect(page.locator('#case-view')).to_be_visible(timeout=45000)
            page.locator('#attachments-button').click()
            expect(page.locator('#attachment-list')).to_contain_text('<img src=x')
            assert page.locator('img').count()==0 and page.evaluate('window.pawAttack') is None
            page.locator('#report-button').click()
            assert page.locator('script').count()==1 # Only the application's own external script.
            page.locator('#data-button').click()
            expect(page.locator('#case-data')).to_contain_text('email-content.invalid')
            assert not external, external
            checks.append({'flow':'Actual hostile-content EML analyzed offline and displayed as inert text','status':'passed'})
            page.locator('#new-analysis').click()
            page.locator('#deadline').fill('1')
            page.locator('#email-file').set_input_files(str(sample))
            page.locator('#start-analysis').click()
            expect(page.locator('#job-status')).to_have_text('Tempo esaurito',timeout=20000)
            expect(page.locator('#case-view')).to_be_hidden()
            checks.append({'flow':'GUI displays timeout from actual worker without fabricated case completion','status':'passed'})
            page.locator('#new-analysis').click()
            page.locator('#deadline').fill('900')
            page.locator('#email-file').set_input_files(str(sample))
            page.locator('#start-analysis').click()
            expect(page.locator('#cancel-job')).to_be_enabled(timeout=5000)
            page.locator('#cancel-job').click()
            expect(page.locator('#job-status')).to_have_text('Annullata',timeout=20000)
            page.locator('#show-log').click()
            expect(page.locator('#job-log')).to_be_visible()
            checks.append({'flow':'GUI cancels an actual job and opens its actual log','status':'passed'})
            assert not errors, errors
            assert not external,external
            browser.close()
    finally:
        server.terminate()
        try: server.wait(timeout=10)
        except subprocess.TimeoutExpired:server.kill();server.wait()
result={'status':'passed','checks':checks,'browser_errors':errors,'external_browser_requests':external,
    'data_directory':str(data),'engine':'Actual PAW worker, no mocked API results'}
(root/'real_gui_results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
