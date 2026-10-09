"""Real CLI worker and real HTTP API. No mocked engine or browser."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import zipfile
import io

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo))
root = Path(os.environ.get('PAW_VERIFICATION_DIR', str(repo.parent / 'paw-validation'))).resolve()
root.mkdir(parents=True, exist_ok=True)
sample = next((repo/'inbox').glob('*.eml'))
data = root / 'real_api_run'
data.mkdir(exist_ok=True)
env = dict(os.environ, PAW_DATA_DIR=str(data), PYTHONPATH=str(repo),
    PYTHONIOENCODING='utf-8', PYTHONPYCACHEPREFIX=str(root/'pycache'))
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
base = f'http://127.0.0.1:{port}'
checks = []
def request(path, body=None, content_type='application/json'):
    req = urllib.request.Request(base+path, data=body,
        headers={'Content-Type':content_type} if body is not None else {})
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.read()
with (data/'api_server.log').open('wb') as log:
    server = subprocess.Popen([sys.executable,'-X','utf8','-m','uvicorn','paw.web.api:app',
        '--host','127.0.0.1','--port',str(port)], cwd=data, env=env, stdout=log, stderr=log)
    try:
        for _ in range(100):
            if server.poll() is not None: raise RuntimeError('API server failed to start')
            try:
                request('/health')
                break
            except (urllib.error.URLError, TimeoutError): time.sleep(.1)
        else: raise RuntimeError('API did not become healthy')
        boundary = 'paw-upload-boundary'
        payload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="source.eml"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
            + sample.read_bytes() + f'\r\n--{boundary}--\r\n'.encode())
        upload = json.loads(request('/api/upload', payload, 'multipart/form-data; boundary='+boundary))
        job = json.loads(request('/api/analyze', json.dumps({'file_path':upload['path'],
            'profile':'strict','options':{'no_egress':True,'stix':True,'abuse':True}}).encode()))
        started = time.perf_counter()
        for _ in range(600):
            status = json.loads(request('/api/analysis/'+job['analysis_id']))
            if status['status'] not in {'queued','running'}: break
            time.sleep(.2)
        if status['status'] != 'completed': raise RuntimeError(str(status))
        case_id = status['case_id']
        detail = json.loads(request('/api/cases/'+case_id))
        execution = detail['execution']
        assert execution['no_egress'] is True
        assert execution['transport_headers_available'] is True
        assert execution['input_kind'] == 'email'
        assert not execution['blocked_operations'], execution
        assert execution['assessment_status'] == 'partial'
        assert detail['authentication']['trusted'] is False
        assert detail['authentication']['dmarc']['verification']['result'] is None
        assert detail['coverage']['stages']['detonation']['status'] == 'skipped'
        assert detail['origin']['verified'] is False
        assert detail['mime']['status'] in {'completed','partial'}
        assert detail['coverage']['stages']['mime_parsing']['status'] == detail['mime']['status']
        index = json.loads((data/'cases'/case_id/'evidence/merkle_index.json').read_text())
        assert {'execution.json','mime_analysis.json','attachments.json','package/subject.txt'} <= set(index)
        assert 'unverified header claims' in detail['executive_report']
        assert not (data/'cases'/case_id/'detonation').exists()
        assert '\\n' not in detail['executive_report']
        assert 'LOW RISK' not in (data/'jobs'/job['analysis_id']/'worker.log').read_text(encoding='utf-8')
        checks.append({'flow':'real API -> real worker -> original repository EML -> evidence verification',
            'status':'passed','elapsed_seconds':round(time.perf_counter()-started,3),
            'execution':execution,'case_id':case_id})
        listing = json.loads(request('/api/cases'))
        assert listing['total'] >= 1
        domain = json.loads((data/'cases'/case_id/'domains.json').read_text())['from_domain']['domain']
        matches = json.loads(request('/api/query',json.dumps({'query_type':'domain','value':domain}).encode()))
        assert matches['matches']
        archive = request('/api/export/'+case_id)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            assert {'manifest.json','input.eml','report/score.json','evidence/merkle_index.json','analysis_coverage.json'} <= set(z.namelist())
        checks.append({'flow':'case list, detail, SQLite indicator query, actual ZIP export','status':'passed'})
        try:
            request('/api/analyze',json.dumps({'file_path':str(sample),'options':{}}).encode())
        except urllib.error.HTTPError as error:
            assert error.code == 400
        else: raise AssertionError('API accepted a file outside uploads')
        checks.append({'flow':'upload path containment','status':'passed'})
        # A disabled legacy update must leave a real sealed case byte-identical.
        from paw.core.trace import update_report
        from paw.core.network_policy import offline_policy
        from paw.core.verify import verify_case
        original_report = (data/'cases'/case_id/'report/executive.md').read_bytes()
        original_index = (data/'cases'/case_id/'evidence/merkle_index.json').read_bytes()
        with offline_policy():
            try: update_report(str(data/'cases'/case_id))
            except RuntimeError as error: assert 'unavailable' in str(error)
            else: raise AssertionError('Legacy update mutated a sealed case')
            assert verify_case(str(data/'cases'/case_id))
        assert original_report == (data/'cases'/case_id/'report/executive.md').read_bytes()
        assert original_index == (data/'cases'/case_id/'evidence/merkle_index.json').read_bytes()
        checks.append({'flow':'legacy update refuses mutation of sealed case', 'status':'passed'})

        # A real invalid MSG must fail its worker, without fabricated completion.
        invalid_payload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="invalid.msg"\r\n\r\n'.encode()
            + b'Not an OLE MSG file' + f'\r\n--{boundary}--\r\n'.encode())
        invalid_upload = json.loads(request('/api/upload', invalid_payload, 'multipart/form-data; boundary='+boundary))
        invalid_job = json.loads(request('/api/analyze', json.dumps({'file_path': invalid_upload['path'], 'options': {'no_egress':True}}).encode()))
        for _ in range(150):
            failure = json.loads(request('/api/analysis/'+invalid_job['analysis_id']))
            if failure['status'] not in {'queued','running'}: break
            time.sleep(.2)
        assert failure['status'] == 'failed', failure
        assert failure['progress'] is None
        assert failure['error']
        checks.append({'flow':'real worker rejects invalid MSG; no fabricated completion', 'status':'passed'})

        # Deadline and cancellation exercise the actual engine worker, never a substitute.
        timed_job = json.loads(request('/api/analyze', json.dumps({'file_path':upload['path'],
            'options':{'no_egress':True},'limits':{'wall_seconds':.05}}).encode()))
        for _ in range(100):
            timed = json.loads(request('/api/analysis/'+timed_job['analysis_id']))
            if timed['status'] not in {'queued','running'}: break
            time.sleep(.1)
        assert timed['status'] == 'timed_out' and timed['progress'] is None, timed
        checks.append({'flow':'actual analysis worker overall timeout','status':'passed','supervisor':timed['supervisor']})
        first_job = json.loads(request('/api/analyze',json.dumps({'file_path':upload['path'],'options':{'no_egress':True}}).encode()))
        second_job = json.loads(request('/api/analyze',json.dumps({'file_path':upload['path'],'options':{'no_egress':True}}).encode()))
        queue_deadline = json.loads(request('/api/analyze',json.dumps({'file_path':upload['path'],
            'options':{'no_egress':True},'limits':{'wall_seconds':.05}}).encode()))
        for _ in range(100):
            expired = json.loads(request('/api/analysis/'+queue_deadline['analysis_id']))
            if expired['status'] not in {'queued','running'}: break
            time.sleep(.1)
        assert expired['status'] == 'timed_out' and expired['error'] == 'Queue deadline exceeded', expired
        assert not (data/'jobs'/queue_deadline['analysis_id']).exists()
        checks.append({'flow':'queue wait consumes overall deadline; expired job never launches','status':'passed'})
        queued = json.loads(request('/api/analysis/'+second_job['analysis_id']+'/cancel', b'{}'))
        assert queued['status'] == 'cancelled', queued
        request('/api/analysis/'+first_job['analysis_id']+'/cancel', b'{}')
        for _ in range(100):
            cancelled = json.loads(request('/api/analysis/'+first_job['analysis_id']))
            if cancelled['status'] not in {'queued','running'}: break
            time.sleep(.1)
        assert cancelled['status'] == 'cancelled', cancelled
        assert cancelled['progress'] is None
        checks.append({'flow':'actual API queued and running cancellation','status':'passed'})
        assert json.loads(request('/api/analysis/'+job['analysis_id']+'/cancel', b'{}'))['status'] == 'completed'
        checks.append({'flow':'cancellation preserves already-completed job','status':'passed'})

    finally:
        server.terminate()
        try: server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
(root/'real_flow_results.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
print(json.dumps(checks,indent=2))
