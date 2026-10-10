"""Original EML -> real CLI + HTTP API in one directory, including CLI crash."""
import io
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

import psutil

REPO = Path(__file__).resolve().parents[1]


def read(path):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except (OSError,ValueError): return {}


def main():
    with tempfile.TemporaryDirectory(prefix='paw-cli-api-',dir=REPO.parent) as temporary:
        root = Path(temporary)
        source = next((REPO/'inbox').glob('*.eml')).read_bytes()
        inputs = root/'inbox'; inputs.mkdir()
        # Repeat original bytes to keep the worker busy while readers are tested.
        for index in range(8): (inputs/f'{index}.eml').write_bytes(source)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        environment = dict(os.environ,PYTHONPATH=str(REPO),PAW_DATA_DIR=str(root),
            PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8')
        empty_query = subprocess.run([sys.executable,'-X','utf8','-m','paw','query',
            '--by','domain','--value','fixture.invalid'],cwd=root,env=environment,
            capture_output=True,timeout=15)
        assert empty_query.returncode==0 and json.loads(empty_query.stdout)==[], empty_query.stderr
        assert not (root/'cases').exists(), 'Query created an empty index/storage'
        api_process = cli = None
        worker = None
        checks = []
        processes = []

        def request(path,method='GET',body=None):
            with urllib.request.urlopen(urllib.request.Request(
                    f'http://127.0.0.1:{port}'+path,method=method,data=body,
                    headers={'Content-Type':'application/json'} if body is not None else {}),timeout=15) as response:
                return response.read()

        def blocked(path,method='GET'):
            try: request(path,method)
            except urllib.error.HTTPError as error:
                assert error.code == 409,(path,error.code)
            else: raise AssertionError('Evidence access permitted: '+path)

        def start_cli(label,wait_for_index=False):
            known = set((root/'jobs').glob('analysis_*'))
            stream = (root/(label+'.log')).open('wb')
            process = subprocess.Popen([sys.executable,'-X','utf8','-m','paw','full',str(inputs),
                '--no-egress','--deadline','90','--stage-timeout','60'],cwd=root,
                env=environment,stdout=stream,stderr=stream)
            processes.append((process,stream,None))
            end = time.monotonic()+30
            while time.monotonic()<end:
                candidates = [p for p in (root/'jobs').glob('analysis_*') if p.is_dir() and p not in known]
                if candidates:
                    control = candidates[0]
                    record = read(control/'process.json')
                    progress = read(control/'progress.json')
                    # Let the first case complete and enter the real SQLite index
                    # while the batch is still active. Its rows must stay hidden.
                    if wait_for_index and len(progress.get('case_ids',[])) < 2:
                        time.sleep(.01)
                        continue
                    for case_id in progress.get('case_ids',[]):
                        case = root/'cases'/case_id
                        if wait_for_index and read(case/'execution.json').get('status') != 'completed':
                            continue
                        if record and read(case/'manifest.json').get('analysis_job') == control.name:
                            current = psutil.Process(record['pid'])
                            assert current.create_time() == record['created_at']
                            current.suspend()
                            processes[-1]=(process,stream,current)
                            return process,control,case,current
                if process.poll() is not None:
                    stream.flush()
                    raise AssertionError((root/(label+'.log')).read_text(encoding='utf-8',errors='replace'))
                time.sleep(.01)
            raise TimeoutError('CLI did not register a case')

        try:
            cli,control,case,worker = start_cli('active',wait_for_index=True)
            with (root/'api.log').open('wb') as log:
                # Startup recovery must leave the identified live CLI untouched.
                api_process = subprocess.Popen([sys.executable,'-m','uvicorn','paw.web.api:app',
                    '--host','127.0.0.1','--port',str(port)],cwd=root,env=environment,stdout=log,stderr=log)
                end = time.monotonic()+20
                while time.monotonic()<end:
                    if api_process.poll() is not None: raise AssertionError('API startup failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API did not start')
                state = json.loads(request('/api/analysis/'+control.name))
                assert state['origin']=='cli' and state['status']=='running',state
                assert cli.poll() is None and worker.is_running()
                listing = json.loads(request('/api/cases?limit=100'))['cases']
                assert listing and all(item['status']=='running' for item in listing),listing
                assert all(set(item)=={'case_id','status','summary','artifact_errors'} for item in listing),listing
                with closing(sqlite3.connect(root/'cases'/'index.db')) as connection:
                    indicator = connection.execute("SELECT type,value FROM indicators WHERE case_id=? AND type IN ('ip','domain','asn') LIMIT 1",
                        (case.name[5:],)).fetchone()
                assert indicator is not None,'Original EML did not produce an indexed indicator'
                query_body = json.dumps({'query_type':indicator[0],'value':indicator[1]}).encode()
                assert json.loads(request('/api/query','POST',query_body))['matches']==[]
                def cli_query():
                    database = root/'cases/index.db'
                    before = hashlib.sha256(database.read_bytes()).hexdigest()
                    result = subprocess.run([sys.executable,'-X','utf8','-m','paw','query',
                        '--by',indicator[0],'--value',indicator[1]],cwd=root,env=environment,
                        capture_output=True,timeout=15)
                    assert result.returncode==0, result.stderr.decode(errors='replace')
                    assert hashlib.sha256(database.read_bytes()).hexdigest()==before, 'CLI query rewrote the index'
                    return json.loads(result.stdout)
                active_matches = cli_query()
                assert active_matches==[], ('CLI exposed indexed cases of an active worker',active_matches)
                for path,method in [(f'/api/cases/{case.name}','GET'),
                        (f'/api/cases/{case.name}/verify','POST'),(f'/api/export/{case.name}','GET')]:
                    blocked(path,method)
                for command in ('verify','export'):
                    result = subprocess.run([sys.executable,'-m','paw',command,'--case',str(case)],cwd=root,
                        env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                    assert result.returncode != 0,(command,result.stdout)
                    assert b'Worker shutdown not confirmed' in result.stdout,result.stdout
                assert not list((root/'exports').glob('*.zip'))
                assert not list((root/'cases').glob('*.zip'))
                worker.resume()
                assert cli.wait(timeout=90)==0
                state=json.loads(request('/api/analysis/'+control.name))
                assert state['status']=='completed' and len(state['case_ids'])==8,state
                for identifier in state['case_ids']:
                    original=root/'cases'/identifier
                    manifest=read(original/'manifest.json')
                    assert manifest['analysis_job']==control.name and manifest['policy']['no_egress'] is True
                    assert (original/'input.eml').read_bytes()==source
                detail=json.loads(request('/api/cases/'+case.name))
                assert detail['status']=='completed' and detail['execution']['no_egress'] is True,detail
                assert json.loads(request('/api/cases/'+case.name+'/verify','POST'))['integrity']=='verified'
                with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                    assert archive.read('input.eml')==source
                matches = json.loads(request('/api/query','POST',query_body))['matches']
                assert len(matches)==8 and all(item['execution_status']=='completed' for item in matches),matches
                completed_matches = cli_query()
                assert {item['id'] for item in completed_matches}=={item['id'] for item in matches}
                listing = json.loads(request('/api/cases?limit=100'))['cases']
                assert len(listing)==8 and all(item['status']=='completed' and 'subject' in item for item in listing),listing
                checks.append({'flow':'missing-index CLI query creates no storage; active original-EML CLI + API startup; collections redacted and indexed matches hidden by both HTTP and CLI; query leaves SQLite bytes unchanged; HTTP and CLI evidence readers blocked; completed collection/query/verify/export','status':'passed'})

                cli,control,case,worker=start_cli('crash')
                cli.kill(); cli.wait(timeout=10)
                if os.name!='nt': worker.resume()  # POSIX orphan still owns its group.
                state=json.loads(request('/api/analysis/'+control.name))
                assert state['status']=='interrupted' and state['supervisor']['tree_stopped'] is True,state
                try:
                    assert worker.status() in {psutil.STATUS_ZOMBIE,psutil.STATUS_DEAD}
                except psutil.NoSuchProcess: pass
                assert json.loads(request('/api/cases/'+case.name+'/verify','POST'))['integrity']=='verified'
                index=(case/'evidence/merkle_index.json').read_bytes()
                with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                    assert archive.read('input.eml')==source
                time.sleep(.2)
                assert (case/'evidence/merkle_index.json').read_bytes()==index
                checks.append({'flow':'real CLI supervisor killed; HTTP recovery confirms worker shutdown before partial seal/verify/export','status':'passed'})
        finally:
            if api_process is not None:
                api_process.terminate(); api_process.wait(timeout=15)
            for process,stream,current in processes:
                if process.poll() is None: process.kill()
                process.wait(timeout=15)
                if current is not None and os.name!='nt':
                    try: os.killpg(current.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                stream.close()
        print(json.dumps({'status':'passed','network_scope':'All original EML analyses explicitly no-egress; HTTP loopback only',
            'platform':os.name,'checks':checks},indent=2))


if __name__=='__main__': main()
