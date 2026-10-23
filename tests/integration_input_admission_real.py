"""Real CLI/HTTP admission and malformed EML observations; no threat labels."""
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.exporter import export_case
from paw.core.verify import verify_case
from test_input_admission import UNC_PATHS

SAMPLES={
    'body.eml':b'not a transport header\r\nraw body',
    'separator.eml':b'From: sender@example.invalid\r\nbroken separator\r\nbody',
    'boundary.eml':b'Content-Type: multipart/mixed; boundary="absent"\r\n\r\nraw body'}
VALID=b'From: sender@example.invalid\r\nTo: recipient@example.invalid\r\n\r\nOriginal neighbor'


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def check_case(case, raw, *, malformed=True):
    assert (case/'input.eml').read_bytes()==raw and verify_case(case)
    execution=read(case/'execution.json')
    assert execution['status']=='completed' and execution['no_egress'] is True
    assert not execution['blocked_operations']
    if malformed:
        coverage=read(case/'analysis_coverage.json')
        assert coverage['stages']['header_parsing']['status']=='partial',coverage
        assert read(case/'header_inventory.json')['message_defects']
    return case


def check_cli_cases(root, inputs, *, partial=False):
    controls=[p for p in (root/'jobs').glob('analysis_*') if p.is_dir()]
    assert len(controls)==1
    control=controls[0]
    assert read(control/'supervisor.json')['tree_stopped'] is True
    result=read(control/'result.json')
    assert result['status']==('partial' if partial else 'completed'),result
    assert len(result['case_ids'])==len(inputs),result
    assert {x['input'] for x in result['successful_inputs']}==set(inputs)
    for item in result['successful_inputs']:
        case=check_case(root/'cases'/item['case_id'],inputs[item['input']],
                        malformed=item['input']!='valid.eml')
        with zipfile.ZipFile(export_case(case,'zip')) as archive:
            assert archive.read(case.name+'/input.eml')==inputs[item['input']]
    return result


def preflight(root, command, arguments, *, expected=1, api=False):
    # Bootstrap first, then fences ensure an old regression cannot contact UNC
    # even before the application guard would see a DNS/socket event.
    code='''import sys
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch
sys.path.insert(0,%r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy,violations
api_mode=%r
if api_mode:
    from paw.web.api import analyze_email,AnalysisRequest
    from fastapi import BackgroundTasks,HTTPException
attempts=[]
def fence(*a,**kw):
    attempts.append('filesystem');raise AssertionError('Pre-admission filesystem access')
with offline_policy(),ExitStack() as stack:
    for name in ('pathlib.Path.stat','pathlib.Path.resolve','pathlib.Path.mkdir','builtins.open','os.open','os.scandir'):
        stack.enter_context(patch(name,side_effect=fence))
    if api_mode:
        for value in %r:
            coroutine=analyze_email(AnalysisRequest(file_path=value),BackgroundTasks())
            try:
                try: coroutine.send(None)
                except HTTPException as error: assert error.status_code==400
                else: raise AssertionError('UNC request admitted')
            finally: coroutine.close()
    else:
        sys.argv=%r
        try: main()
        except SystemExit as error: assert error.code==%r
        else: raise AssertionError('Invalid CLI admitted')
assert not attempts and not violations(),(attempts,violations())
print('INPUT_PREFLIGHT_BEFORE_IO')
''' % (str(REPO),api,list(UNC_PATHS),['paw',command]+arguments,expected)
    env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1',PAW_DATA_DIR=str(root/'api'))
    result=subprocess.run([sys.executable,'-B','-c',code],cwd=root,env=env,capture_output=True,timeout=30)
    assert result.returncode==0 and b'INPUT_PREFLIGHT_BEFORE_IO' in result.stdout,result.stderr


def check_http(root, environment):
    data=root/'http';data.mkdir()
    with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    def request(path,body=None,content_type='application/json'):
        query=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=body,
            headers={'Content-Type':content_type} if body is not None else {})
        with urllib.request.urlopen(query,timeout=15) as response:return response.read()
    def upload(name,raw):
        boundary='paw-input-admission-boundary'
        payload=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+raw+f'\r\n--{boundary}--\r\n'.encode())
        return json.loads(request('/api/upload',payload,'multipart/form-data; boundary='+boundary))
    def analyze(path,**fields):
        return json.loads(request('/api/analyze',json.dumps({'file_path':path,'options':{'no_egress':True},**fields}).encode()))
    def wait(job):
        end=time.monotonic()+60
        while time.monotonic()<end:
            state=json.loads(request('/api/analysis/'+job['analysis_id']))
            if state['status'] not in {'running','queued'}:
                assert state['supervisor']['tree_stopped'] is True,state
                return state
            time.sleep(.05)
        raise TimeoutError(job)
    with (data/'server.log').open('wb') as log:
        server=subprocess.Popen([sys.executable,'-B','-m','uvicorn','paw.web.api:app','--host','127.0.0.1','--port',str(port)],cwd=data,env=dict(environment,PAW_DATA_DIR=str(data)),stdout=log,stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:raise RuntimeError('HTTP bootstrap failed')
                try:request('/health');break
                except urllib.error.URLError:time.sleep(.1)
            else:raise TimeoutError('HTTP bootstrap')
            uploaded=None
            for name,raw in SAMPLES.items():
                uploaded=upload(name,raw)
                state=wait(analyze(uploaded['path']))
                assert state['status']=='completed',state
                case=check_case(data/'cases'/state['case_id'],raw)
                assert json.loads(request('/api/cases/'+case.name+'/verify',b''))['integrity']=='verified'
                with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                    assert archive.read('input.eml')==raw
            before={p.name for p in (data/'jobs').iterdir()}
            invalid=[{'limits':{field:1.5}} for field in ('memory_bytes','artifact_bytes','artifact_files','log_bytes')]
            invalid += [{'limits':{'wall_seconds':True}},{'limits':{'stage_seconds':False}},
                {'profile':'unknown'},{'options':{'no_egress':'true'}},
                {'options':{'no_egress':True,'dkim_keys':{'invalid':True}}}]
            for fields in invalid:
                try:analyze(uploaded['path'],**fields)
                except urllib.error.HTTPError as error:assert error.code in (400,422),error.code
                else:raise AssertionError('Malformed HTTP options admitted')
            try:analyze(str(data/'uploads'))
            except urllib.error.HTTPError as error:assert error.code==404,error.code
            else:raise AssertionError('Directory admitted as upload')
            try:upload('empty.eml',b'')
            except urllib.error.HTTPError as error:assert error.code==400,error.code
            else:raise AssertionError('Empty upload admitted')
            assert {p.name for p in (data/'jobs').iterdir()}==before
            unsupported=upload('unsupported.MSG',b'Unavailable MSG fixture')
            state=wait(analyze(unsupported['path']))
            assert state['status']=='failed' and not state.get('case_ids'),state
        finally:
            server.terminate()
            try:server.wait(timeout=10)
            except subprocess.TimeoutExpired:server.kill();server.wait()


def main():
    with tempfile.TemporaryDirectory(prefix='paw-input-admission-') as temporary:
        root=Path(temporary);environment=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        guards=root/'guards';guards.mkdir()
        for command in ('analyze','quick','full','forensic','trace'):
            for path in UNC_PATHS:
                args=['--src',path] if command=='trace' else [path]
                if command!='quick':args+=['--no-egress']
                preflight(guards,command,args)
            for option,value in (('--deadline','nan'),('--stage-timeout','0'),('--memory-mib','0'),('--memory-mib',str(2**80))):
                args=['--src','input.eml'] if command=='trace' else ['input.eml']
                preflight(guards,command,args+[option,value])
        preflight(guards,'',[],api=True)
        assert not (guards/'jobs').exists() and not (guards/'cases').exists()
        cli_count=0
        for index,command in enumerate(('analyze','quick','full','forensic','trace')):
            work=root/command;work.mkdir();name=list(SAMPLES)[index%3];raw=SAMPLES[name]
            source=work/name;source.write_bytes(raw)
            args=['--src',str(source)] if command=='trace' else [str(source)]
            if command!='quick':args+=['--no-egress']
            result=subprocess.run([sys.executable,'-B','-m','paw',command,*args],cwd=work,env=environment,capture_output=True,timeout=90)
            assert result.returncode==0,(command,result.stdout,result.stderr)
            check_cli_cases(work,{name:raw});assert source.read_bytes()==raw;cli_count+=1
        batch=root/'batch';batch.mkdir();source=batch/'inputs';source.mkdir()
        good={**SAMPLES,'valid.eml':VALID}
        for name,raw in {**good,'empty.eml':b'','unsupported.MSG':b'Unavailable MSG fixture'}.items():
            (source/name).write_bytes(raw)
        result=subprocess.run([sys.executable,'-B','-m','paw','full',str(source),'--no-egress'],cwd=batch,env=environment,capture_output=True,timeout=90)
        assert result.returncode==1,result.stdout
        result=check_cli_cases(batch,good,partial=True)
        assert {item['input'] for item in result['failed_inputs']}=={'empty.eml','unsupported.MSG'},result
        assert set(result['selected_inputs'])==set(good)|{'empty.eml','unsupported.MSG'}
        for index,raw in enumerate((b'{',b'\xff',b'x'*(64*1024+1))):
            work=root/f'keys-{index}';work.mkdir();(work/'input.eml').write_bytes(VALID);(work/'keys.json').write_bytes(raw)
            result=subprocess.run([sys.executable,'-B','-m','paw','full','input.eml','--no-egress','--dkim-keys','keys.json'],cwd=work,env=environment,capture_output=True,timeout=30)
            assert result.returncode==1 and not (work/'jobs').exists() and not (work/'cases').exists(),result.stdout

        check_http(root,environment)
        print(json.dumps({'status':'passed','guarded_cold_CLI_preflights':50,'guarded_API_preflight_processes':1,
            'API_UNC_spellings':6,'actual_CLI_presets':cli_count,'actual_partial_batch_completed':4,
            'actual_partial_batch_failures':2,'invalid_key_CLI_invocations':3,'actual_HTTP_malformed_cases':3,
            'actual_failed_HTTP_MSG':1,'invalid_HTTP_requests_no_job':11,
            'scope':'Real workers, partial accounting, observed malformed EML defects and byte-preserving verify/ZIP. Pre-I/O fences prevent actual UNC access. No source authenticity, accuracy or OS network containment claim.'},indent=2))


if __name__=='__main__':main()
