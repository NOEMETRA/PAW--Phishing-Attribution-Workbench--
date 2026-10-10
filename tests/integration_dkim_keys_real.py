"""Actual RSA signatures -> offline CLI/HTTP workers, sealed key evidence and ZIP."""
import base64
import hashlib
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
from paw.core.verify import verify_case


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def check_case(case, raw, expected, key_raw=None):
    assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
    auth=read(case/'auth.json')['dkim']
    check=auth['verification']; assert check['result']==expected,check
    execution=read(case/'execution.json')
    assert execution['no_egress'] and not execution['blocked_operations'],execution
    score=read(case/'report'/'score.json')
    assert score['score_components']['verified_authentication_failures']==0,score
    if key_raw is None:
        assert not (case/'dkim_keys.json').exists()
        assert 'dkim_key_evidence' not in read(case/'manifest.json')
    else:
        assert (case/'dkim_keys.json').read_bytes()==key_raw
        evidence=read(case/'manifest.json')['dkim_key_evidence']
        assert evidence==auth['key_evidence']
        assert evidence['sha256']==hashlib.sha256(key_raw).hexdigest()
        assert evidence['provenance_status']=='unverified'
        assert 'dkim_key_provenance' in score['coverage']['not_evaluated']
        assert 'key provenance unverified' in (case/'report'/'executive.md').read_text(encoding='utf-8')
        if check.get('source'):
            assert check['key_provenance_status']=='unverified'
            assert check['message_sha256']==hashlib.sha256(raw).hexdigest()
    return check


def main():
    import dkim
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
    public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    raw=b'From: sender@example.com\r\nTo: recipient@example.net\r\nSubject: Signature regression\r\n\r\nOriginal body\r\n'
    def sign(selector,message=raw):
        return dkim.sign(message,selector,b'example.com',private,include_headers=[b'from',b'to',b'subject'])+message
    signed=sign(b'test')
    samples={'pass.eml':signed,'fail.eml':signed.replace(b'Original body',b'Changed body'),
        'missing.eml':sign(b'missing').replace(b'Original body',b'Changed body'),
        'unsigned.eml':raw,'multi.eml':sign(b'missing',signed)}
    results={'pass.eml':'pass','fail.eml':'fail','missing.eml':None,'unsigned.eml':None,'multi.eml':'pass'}
    bundle={'schema_version':1,'source':'Generated RSA regression fixture; no independent DNS provenance',
            'records':{'TEST._domainkey.Example.com.':'v=DKIM1; k=rsa; p='+base64.b64encode(public).decode('ascii')}}
    key_raw=(json.dumps(bundle,indent=2)+'\r\n').encode('utf-8')
    with tempfile.TemporaryDirectory(prefix='paw-dkim-keys-',dir=REPO.parent) as temporary:
        base=Path(temporary); inputs=base/'inputs'; inputs.mkdir()
        for name,value in samples.items(): (inputs/name).write_bytes(value)
        keys=base/'keys.json'; keys.write_bytes(key_raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        def cli(label,args,expected=0):
            root=base/label; root.mkdir()
            result=subprocess.run([sys.executable,'-X','utf8','-m','paw',*args,
                '--deadline','90','--stage-timeout','45'],cwd=root,env=env,capture_output=True,timeout=120)
            (base/(label+'.log')).write_bytes(result.stdout+result.stderr)
            assert result.returncode==expected,result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
            if expected: return root
            control,=(p for p in (root/'jobs').iterdir() if p.is_dir())
            assert read(control/'supervisor.json')['tree_stopped']
            request=read(control/'request.json')
            if '--dkim-keys' in args:
                admitted=Path(args[args.index('--dkim-keys')+1]).read_bytes()
                assert request['dkim_key_evidence']['text'].encode('utf-8')==admitted
            return root
        root=cli('batch',['full',str(inputs),'--no-egress','--dkim-keys',str(keys)])
        cases={read(p/'manifest.json')['source_name']:p for p in (root/'cases').glob('case-*')}
        assert set(cases)==set(samples)
        for name,case in cases.items(): check_case(case,samples[name],results[name],key_raw)
        multi=read(cases['multi.eml']/'auth.json')['dkim']['verification']
        assert [s['result'] for s in multi['signatures']]==[None,'pass'],multi
        for profile in ('analyze','quick','forensic','trace'):
            args=[profile,*(['--src'] if profile=='trace' else []),str(inputs/'pass.eml')]
            if profile!='quick': args+=['--no-egress']
            args+=['--dkim-keys',str(keys)]
            root=cli(profile,args); case,=(root/'cases').glob('case-*')
            check_case(case,signed,'pass',key_raw)
        root=cli('no-keys',['full',str(inputs/'pass.eml'),'--no-egress'])
        case,=(root/'cases').glob('case-*'); check_case(case,signed,None)
        malformed_bundle={**bundle,'records':{'test._domainkey.example.com':'v=DKIM1; p=invalid'}}
        malformed=base/'malformed-key.json'; malformed.write_text(json.dumps(malformed_bundle),encoding='utf-8')
        # This is structurally valid evidence, but the actual public-key decoder
        # must retain an error outcome instead of labeling the message a failure.
        root=cli('malformed-key',['full',str(inputs/'pass.eml'),'--no-egress','--dkim-keys',str(malformed)])
        case,=(root/'cases').glob('case-*')
        key_check=check_case(case,signed,None,malformed.read_bytes())
        assert key_check['signatures'][0]['status']=='error',key_check
        for label,content in [('bad-json',b'{'),('oversized',b'x'*65537)]:
            invalid=base/(label+'.json'); invalid.write_bytes(content)
            root=cli(label,['full',str(inputs/'pass.eml'),'--no-egress','--dkim-keys',str(invalid)],expected=1)
            assert not (root/'cases').exists() and not (root/'jobs').exists()

        api_root=base/'api'; api_root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        server_env=dict(env,PAW_DATA_DIR=str(api_root))
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (base/'api.log').open('wb') as log:
            server=subprocess.Popen([sys.executable,'-X','utf8','-m','uvicorn','paw.web.api:app',
                '--host','127.0.0.1','--port',str(port)],cwd=api_root,env=server_env,stdout=log,stderr=log)
            try:
                end=time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API startup failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('pass.eml','fail.eml'):
                    message=samples[name]; boundary='paw_dkim_fixture'
                    upload=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+message+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded=json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload={'file_path':uploaded['path'],'profile':'strict',
                             'options':{'no_egress':True,'dkim_keys':bundle}}
                    if name=='pass.eml':
                        for bad in ('keys.json',{**bundle,'verified':True},{**bundle,'records':{'example.com':'x'}}):
                            invalid={**payload,'options':{'no_egress':True,'dkim_keys':bad}}
                            try: request('/api/analyze','POST',json.dumps(invalid).encode())
                            except urllib.error.HTTPError as exc: assert exc.code==400,exc
                            else: raise AssertionError('Invalid API keys accepted')
                        assert not list((api_root/'jobs').glob('analysis_*'))
                    job=json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end=time.monotonic()+90
                    while time.monotonic()<end:
                        state=json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'running','queued'}: break
                        time.sleep(.1)
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case=api_root/'cases'/state['case_id']
                    api_key_raw=json.dumps(bundle,ensure_ascii=False,separators=(',',':')).encode('utf-8')
                    check_case(case,message,results[name],api_key_raw)
                    archive=request('/api/export/'+case.name)
                    with zipfile.ZipFile(io.BytesIO(archive)) as zip_file:
                        assert zip_file.read('input.eml')==message
                        assert zip_file.read('dkim_keys.json')==api_key_raw
                assert keys.read_bytes()==key_raw
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: actual RSA pass/body-fail/missing-key/unsigned/multiple-signature offline batch; '
          'all five CLI presets, absent-key compatibility, pre-job rejection; actual loopback HTTP '
          'API workers and exports preserve MIME/key snapshots/seals with unverified provenance '
          'and zero local-key authentication risk; no DNS retrieval or simulated analysis.')


if __name__=='__main__': main()
