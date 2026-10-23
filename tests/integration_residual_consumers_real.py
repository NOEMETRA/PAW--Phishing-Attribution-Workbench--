"""Actual offline publication/query/HTTP, saved-provider fixtures and preservation."""
from contextlib import closing
from email.message import EmailMessage
import hashlib
import io
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.consumer_views import assessment_view
from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case
from integration_html_observers_real import report_blocks


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def hashes(case):
    return {p.relative_to(case).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in case.rglob('*') if p.is_file()}


def check(case,raw,language='en'):
    require_stopped_case(case)
    assert verify_case(str(case)) and (case/'input.eml').read_bytes()==raw
    score=read(case/'report/score.json'); view=assessment_view(score)
    assert view['status']=='consistent_current_metadata'
    assert math.isclose(math.fsum(score['score_components'].values()),score['raw_score'],abs_tol=1e-12)
    assert score['coverage']==read(case/'analysis_coverage.json')
    assert score['calibrated'] is False and read(case/'execution.json')['no_egress'] is True
    text=(case/f'package/abuse_email_{language}.txt').read_text(encoding='utf-8')
    start=text.index('{',text.index('Recorded assessment' if language=='en' else 'Valutazione registrata'))
    recorded,_=json.JSONDecoder().raw_decode(text[start:])
    assert recorded=={'view':view,'recorded_assessment':score}
    assert read(case/'package/xarf_report.json')['assessment']==score
    for report in ('executive.md','technical.md'): report_blocks((case/'report'/report).read_text(encoding='utf-8'))
    return score


def check_zip(archive,case,raw,prefix=''):
    assert archive.read(prefix+'input.eml')==raw
    for name in ('report/score.json','analysis_coverage.json','report/executive.md','report/technical.md',
                 'package/xarf_report.json','evidence/merkle_index.json'):
        assert archive.read(prefix+name)==(case/name).read_bytes()


def main():
    message=EmailMessage(); message['From']='regression@example.invalid'; message['To']='recipient@example.invalid'
    message['Subject']='Constructed publication fixture, not accuracy truth'
    message.set_content('<p>Original &amp; literal</p>',subtype='html')
    samples={'crafted.eml':message.as_bytes(),'original.eml':next((REPO/'inbox').glob('*.eml')).read_bytes()}
    env=dict(os.environ,PYTHONPATH=str(REPO)+os.pathsep+str(REPO/'tests'),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PAW_PGP_PRIV',None)
    with tempfile.TemporaryDirectory(prefix='paw-residual-consumers-') as temporary:
        root=Path(temporary); inputs=root/'inputs'; inputs.mkdir()
        for name,raw in samples.items(): (inputs/name).write_bytes(raw)
        for profile,language in [('default','en'),('strict','it'),('conservative','en')]:
            directory=root/profile; directory.mkdir()
            run=subprocess.run([sys.executable,'-B','-P','-m','paw','trace','--src',str(inputs),
                '--no-egress','--abuse','--stix','--profile',profile,'--lang',language],
                cwd=directory,env=env,capture_output=True,timeout=180)
            assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-6000:]
            cases=list((directory/'cases').glob('case-*')); assert len(cases)==2
            for case in cases:
                raw=samples[read(case/'manifest.json')['source_name']]; check(case,raw,language)
                before=hashes(case)
                run=subprocess.run([sys.executable,'-B','-P','-m','paw','export','--case',str(case),'--format','zip'],
                    cwd=directory,env=env,capture_output=True,timeout=30)
                assert run.returncode==0,run.stdout+run.stderr
                exported=Path(str(case)+'.zip')
                with zipfile.ZipFile(exported) as archive: check_zip(archive,case,raw,case.name+'/')
                old_zip=exported.read_bytes(); signature=Path(str(exported)+'.asc'); signature.write_bytes(b'Existing signature fixture, not a valid proof')
                run=subprocess.run([sys.executable,'-B','-P','-m','paw','export','--case',str(case),'--format','zip'],
                    cwd=directory,env=dict(env,PAW_PGP_PRIV=str(root/'missing-private-key')),capture_output=True,timeout=30)
                assert run.returncode!=0 and b'PGP signing unavailable' in run.stdout+run.stderr
                assert exported.read_bytes()==old_zip and signature.read_bytes()==b'Existing signature fixture, not a valid proof'
                assert hashes(case)==before and verify_case(str(case))
            database=directory/'cases/index.db'; database_before=database.read_bytes()
            run=subprocess.run([sys.executable,'-B','-P','-m','paw','query','--by','domain','--value','example.invalid'],
                cwd=directory,env=env,capture_output=True,timeout=30)
            assert run.returncode==0,run.stdout+run.stderr
            rows=json.loads(run.stdout); assert rows
            assert all(row['assessment_view']['status']=='legacy_display_only' and row['assessment_view']['decision'] is None for row in rows)
            assert database.read_bytes()==database_before

        # Actual direct offline engine, with supplied saved metadata inserted only
        # after numeric assessment. This does not simulate provider acquisition.
        direct=root/'supplied-publication'; direct.mkdir()
        code='''import json
from pathlib import Path
from paw.core.network_policy import offline_policy
with offline_policy():
 from paw.core import trace
 write=trace.write_json
 def publish(path,value):
  write(path,value)
  if str(path).replace('\\\\','/').endswith('report/score.json'):
   case=Path(path).parent.parent
   marker='![literal](https://inert.invalid/pixel)<b>literal</b>'
   for name,data in [('detonation/summary.json',{'status':'fixture_supplied','endpoints':[{'host':marker,'ips':[],'count':1}]}),
       ('canary_ips.json',[marker]),('canary_visitors.json',[{'ip':marker,'reputation':{'score':8}}]),
       ('evidence/rekor_anchor.json',{'entry_uuid':marker,'logIndex':0}),('evidence/rekor_proof.json',{'treeSize':123})]:
    target=case/name; target.parent.mkdir(parents=True,exist_ok=True); write(str(target),data)
 trace.write_json=publish
 trace.trace_one(SOURCE,'en',True,True,False,True,'strict')
'''.replace('SOURCE',repr(str(inputs/'crafted.eml')))
        run=subprocess.run([sys.executable,'-B','-P','-c',code],cwd=direct,
            env=dict(env,PAW_PGP_PRIV=str(root/'unread-private-key')),capture_output=True,timeout=120)
        assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-5000:]
        supplied,=list((direct/'cases').glob('case-*'))
        check(supplied,samples['crafted.eml'])
        signing=read(supplied/'analysis_coverage.json')['stages']['manifest_signing']
        assert signing['status']=='unavailable' and signing['requested'] is True and signing['key_accessed'] is False
        assert not list(supplied.rglob('*.asc'))
        executive=report_blocks((supplied/'report/executive.md').read_text(encoding='utf-8'))
        technical=report_blocks((supplied/'report/technical.md').read_text(encoding='utf-8'))
        assert executive['Detonation (stored observations)']==read(supplied/'detonation/summary.json')
        assert executive['Canary (stored observations)']['ip_values']==read(supplied/'canary_ips.json')
        rekor=technical['Rekor (stored provider fields)']
        assert rekor['verification']['status']=='not_evaluated' and rekor['verification']['result'] is None
        assert rekor['proof']=={'treeSize':123}

        data=root/'http'; data.mkdir()
        with socket.socket() as listener: listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        def request(path,body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=body,
                    headers={'Content-Type':content_type}),timeout=20) as response: return response.read()
        with (root/'http.log').open('wb') as log:
            server=subprocess.Popen([sys.executable,'-B','-P','-m','uvicorn','paw.web.api:app','--app-dir',str(REPO),
                '--host','127.0.0.1','--port',str(port)],cwd=data,env=dict(env,PAW_DATA_DIR=str(data)),stdout=log,stderr=log)
            try:
                end=time.monotonic()+30
                while time.monotonic()<end:
                    assert server.poll() is None
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for profile in ('default','strict','conservative'):
                    raw=samples['crafted.eml']; boundary='residual-consumer-fixture'
                    upload=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="crafted.eml"\r\n'
                        'Content-Type: message/rfc822\r\n\r\n').encode()+raw+f'\r\n--{boundary}--\r\n'.encode()
                    path=json.loads(request('/api/upload',upload,'multipart/form-data; boundary='+boundary))['path']
                    job=json.loads(request('/api/analyze',json.dumps({'file_path':path,'profile':profile,
                        'options':{'no_egress':True,'abuse':True,'stix':True},'limits':{'wall_seconds':120,'stage_seconds':60}}).encode()))['analysis_id']
                    end=time.monotonic()+140
                    while time.monotonic()<end:
                        state=json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case=data/'cases'/state['case_ids'][0]; score=check(case,raw)
                    detail=json.loads(request('/api/cases/'+case.name))
                    assert detail['score']==score and detail['assessment_view']==assessment_view(score)
                    listing=json.loads(request('/api/cases'))['cases']
                    assert next(row for row in listing if row['case_id']==case.name)['assessment_view']==detail['assessment_view']
                    database=data/'cases/index.db'; before_db=database.read_bytes()
                    rows=json.loads(request('/api/query',json.dumps({'query_type':'domain','value':'example.invalid'}).encode()))['matches']
                    assert rows and all(row['assessment_view']['decision'] is None for row in rows)
                    assert database.read_bytes()==before_db
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive: check_zip(archive,case,raw)
                # Deliberate damage to the newly generated, stopped test case.
                # API reads must retain exact damaged bytes; restore them only
                # in this fixture so its original seal can be checked again.
                saved={name:(case/name).read_bytes() for name in ('manifest.json','headers.json','report/score.json',
                    'origin.json','attachments.json','report/technical.md')}
                try:
                    faults={'manifest.json':b'[1]','headers.json':b'[1]','report/score.json':b'{"score":NaN}',
                        'origin.json':b'{"cc":{"bad":1},"asn":[1]}','attachments.json':b'{}','report/technical.md':b'\xff'}
                    for name,value in faults.items(): (case/name).write_bytes(value)
                    damaged=hashes(case)
                    listing=json.loads(request('/api/cases'))['cases']
                    bad=next(row for row in listing if row['case_id']==case.name)
                    assert {'manifest.json','headers.json','score.json'} <= set(bad['artifact_errors'])
                    assert sum(row['assessment_view']['status']=='consistent_current_metadata' for row in listing)==2
                    detail=json.loads(request('/api/cases/'+case.name))
                    assert detail['score'] is detail['attachments'] is detail['technical_report'] is None
                    assert detail['assessment_view']['status']=='not_evaluated'
                    assert case.name in json.loads(request('/api/statistics'))['artifact_errors']
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('report/score.json')==faults['report/score.json']
                    assert hashes(case)==damaged
                    (case/'report/score.json').write_text('{"score":0.72,"decision":"legacy claim"}',encoding='utf-8')
                    detail=json.loads(request('/api/cases/'+case.name))
                    assert detail['score']['decision']=='legacy claim' and detail['assessment_view']['decision'] is None
                    assert detail['assessment_view']['status']=='legacy_display_only'
                finally:
                    for name,value in saved.items(): (case/name).write_bytes(value)
                assert verify_case(str(case))
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: six actual CLI cases / three owned-loopback HTTP workers / one direct offline saved-publication fixture; '
          'three profiles, two draft languages, read-only queries, unavailable PGP preserving existing ZIP/signature, '
          'literal saved dynamic/Rekor values, malformed-neighbor isolation, source/error/view and ZIP parity, originals and seals. '
          'No active provider acquisition or accuracy labels.')


if __name__=='__main__': main()
