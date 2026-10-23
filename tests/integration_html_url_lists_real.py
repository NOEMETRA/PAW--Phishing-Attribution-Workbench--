"""Actual offline list-context extraction and publication; no browser/requests to samples."""
import base64
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
from html import escape
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

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def fixtures():
    one, two = 'https://one.invalid/a', 'https://two.invalid/b'
    token = base64.b64encode(b'https://encoded.invalid/a%2Fb').decode()
    invalid = ['https://bad.invalid/%ZZ','https://bad.invalid:bad/a','https://long.invalid/'+'x'*65536]
    budget = [f'https://slot.invalid/p{index}' for index in range(100)]
    entity_invalid = ['https://bad.invalid/a"tail','https://bad.invalid/?x=a<tail',
        'https://bad.invalid/#a>tail','hxxps://bad[.]invalid/a"tail',
        base64.b64encode(b'https://encoded.invalid/a"tail').decode()]
    entity_valid = ["https://good.invalid/a'b?x=c'd#e'f",'https://good.invalid/a%22b%3Cc%3Ed%27e']
    rows = {
        'srcset.eml': ([f'<img srcset="{one}, {two} 2x">'],[one,two],[one,two],2),
        'imagesrcset.eml': ([f'<link imagesrcset="{one}, {two} 2x">'],[one,two],[one,two],2),
        'commas.eml': (['<img srcset="HTTPS://one.invalid/a,b%2Cc?x=1,2&amp;y=3#c,d 1x, '+two+' 2x">'],
                       ['HTTPS://one.invalid/a,b%2Cc?x=1,2&y=3#c,d',two],
                       ['HTTPS://one.invalid/a,b%2Cc?x=1,2&y=3#c,d',two],2),
        'nonnetwork.eml': (['<img srcset="data:text/plain,https://data.invalid/a 1x, '
            '/relative?next=https://query.invalid/a 2x, '+one+' invalid(https://descriptor.invalid/a,b), '+two+' 3x">'],
            [one,two],[one,two],2),
        'encoded.eml': ([f'<img srcset="hxxps://refanged[.]invalid/a%2Fb, {token} 2x">'],
            ['https://refanged.invalid/a%2Fb','https://encoded.invalid/a%2Fb'],
            ['hxxps://refanged[.]invalid/a%2Fb',token],2),
        'invalid.eml': (['<img srcset="'+', '.join(invalid)+'">'],[],invalid,3),
        'entity-invalid.eml': (['<img '+name+'="'+escape(', '.join(entity_invalid),quote=True)+'">'
            for name in ('srcset','imagesrcset')],[],entity_invalid,10),
        'entity-valid.eml': (['<img '+name+'="'+escape(', '.join(entity_valid),quote=True)+'">'
            for name in ('srcset','imagesrcset')],entity_valid,entity_valid,4),
        'ordinary.eml': (['<a href="'+one+',">go</a><script>"'+one+',"</script><!-- '+one+', -->'
                          '<img srcset="'+one+',">'],[one+',',one],[one+',',one],2),
        'multipart.eml': (['<script>unfinished',f'<img srcset="{one}, {two} 2x">',f'<source srcset="{one},">'],
                          [one,two],[one,two],3),
        'budget.eml': (['<img srcset="'+', '.join(budget)+'">']*50,budget,budget,5000)}
    samples = {}
    for name,(html,targets,sources,count) in rows.items():
        message = EmailMessage(policy=policy.SMTP)
        message['From'] = 'fixture@example.invalid'; message['Subject'] = 'HTML URL list fixture'
        message.set_content(html[0],subtype='html')
        for part in html[1:]: message.add_alternative(part,subtype='html')
        samples[name] = (message.as_bytes(),targets,sources,count)
    return samples


def check(case, sample):
    raw,targets,originals,total = sample
    require_stopped_case(case); assert verify_case(str(case))
    assert (case/'input.eml').read_bytes() == raw
    execution = read(case/'execution.json')
    assert execution['no_egress'] and not execution['blocked_operations'], execution
    headers = read(case/'headers.json'); evidence = read(case/'url_evidence.json')
    sources = read(case/'url_source_inventory.json'); coverage = read(case/'analysis_coverage.json')
    assert headers['urls'] == targets, headers['urls']
    assert headers['url_evidence'] == evidence
    assert [item.get('source_url',item['url']) for item in evidence] == originals
    # Distinct original encoded/refanged fields can share a target. Keep every
    # provenance record while comparing the unique network destination list.
    assert list(dict.fromkeys(item['url'] for item in evidence if item['network_target'])) == targets
    assert sources['unmapped_evidence_count'] == 0
    assert sources['total_link_count'] == total
    assert sources['inventoried_link_count'] == min(total,4096)
    assert sources['omitted_link_count'] == max(0,total-4096)
    assert sources['status'] == ('limited' if total>4096 else 'completed')
    for source in sources['sources']:
        if source['kind'] != 'mime_body': continue
        assert source['representation'] == 'html_parser_derived_url_candidate_views'
        assert source['derivation'] == {'method':'paw_html_url_candidate_views_v5','persisted':False}
        text = source['derived_from']; data = (case/text['text_path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == text['text_sha256']
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    html = [part.get_payload(decode=True) for part in parsed.walk() if part.get_content_type()=='text/html']
    bodies = read(case/'mime_body_evidence.json')['parts']
    assert [(case/item['payload_path']).read_bytes() for item in bodies] == html
    assert coverage == read(case/'report/score.json')['coverage']
    assert coverage['stages']['url_sources']['total_link_count'] == total
    if not targets and evidence: assert coverage['stages']['url_interpretation']['status'] == 'partial'
    assert 'resource selection are not evaluated' in coverage['stages']['url_interpretation']['limitation']
    return evidence,sources


def check_zip(archive,case,prefix=''):
    names = ['input.eml','headers.json','url_evidence.json','url_source_inventory.json',
             'mime_body_evidence.json','mime_cid_inventory.json','deobfuscation_results.json',
             'analysis_coverage.json','report/score.json',
             'report/technical.md','report/executive.md']
    for item in read(case/'mime_body_evidence.json')['parts']:
        names.extend([item['payload_path'],item['text_path']])
    for name in names: assert archive.read(prefix+name) == (case/name).read_bytes(), name


def main(samples=None, http_names=None, summary=None, case_check=None):
    samples = fixtures() if samples is None else samples
    http_names = (('nonnetwork.eml','encoded.eml','budget.eml','entity-invalid.eml','entity-valid.eml')
                  if http_names is None else http_names)
    env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-html-url-lists-') as temporary:
        root = Path(temporary); inputs = root/'inputs'; inputs.mkdir()
        for name,(raw,*_) in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable,'-B','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--deadline','180','--stage-timeout','60','--memory-mib','1024'],
            cwd=root,env=env,capture_output=True,timeout=210)
        assert result.returncode == 0,(result.stdout+result.stderr).decode(errors='replace')[-8000:]
        cases = {read(case/'manifest.json')['source_name']:case for case in (root/'cases').glob('case-*')}
        assert set(cases) == set(samples)
        for name,case in cases.items():
            check(case,samples[name])
            if case_check is not None: case_check(case,samples[name])
            result = subprocess.run([sys.executable,'-B','-X','utf8','-m','paw','export','--case',str(case),'--format','zip'],
                                    cwd=root,env=env,capture_output=True,timeout=30)
            assert result.returncode == 0,result.stdout+result.stderr
            with zipfile.ZipFile(str(case)+'.zip') as archive: check_zip(archive,case,case.name+'/')
            assert verify_case(str(case))
        data = root/'http'; data.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        def request(path,body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (root/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable,'-B','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--host','127.0.0.1','--port',str(port)],cwd=data,env=dict(env,PAW_DATA_DIR=str(data)),stdout=log,stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API startup failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in http_names:
                    raw = samples[name][0]; boundary = 'html-list-upload'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
                              +raw+f'\r\n--{boundary}--\r\n'.encode())
                    path = json.loads(request('/api/upload',upload,'multipart/form-data; boundary='+boundary))['path']
                    job = json.loads(request('/api/analyze',json.dumps({'file_path':path,'profile':'strict',
                        'options':{'no_egress':True},'limits':{'wall_seconds':120,'stage_seconds':60}}).encode()))['analysis_id']
                    end = time.monotonic()+140
                    while time.monotonic()<end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case = data/'cases'/state['case_ids'][0]; evidence,sources = check(case,samples[name])
                    if case_check is not None: case_check(case,samples[name])
                    detail = json.loads(request('/api/cases/'+case.name))
                    assert detail['url_evidence']==evidence and detail['url_source_inventory']==sources
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive: check_zip(archive,case)
                    assert verify_case(str(case))
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print(f'PASS: {len(samples)} full no-egress CLI cases and {len(http_names)} loopback HTTP workers; '+(summary or
          'list separators versus resource commas, '
          'descriptor/nonnetwork exclusion, refanged/encoded/invalid/limited original tokens, ordinary comma literals, '
          'entity-decoded invalid delimiters versus legal apostrophes/percent escapes, '
          'independent MIME documents, source v5, exact 5000/4096/904 link accounting, raw/body bytes, coverage, '
          'stopped owners, seals and CLI/HTTP ZIP parity. Descriptors/resource selection are not evaluated; fixtures are not accuracy labels.'))


if __name__=='__main__':
    main()
