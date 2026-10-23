"""Actual no-egress workers; source contexts specified independently in fixtures."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib, io, json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path
import urllib.error, urllib.request, zipfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.verify import verify_case


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def fixtures():
    url='https://shared-source.invalid/a?x=1&y=2'
    value=EmailMessage(policy=policy.SMTP);value['From']='outer@example.invalid';value['Subject']='Notice '+url
    value.set_content('Plain '+url+'\nAgain '+url)
    value.add_alternative('<a href="'+url.replace('&','&amp;')+'">'+url.replace('&','&amp;')+'</a>',subtype='html')
    value.add_attachment('https://attached-only.invalid/',filename='letter.txt')
    inner=EmailMessage();inner.set_content('https://embedded-only.invalid/');value.add_attachment(inner,filename='inner.eml')
    samples={'shared.eml':(value.as_bytes(),{url:{('mime_body','0.0.0',None),('mime_body','0.0.1',None),('selected_header','0','subject')}})}
    def multipart(*entities):
        return (b'From: outer@example.invalid\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n'
            +b''.join(b'--b\r\n'+entity+b'\r\n' for entity in entities)+b'--b--\r\n')
    samples['collisions.eml']=(multipart(b'Content-Type: text/plain\r\n\r\nhxxps://example[.]invalid/a',
        b'Content-Type: text/html\r\n\r\n<div data-next="aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvYQ=="></div>'),
        {'hxxps://example[.]invalid/a':{('mime_body','0.0',None)},
         'aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvYQ==':{('mime_body','0.1',None)}})
    samples['invalid.eml']=(multipart(b'Content-Type: text/plain\r\n\r\nhxxps://bad[.]invalid/%ZZ aHR0c!!!'),
        {s:{('mime_body','0.0',None)} for s in ('hxxps://bad[.]invalid/%ZZ','aHR0c!!!')})
    samples['html.eml']=(multipart(b'Content-Type: text/html\r\n\r\n<script>unclosed',
        b'Content-Type: text/html\r\n\r\n<p>https://split.invalid/<b>tail</b></p>'
        b'<a href="https://entity.invalid/?x=1&amp;y=2">go</a><!-- hxxps://comment[.]invalid/ -->'
        b'<div xmlns="https://vocabulary.invalid/"></div>',
        b'Content-Type: text/javascript\r\n\r\nconst u="https://js-source.invalid/";'),
        {**{s:{('mime_body','0.1',None)} for s in ('https://split.invalid/tail',
            'https://entity.invalid/?x=1&y=2','hxxps://comment[.]invalid/')},
         'https://js-source.invalid/':{('mime_body','0.2',None)}})
    samples['headers.eml']=(b'X-Unknown: https://unknown-only.invalid/\r\nSubject: https://first.invalid/\r\n'
        b'Subject: https://second-only.invalid/\r\nFrom: "https://display.invalid/" <outer@example.invalid>\r\n\r\nbody',
        {'https://first.invalid/':{('selected_header','0','subject')},'https://display.invalid/':{('selected_header','0','from')}})
    samples['late-header.eml']=(b'X-Kept: value\r\n'*1100+b'From: outer@example.invalid\r\n'
        b'Subject: https://late-header.invalid/\r\n\r\nbody',{'https://late-header.invalid/':{('selected_header','0','subject')}})
    samples['charset.eml']=(b'From: outer@example.invalid\r\nContent-Type: text/plain; charset=unknown-charset\r\n\r\n'
        b'\xff https://charset.invalid/',{'https://charset.invalid/':{('mime_body','0',None)}})
    samples['empty.eml']=(b'From: outer@example.invalid\r\n\r\nbody',{})
    urls=['https://limit-source.invalid/'+str(i) for i in range(100)]
    body=(' '.join(urls)).encode()
    samples['limited.eml']=(multipart(*[b'Content-Type: text/plain\r\n\r\n'+body]*50),
        {u:{('mime_body','0.'+str(i),None) for i in range(50)} for u in urls})
    return samples


def check_case(case,raw,expected):
    assert verify_case(str(case)) and (case/'input.eml').read_bytes()==raw
    execution=read(case/'execution.json');assert execution['no_egress'] and not execution['blocked_operations']
    inventory=read(case/'url_source_inventory.json');evidence=read(case/'url_evidence.json')
    assert inventory['source']=={'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()}
    assert inventory['verified'] is False and inventory['url_evidence_artifact']=='url_evidence.json'
    assert inventory['url_evidence_record_count']==len(evidence)
    assert {r.get('source_url',r['url']) for r in evidence}==set(expected)
    assert evidence==read(case/'headers.json')['url_evidence']
    sources=inventory['sources']; bodies=read(case/'mime_body_evidence.json')['parts']
    parser=BytesParser(policy=policy.default).parsebytes(raw)
    first={}
    for index,(name,_) in enumerate(parser.raw_items()):
        first.setdefault(name.lower(),index)
    assert len(sources)==len(bodies)+sum(name in first for name in ('subject','from'))
    for index,source in enumerate(sources):
        assert source['source_index']==index
        if source['kind']=='mime_body':
            body=next(b for b in bodies if b['part_id']==source['part_id'])
            text_source=source.get('derived_from',source)
            assert text_source['representation']=='per_part_charset_decoded_text'
            assert text_source['text_status']==body['text_status'] and text_source['text_path']==body['text_path']
            assert text_source['text_sha256']==body['text_sha256']
            if body['declared_mime']=='text/html':
                assert source['representation']=='html_parser_derived_url_candidate_views'
                assert source['derivation']=={'method':'paw_html_url_candidate_views_v5','persisted':False}
                assert 'text_path' not in source
            else:assert 'derived_from' not in source
            if text_source['text_status']=='captured':
                assert hashlib.sha256((case/text_source['text_path']).read_bytes()).hexdigest()==text_source['text_sha256']
        else:
            assert source['part_id']=='0' and source['header_index']==first[source['field']]
            fields=read(case/'header_inventory.json')['fields']
            field=next((f for f in fields if f['header_index']==source['header_index']),None)
            assert source['header_inventory_status']==(field['parsed_status'] if field else 'not_inventoried')
    all_links=[]
    for source in sources:
        context=(source['kind'],source['part_id'],source.get('field'))
        for index,record in enumerate(evidence):
            if context in expected[record.get('source_url',record['url'])]:
                all_links.append({'url_evidence_index':index,'source_index':source['source_index']})
    # Per-source extraction may enumerate observed and encoded candidates in a
    # different order from the final URL inventory. Compare sets, then require
    # a retained prefix of the independently specified source context sequence.
    actual=inventory['links']; limit=inventory['limits']['max_links']
    assert len(actual)==min(len(all_links),limit)
    assert all(link in all_links for link in actual) and len({tuple(link.values()) for link in actual})==len(actual)
    if len(all_links)<=limit:assert {tuple(x.values()) for x in actual}=={tuple(x.values()) for x in all_links}
    else:
        # This fixture's plain sources all enumerate targets in the same order.
        assert actual==all_links[:limit]
    assert inventory['total_link_count']==len(all_links)
    assert inventory['inventoried_link_count']==len(actual)
    assert inventory['omitted_link_count']==len(all_links)-len(actual)
    assert inventory['mapped_evidence_count']==len(evidence) and inventory['unmapped_evidence_count']==0
    assert inventory['unmapped_evidence_indexes']==[] and inventory['omitted_unmapped_index_count']==0
    assert inventory['status']==('limited' if len(all_links)>limit else 'completed')
    coverage=read(case/'analysis_coverage.json')['stages']['url_sources']
    assert coverage==read(case/'report/score.json')['coverage']['stages']['url_sources']
    for key in ('status','scope','verified','source_count','total_link_count','inventoried_link_count',
                'omitted_link_count','mapped_evidence_count','unmapped_evidence_count'):
        assert coverage[key]==inventory[key]
    assert coverage['artifact']=='url_source_inventory.json'
    assert 'url_source_inventory.json' in (case/'report/technical.md').read_text(encoding='utf-8')
    return inventory,evidence


def main():
    samples=fixtures();env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-url-sources-',dir=REPO.parent) as temporary:
        base=Path(temporary).resolve();inputs=base/'inputs';inputs.mkdir()
        for name,(raw,_) in samples.items():(inputs/name).write_bytes(raw)
        run=subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','180','--stage-timeout','60','--memory-mib','1024'],
            cwd=base,env=env,capture_output=True,timeout=210)
        assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-6000:]
        cases=list((base/'cases').glob('case-*'));assert len(cases)==len(samples)
        for case in cases:check_case(case,*samples[read(case/'manifest.json')['source_name']])
        root=base/'http';root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:return response.read()
        with (base/'http.log').open('wb') as log:
            server=subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],
                cwd=root,env=dict(env,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
            try:
                end=time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None:raise AssertionError('API bootstrap failed')
                    try:request('/health');break
                    except (urllib.error.URLError,TimeoutError):time.sleep(.1)
                else:raise TimeoutError('API startup')
                for name in ('shared.eml','collisions.eml','invalid.eml','late-header.eml','limited.eml'):
                    raw,expected=samples[name];boundary='paw_url_sources_fixture'
                    upload=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded=json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload={'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':120.0,'stage_seconds':60.0}}
                    job=json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end=time.monotonic()+140
                    while time.monotonic()<end:
                        state=json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}:break
                        time.sleep(.1)
                    else:raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case=root/'cases'/state['case_ids'][0];inventory,evidence=check_case(case,raw,expected)
                    detail=json.loads(request('/api/cases/'+case.name))
                    assert detail['url_source_inventory']==inventory and detail['url_evidence']==evidence
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('input.eml')==raw
                        assert json.loads(archive.read('url_source_inventory.json'))==inventory
                        assert json.loads(archive.read('url_evidence.json'))==evidence
                        for source in inventory['sources']:
                            assert archive.read(source['artifact'])==(case/source['artifact']).read_bytes()
                            text_source=source.get('derived_from',source)
                            if text_source.get('text_path'):assert archive.read(text_source['text_path'])==(case/text_source['text_path']).read_bytes()
            finally:
                server.terminate()
                try:server.wait(timeout=15)
                except subprocess.TimeoutExpired:server.kill();server.wait(timeout=15)
    print('PASS: nine actual full CLI cases and five loopback HTTP workers; repeated sources, original candidates, per-part/header links, exact 5000-link accounting/4096-prefix, charset/field limits, attached scope, no-egress, API/ZIP and seals. Constructed inputs are not classification truth.')


if __name__=='__main__':main()
