"""Actual offline observer -> score -> report/draft/index/API/ZIP contracts."""
import io
import json
import os
from contextlib import closing
from email.message import EmailMessage
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

from markdown_it import MarkdownIt

REPO = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def fixtures():
    samples = {
        'ordinary.eml':['<form><input name="literal"></form><script>console.log("inert")</script>'],
        'dimensions.eml':['<iframe src="https://example.invalid/"></iframe>'
                          '<iframe src="https://example.invalid/" width height="4"></iframe>'],
        'record-limits.eml':['<div style="display:none">hidden</div>'*270+
                             '<form></form>'*270+'<iframe></iframe>'*270+
                             '<script>eval("inert")</script>'*270],
        'input-limits.eml':['<form>'+'<input type="hidden" value="http-literal">'*1030+'</form>'],
        'independent.eml':['<form></form>'*257, '<p>&lt;form&gt;literal&lt;/form&gt;</p>'],
        'no-html.eml':[],
    }
    result = {}
    for name, documents in samples.items():
        message = EmailMessage(); message['From']='regression@example.invalid'; message['To']='recipient@example.invalid'
        message['Subject']='Constructed observer contract, not accuracy ground truth'
        if len(documents) == 1:
            message.set_content(documents[0], subtype='html')
        else:
            message.set_content('Inert MIME document fixture')
            for document in documents:
                part = EmailMessage(); part.set_content(document, subtype='html')
                if not message.is_multipart(): message.make_mixed()
                message.attach(part)
        result[name] = message.as_bytes()
    return result


def report_blocks(text):
    tokens = MarkdownIt('commonmark').enable('table').parse(text)
    assert not any(child.type in {'image','link_open','html_inline','html_block'}
                   for token in tokens for child in [token]+(token.children or []))
    blocks, section = {}, None
    for index, token in enumerate(tokens):
        if token.type == 'heading_open' and token.tag == 'h2': section = tokens[index+1].content
        elif token.type == 'fence' and token.info == 'json': blocks[section] = json.loads(token.content)
    return blocks


def check_case(case, original, full=False):
    from paw.core.verify import verify_case
    assert (case/'input.eml').read_bytes() == original
    assert verify_case(str(case))
    assert read(case/'execution.json')['no_egress'] is True
    deob = read(case/'deobfuscation_results.json')
    assert read(case/'headers.json')['deobfuscation_analysis'] == deob
    coverage = read(case/'analysis_coverage.json')
    score = read(case/'report/score.json')
    summary = coverage['stages']['html_observations']
    assert summary == deob['coverage']['html']
    assert coverage == score['coverage']
    assert summary == report_blocks((case/'report/executive.md').read_text(encoding='utf-8'))['HTML observation coverage']
    technical = report_blocks((case/'report/technical.md').read_text(encoding='utf-8'))
    assert technical['Deobfuscation Analysis'] == deob
    assert score['score_components']['deobfuscation_heuristics'] == 0
    assert score['score_components']['verified_authentication_failures'] == 0
    assert score['raw_score'] == score['decision_score'] == .05 and score['decision']=='Inconclusive'
    html = deob['deobfuscated_artifacts'].get('html', {})
    documents = html.get('documents', [html] if html else [])
    for document, row in zip(documents, summary['documents']):
        assert document['original_html'] == document['final_html']
        assert row['observers'] == document['observer_coverage']
        source = row['source']
        assert (case/source['text_path']).read_text(encoding='utf-8') == document['original_html']
        assert document['suspicion_score'] == 0 and document['risk_detection']=='not_evaluated'
    name = read(case/'manifest.json')['source_name']
    if name == 'dimensions.eml':
        assert html['iframe_analysis']['suspicious_count'] == 0
    elif name == 'record-limits.eml':
        for row in summary['documents'][0]['observers'].values():
            assert (row['observed_count'],row['inventoried_count'],row['omitted_count']) == (270,256,14)
            assert row['status']=='partial'
    elif name == 'input-limits.eml':
        row = summary['documents'][0]['observers']['forms']
        assert (row['observed_input_count'],row['inventoried_input_count'],row['omitted_input_count']) == (1030,1024,6)
    elif name == 'independent.eml':
        assert [row['status'] for row in summary['documents']] == ['partial','descriptive_only']
    elif name == 'no-html.eml':
        assert summary['status']=='not_evaluated' and summary['document_count']==0
    if full:
        assert read(case/'package/xarf_report.json')['assessment'] == score
        from email import policy
        from email.parser import BytesParser
        draft = BytesParser(policy=policy.default).parsebytes((case/'package/arf_report.eml').read_bytes())
        details = next(part for part in draft.walk() if part.get_filename()=='paw-review-draft.json')
        assert json.loads(details.get_payload(decode=True))['assessment'] == score
    with closing(sqlite3.connect(case.parent/'index.db')) as connection:
        row = connection.execute('SELECT score FROM cases WHERE id=?',(case.name.removeprefix('case-'),)).fetchone()
        assert row[0] == score['score']
    return summary


def check_zip(archive, case, raw, prefix=''):
    assert archive.read(prefix+'input.eml') == raw
    for name in ('analysis_coverage.json','report/score.json','report/executive.md','report/technical.md',
                 'deobfuscation_results.json','headers.json','evidence/merkle_index.json'):
        assert archive.read(prefix+name) == (case/name).read_bytes()


def main():
    samples = fixtures()
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-observers-') as temporary:
        root = Path(temporary); inputs = root/'inputs'; inputs.mkdir()
        for name, raw in samples.items(): (inputs/name).write_bytes(raw)
        process = subprocess.run([sys.executable,'-B','-P','-m','paw','full',str(inputs),'--no-egress',
            '--lang','en','--deadline','180','--stage-timeout','60'],cwd=root,env=env,capture_output=True,timeout=210)
        assert process.returncode == 0, (process.stdout+process.stderr).decode(errors='replace')[-6000:]
        cases = {read(case/'manifest.json')['source_name']:case for case in (root/'cases').glob('case-*')}
        assert set(cases)==set(samples)
        for name, case in cases.items():
            check_case(case, samples[name], full=True)
            result = subprocess.run([sys.executable,'-B','-P','-m','paw','export','--case',str(case),
                '--format','zip'],cwd=root,env=env,capture_output=True,timeout=30)
            assert result.returncode==0, result.stdout+result.stderr
            with zipfile.ZipFile(str(case)+'.zip') as archive: check_zip(archive,case,samples[name],case.name+'/')
        data=root/'http'; data.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
        def request(path, body=None, content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=body,
                    headers={'Content-Type':content_type}),timeout=15) as response: return response.read()
        with (root/'http.log').open('wb') as log:
            server=subprocess.Popen([sys.executable,'-B','-P','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],cwd=data,
                env=dict(env,PAW_DATA_DIR=str(data)),stdout=log,stderr=log)
            try:
                end=time.monotonic()+30
                while time.monotonic()<end:
                    assert server.poll() is None, 'API bootstrap failed'
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('dimensions.eml','record-limits.eml','independent.eml','no-html.eml'):
                    raw=samples[name]; boundary='html-observer-fixture'
                    upload=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                        'Content-Type: message/rfc822\r\n\r\n').encode()+raw+f'\r\n--{boundary}--\r\n'.encode()
                    path=json.loads(request('/api/upload',upload,'multipart/form-data; boundary='+boundary))['path']
                    job=json.loads(request('/api/analyze',json.dumps({'file_path':path,'profile':'strict',
                        'options':{'no_egress':True},'limits':{'wall_seconds':120,'stage_seconds':60}}).encode()))['analysis_id']
                    end=time.monotonic()+140
                    while time.monotonic()<end:
                        state=json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case=data/'cases'/state['case_ids'][0]
                    summary=check_case(case,raw)
                    detail=json.loads(request('/api/cases/'+case.name))
                    assert detail['coverage']['stages']['html_observations']==summary
                    assert detail['deobfuscation']==read(case/'deobfuscation_results.json')
                    assert detail['score']==read(case/'report/score.json')
                    assert detail['executive_report']==(case/'report/executive.md').read_text(encoding='utf-8')
                    listing=json.loads(request('/api/cases'))['cases']
                    assert next(row for row in listing if row['case_id']==case.name)['summary']==detail['score']
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        check_zip(archive,case,raw)
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: six actual full no-egress CLI cases / four owned-loopback HTTP workers; observer limits, '
          'independent document coverage, literal reports, zero HTML risk, draft/index/API/ZIP parity, '
          'original bytes, stopped owners and seals. Constructed fixtures are not accuracy evidence.')


if __name__=='__main__':
    sys.path.insert(0,str(REPO))
    main()
