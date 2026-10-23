"""Real no-egress MIME selection, preservation, coverage and publication."""
from email import policy
from email.parser import BytesParser
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

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def fixtures():
    base = b'From: fixture@example.invalid\r\nSubject: MIME context fixture\r\n'
    body = b'https://body.invalid/\r\n'
    plain = b'Content-Type: text/plain\r\n'
    duplicate = plain+b'Content-Type: text/html\r\n'
    container = b'Content-Type: multipart/mixed; boundary=a\r\n'
    leaf = plain+b'\r\n'+body
    nested = container+plain+b'\r\n--a\r\n'+leaf+b'--a--\r\n'
    # Explicit sets describe the partial selections and inherited selections;
    # expected bytes/first header positions are read independently below.
    cases = {
        'control.eml': (plain+b'\r\n'+body, set(), set()),
        'default.eml': (b'\r\n'+body, set(), set()),
        'type.eml': (duplicate+b'\r\n'+body, {'0'}, set()),
        'same-type.eml': (plain+plain+b'\r\n'+body, {'0'}, set()),
        'inline.eml': (plain+b'Content-Disposition: inline\r\nContent-Disposition: attachment\r\n\r\n'+body, {'0'}, set()),
        'attachment.eml': (duplicate+b'Content-Disposition: attachment\r\nContent-Disposition: inline\r\n\r\n'+body, {'0'}, set()),
        'container.eml': (container+plain+b'\r\n--a\r\n'+leaf+b'--a--\r\n', {'0', '0.0'}, {'0.0'}),
        'disposition-container.eml': (container+b'Content-Disposition: inline\r\nContent-Disposition: attachment\r\n\r\n--a\r\n'+leaf+b'--a--\r\n', {'0', '0.0'}, {'0.0'}),
        'boundary-parameters.eml': (b'Content-Type: multipart/mixed; boundary=a; boundary=b\r\n\r\n--a\r\n'+leaf+b'--a--\r\n', {'0', '0.0'}, {'0.0'}),
        'truncated-container.eml': (container+b'\r\n--a\r\n'+leaf, {'0', '0.0'}, {'0.0'}),
        'invalid-container-transfer.eml': (container+b'Content-Transfer-Encoding: base64\r\n\r\n--a\r\n'+leaf+b'--a--\r\n', {'0', '0.0'}, {'0.0'}),
        'nested.eml': (b'Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n'+nested
                       +b'--outer\r\n'+leaf+b'--outer--\r\n', {'0.0', '0.0.0'}, {'0.0.0'}),
        'parameters.eml': (b'Content-Type: text/plain; charset=us-ascii; charset=utf-8\r\n\r\n'+body, {'0'}, set()),
        'transfer.eml': (plain+b'Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'+body, {'0'}, set()),
        'limited-headers.eml': (b'X-Other: kept\r\n'*1100+duplicate+b'\r\n'+body, {'0'}, set()),
        'embedded.eml': (b'Content-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n'+base+duplicate+b'\r\n'+body, set(), set())}
    return {name:(base+wire, partial, inherited) for name,(wire,partial,inherited) in cases.items()}


def check(case, sample):
    raw, partial, inherited = sample
    require_stopped_case(case)
    assert verify_case(str(case))
    assert (case/'input.eml').read_bytes() == raw
    execution = read(case/'execution.json')
    assert execution['no_egress'] and not execution['blocked_operations'], execution
    mime, bodies, attachments = read(case/'mime_analysis.json'), read(case/'mime_body_evidence.json'), read(case/'attachments.json')
    assert mime['status'] == ('partial' if partial else 'completed'), mime['issues']
    assert mime['context_partial_part_count'] == len(partial)
    assert mime['context_inherited_part_count'] == len(inherited)
    parsed, stack = {}, [(BytesParser(policy=policy.default).parsebytes(raw), '0')]
    while stack:
        part, identifier = stack.pop()
        parsed[identifier] = part
        payload = part.get_payload()
        if part.get_content_maintype() != 'message' and isinstance(payload, list):
            stack.extend((child, identifier+'.'+str(index)) for index,child in enumerate(payload))
    assert {p['part_id'] for p in mime['parts']} == set(parsed)
    selected = {p['part_id']:p for p in mime['parts']}
    for identifier, part in parsed.items():
        item = selected[identifier]; context = item['mime_context']
        assert context['status'] == ('partial' if identifier in partial else 'completed')
        assert bool(context['partial_ancestor_part_ids']) == (identifier in inherited)
        assert all(identifier.startswith(parent+'.') for parent in context['partial_ancestor_part_ids'])
        assert not context['verified']
        assert context['parser_structure_defect_count'] == len(part.defects)
        assert item['content_type'] == part.get_content_type()
        assert item['disposition'] == part.get_content_disposition()
        names = [name.lower() for name,_ in part.raw_items()]
        for name, field in context['headers'].items():
            assert field['field_count'] == names.count(name)
            assert field['selected_header_index'] == (names.index(name) if name in names else None)
    for item in bodies['parts']+attachments:
        identifier = item['part_id']; part = parsed[identifier]
        assert item['mime_context'] == selected[identifier]['mime_context']
        if identifier in partial: assert item['status'] == 'partial'
        path = item.get('payload_path', item.get('evidence_path'))
        expected = part.get_payload(decode=True)
        if part.get_content_maintype() == 'message':
            expected = b'\r\n'.join(child.as_bytes() for child in part.get_payload())
        assert (case/path).read_bytes() == expected
        assert item['sha256'] == hashlib.sha256(expected).hexdigest()
    assert bodies['status'] == ('partial' if any(p['part_id'] in partial for p in bodies['parts']) else 'completed')
    coverage = read(case/'analysis_coverage.json'); score = read(case/'report/score.json')
    assert coverage == score['coverage']
    assert coverage['stages']['mime_parsing']['status'] == mime['status']
    assert coverage['stages']['mime_parsing']['context_partial_part_count'] == len(partial)
    assert coverage['stages']['mime_body_evidence']['status'] == bodies['status']
    if attachments and partial: assert coverage['stages']['attachment_metadata']['status'] == 'partial'
    report = (case/'report/technical.md').read_text(encoding='utf-8')
    assert 'partial selected contexts: '+str(len(partial))+';' in report
    assert 'inherited partial contexts: '+str(len(inherited)) in report
    assert 'Alternative interpretations are not evaluated' in report
    if read(case/'manifest.json')['source_name'] == 'limited-headers.eml':
        inventory = read(case/'mime_header_inventory.json')['parts'][0]['headers']
        assert inventory['omitted_field_count'] > 0
        assert not any(f['normalized_name'] == 'content-type' for f in inventory['fields'])
        assert selected['0']['mime_context']['headers']['content-type']['selected_header_index'] == 1102
    return score


ARTIFACTS = ['input.eml', 'mime_analysis.json', 'mime_body_evidence.json', 'attachments.json',
             'mime_header_inventory.json', 'analysis_coverage.json', 'report/score.json', 'report/technical.md']


def check_zip(archive, case, prefix=''):
    for name in ARTIFACTS:
        assert archive.read(prefix+name) == (case/name).read_bytes(), name


def main():
    samples = fixtures()
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-mime-context-') as temporary:
        root = Path(temporary); inputs = root/'inputs'; inputs.mkdir()
        for name,(raw,_,_) in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable,'-B','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--deadline','120','--stage-timeout','60'], cwd=root,env=env,capture_output=True,timeout=150)
        assert result.returncode == 0, (result.stdout+result.stderr).decode(errors='replace')[-8000:]
        cases = {read(case/'manifest.json')['source_name']:case for case in (root/'cases').glob('case-*')}
        assert set(cases) == set(samples)
        scores = {}
        for name, case in cases.items():
            scores[name] = check(case, samples[name])
            result = subprocess.run([sys.executable,'-B','-X','utf8','-m','paw','export','--case',str(case),'--format','zip'],
                                    cwd=root,env=env,capture_output=True,timeout=30)
            assert result.returncode == 0, result.stdout+result.stderr
            with zipfile.ZipFile(str(case)+'.zip') as archive: check_zip(archive,case,case.name+'/')
            assert verify_case(str(case))
        for name in ('type.eml','same-type.eml','inline.eml','limited-headers.eml'):
            assert scores[name]['score_components'] == scores['control.eml']['score_components']
        data = root/'http'; data.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        def request(path, body=None, content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (root/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable,'-B','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--host','127.0.0.1','--port',str(port)],cwd=data,env=dict(env,PAW_DATA_DIR=str(data)),stdout=log,stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic() < end:
                    if server.poll() is not None: raise AssertionError('API startup failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('container.eml','truncated-container.eml','attachment.eml','limited-headers.eml'):
                    raw = samples[name][0]; boundary = 'mime-context-upload'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
                              +raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded = json.loads(request('/api/upload',upload,'multipart/form-data; boundary='+boundary))
                    job = json.loads(request('/api/analyze',json.dumps({'file_path':uploaded['path'],
                        'profile':'strict','options':{'no_egress':True}}).encode()))['analysis_id']
                    end = time.monotonic()+120
                    while time.monotonic() < end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status'] == 'completed' and state['supervisor']['tree_stopped'], state
                    case = data/'cases'/state['case_ids'][0]; check(case,samples[name])
                    detail = json.loads(request('/api/cases/'+case.name))
                    assert detail['mime'] == read(case/'mime_analysis.json')
                    assert detail['technical_report'] == (case/'report/technical.md').read_text(encoding='utf-8')
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive: check_zip(archive,case)
                    assert verify_case(str(case))
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: sixteen actual full no-egress CLI cases and four loopback HTTP workers; '
          'duplicate/defective declarations, inherited context and unaffected siblings, '
          'first-view bytes, body/attachment status, late omitted headers, source positions, '
          'no added risk contributions, coverage/report/API/ZIP parity, stopped owners and seals. '
          'Constructed fixtures are not classification truth.')


if __name__ == '__main__':
    main()
