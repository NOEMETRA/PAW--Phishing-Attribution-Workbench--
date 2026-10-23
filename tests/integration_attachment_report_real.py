"""Actual extraction/report publication; passive CommonMark/GFM parsing only."""
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
import urllib.parse
import urllib.request
import zipfile

from markdown_it import MarkdownIt

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def message(names):
    raw = (b'From: sender@example.invalid\r\nSubject: Inert attachment report fixture\r\n'
           b'Received: from relay.invalid (helo=![helo](https://helo.invalid/pixel) '
           b'<img src="https://received.invalid/pixel"> ````) by mx.invalid; '
           b'Thu, 22 Oct 2026 10:00:00 +0000\r\n'
           b'Authentication-Results: mx.invalid (![auth](https://auth.invalid/pixel) '
           b'<b>literal claim</b> ````); spf=none\r\n'
           b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="report-fixture"\r\n\r\n'
           b'--report-fixture\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
           b'Explicit presentation fixture. ![body](https://body.invalid/pixel) '
           b'<img src="https://body.invalid/pixel">\r\n````\r\n# literal source heading\r\n')
    for index, name in enumerate(names):
        raw += (b'--report-fixture\r\nContent-Type: application/octet-stream\r\n'
                b"Content-Disposition: attachment; filename*=utf-8''"
                + urllib.parse.quote(name, safe='').encode('ascii')
                + b'\r\n\r\nInert payload ' + str(index).encode('ascii') + b'\r\n')
    return raw + b'--report-fixture--\r\n'


def check_report_evidence(case):
    reports = {name: (case/'report'/name).read_text(encoding='utf-8')
               for name in ('executive.md', 'technical.md')}
    parsed = {name: MarkdownIt('commonmark').enable('table').parse(text)
              for name, text in reports.items()}
    active = [(name, child.type, child.content)
              for name, tokens in parsed.items() for token in tokens
              for child in ([token] + (token.children or []))
              if child.type in {'image', 'link_open', 'html_inline', 'html_block'}]
    assert not active, active
    blocks, section = {}, None
    tokens = parsed['technical.md']
    for index, token in enumerate(tokens):
        if token.type == 'heading_open' and token.tag == 'h2':
            section = tokens[index+1].content
        elif token.type == 'fence' and token.info == 'json':
            assert section not in blocks, section
            blocks[section] = json.loads(token.content)
    assert blocks['Auth Alignment'] == read(case/'auth.json')
    assert blocks['Forgery Checks'] == read(case/'received_anomalies.json')
    assert blocks['Deobfuscation Analysis'] == read(case/'headers.json')['deobfuscation_analysis']
    origin = read(case/'origin.json')
    domain = read(case/'domains.json')['from_domain']
    candidate = [origin['ip'], origin['asn'], origin['org'], origin['cc']]
    executive_values = [json.loads(child.content)
                        for token in parsed['executive.md'] for child in (token.children or [])
                        if child.type == 'code_inline']
    assert executive_values == candidate*2 + [read(case/'auth.json')['from_domain'] or '',
        domain.get('registrar'), domain.get('created'), domain.get('nrd_days'),
        domain.get('ns', []), domain.get('mx', [])], executive_values
    assert read(case/'analysis_coverage.json') == read(case/'report/score.json')['coverage']
    hops = read(case/'received_path.json')['ordered_hops']
    codes = [child.content for token in tokens for child in (token.children or [])
             if child.type == 'code_inline']
    for hop in hops:
        for field in ('by', 'from', 'ip', 'date', 'helo', 'ptr', 'skew_s',
                      'fqdn_ok', 'helo_ptr_match', 'role'):
            assert json.dumps(hop.get(field), ensure_ascii=True) in codes, (field, codes)
    assert 'unverified' in reports['technical.md'].lower()
    assert 'Missing checks do not establish safety' in reports['executive.md']


def check_case(case, raw, names):
    require_stopped_case(case)
    assert verify_case(str(case))
    assert (case/'input.eml').read_bytes() == raw
    execution = read(case/'execution.json')
    assert execution['no_egress'] and not execution['blocked_operations'], execution
    check_report_evidence(case)
    metadata = read(case/'attachments.json')
    parts = list(BytesParser(policy=policy.default).parsebytes(raw).iter_attachments())
    assert len(parts) == len(metadata) == len(names)
    for item, part, name in zip(metadata, parts, names):
        payload = part.get_payload(decode=True)
        assert item['filename'] == part.get_filename() == name
        assert item['mime'] == part.get_content_type()
        assert item['sha256'] == hashlib.sha256(payload).hexdigest()
        assert item['size'] == len(payload)
        assert (case/item['evidence_path']).resolve().is_relative_to((case/'attachments').resolve())
        assert (case/item['evidence_path']).read_bytes() == payload
    report = (case/'report/technical.md').read_text(encoding='utf-8')
    section = report.split('\n## Attachments (metadata-only)\n')
    if not names:
        assert len(section) == 1
        return metadata
    assert len(section) == 2
    tokens = MarkdownIt('commonmark').enable('table').parse(section[1])
    assert sum(token.type == 'table_open' for token in tokens) == 1
    assert not any(token.type == 'heading_open' for token in tokens)
    rows, row, in_body = [], None, False
    for token in tokens:
        if token.type == 'tbody_open': in_body = True
        elif token.type == 'tbody_close': in_body = False
        elif in_body and token.type == 'tr_open': row = []
        elif in_body and token.type == 'inline': row.append(token)
        elif in_body and token.type == 'tr_close': rows.append(row)
    assert len(rows) == len(metadata), [len(row) for row in rows]
    for row, item in zip(rows, metadata):
        assert len(row) == 5, [cell.content for cell in row]
        for cell, key in ((row[0], 'filename'), (row[2], 'mime')):
            assert [child.type for child in cell.children] == ['code_inline'], cell
            assert json.loads(cell.children[0].content) == item[key]
        assert row[1].content == str(item['size'])
        assert row[3].content == 'not evaluated'
        assert row[4].content == item['sha256'][:16] + '...'
        assert all(child.type not in {'link_open', 'image', 'html_inline'}
                   for cell in row for child in cell.children)
    return metadata


def check_zip(archive, case, raw, metadata, prefix=''):
    assert archive.read(prefix+'input.eml') == raw
    for name in ('report/technical.md', 'report/executive.md', 'auth.json', 'origin.json', 'domains.json',
                 'received_path.json', 'received_anomalies.json', 'headers.json',
                 'analysis_coverage.json', 'report/score.json'):
        assert archive.read(prefix+name) == (case/name).read_bytes(), name
    assert json.loads(archive.read(prefix+'attachments.json')) == metadata
    for item in metadata:
        assert archive.read(prefix+item['evidence_path']) == (case/item['evidence_path']).read_bytes()


def main():
    names = ['invoice|declared.txt', 'invoice\n\n## PAW AUDIT FIXTURE HEADING\n\nsuffix.txt',
             *['backslash'+('\\'*count)+'|tail.txt' for count in range(1, 4)],
             'literal ` and ```` ticks.txt', '![image](asset) [link](target).txt',
             '<b>literal</b>&copy;.txt', 'ricevuta città 日本語.txt', 'space\r\n\ttail.txt']
    samples = {'crafted.eml': (message(names), names),
               'ordinary.eml': (message(['invoice.txt']), ['invoice.txt']),
               'original.eml': (next((REPO/'inbox').glob('*.eml')).read_bytes(), [])}
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-attachment-report-') as temporary:
        root = Path(os.environ.get('PAW_VERIFICATION_DIR', temporary)).resolve()
        root.mkdir(parents=True, exist_ok=True)
        inputs = root/'inputs'; inputs.mkdir()
        for name, (raw, _) in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'full', str(inputs),
            '--no-egress', '--deadline', '90', '--stage-timeout', '45'],
            cwd=root, env=env, capture_output=True, timeout=120)
        (root/'full.log').write_bytes(result.stdout+result.stderr)
        assert result.returncode == 0, (result.stdout+result.stderr).decode(errors='replace')
        control, = (path for path in (root/'jobs').iterdir() if path.is_dir())
        assert read(control/'supervisor.json')['tree_stopped']
        cases = {read(case/'manifest.json')['source_name']: case
                 for case in (root/'cases').glob('case-*') if case.is_dir()}
        assert set(cases) == set(samples)
        for name, (raw, expected_names) in samples.items():
            case = cases[name]; metadata = check_case(case, raw, expected_names)
            exported = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'export',
                '--case', str(case), '--format', 'zip'], cwd=root, env=env, capture_output=True, timeout=30)
            assert exported.returncode == 0, exported.stdout+exported.stderr
            with zipfile.ZipFile(str(case)+'.zip') as archive:
                check_zip(archive, case, raw, metadata, case.name+'/')
            assert verify_case(str(case))

        data = root/'http'; data.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        def request(path, body=None, content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body, headers={'Content-Type': content_type}), timeout=15) as response:
                return response.read()
        with (root/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable, '-X', 'utf8', '-m', 'uvicorn', 'paw.web.api:app',
                '--host', '127.0.0.1', '--port', str(port)], cwd=data,
                env=dict(env, PAW_DATA_DIR=str(data)), stdout=log, stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic() < end:
                    if server.poll() is not None: raise AssertionError('API startup failed')
                    try: request('/health'); break
                    except (urllib.error.URLError, TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                raw, expected_names = samples['crafted.eml']; boundary = 'attachment-report-upload'
                upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="crafted.eml"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
                          +raw+f'\r\n--{boundary}--\r\n'.encode())
                uploaded = json.loads(request('/api/upload', upload, 'multipart/form-data; boundary='+boundary))
                job = json.loads(request('/api/analyze', json.dumps({'file_path': uploaded['path'],
                    'profile': 'strict', 'options': {'no_egress': True}}).encode()))['analysis_id']
                end = time.monotonic()+120
                while time.monotonic() < end:
                    state = json.loads(request('/api/analysis/'+job))
                    if state['status'] not in {'queued', 'running'}: break
                    time.sleep(.1)
                else: raise TimeoutError('API analysis')
                assert state['status'] == 'completed' and state['supervisor']['tree_stopped'], state
                case = data/'cases'/state['case_ids'][0]
                metadata = check_case(case, raw, expected_names)
                detail = json.loads(request('/api/cases/'+case.name))
                assert detail['attachments'] == metadata
                assert detail['technical_report'] == (case/'report/technical.md').read_text(encoding='utf-8')
                assert detail['executive_report'] == (case/'report/executive.md').read_text(encoding='utf-8')
                with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                    check_zip(archive, case, raw, metadata)
                assert verify_case(str(case))
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: three actual offline full CLI cases and one loopback HTTP worker; '
          'literal Received/authentication/deobfuscation observations and filename/MIME table cells; '
          'JSON round trips, no source-created images/links/HTML, five columns, all rows/digests, original MIME, '
          'attachment payloads/metadata, stopped owners, seals, detail and CLI/HTTP ZIP bytes. '
          'Passive Markdown parsing only; constructed fixtures are not accuracy labels.')


if __name__ == '__main__':
    main()
