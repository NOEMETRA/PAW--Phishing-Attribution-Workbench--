"""Actual offline attachment capability/omission publication, not format detection."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from markdown_it import MarkdownIt

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case

UNEVALUATED = ['document_text', 'url_extraction', 'resource_resolution',
               'embedded_message_body', 'archive_member_content', 'decryption']
ARCHIVE_FIELDS = ('status', 'reason', 'scope', 'verified', 'entry_count',
                  'inventoried_entry_count', 'omitted_entry_count', 'limited_name_count',
                  'issues', 'limits', 'macro_container_entries_scope')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


def message():
    msg = EmailMessage(policy=policy.SMTP)
    msg['From'] = 'outer@example.invalid'
    msg['Subject'] = 'Constructed attachment capability contracts'
    msg.set_content('Outer body without resource targets')
    return msg


def fixtures():
    rows = {'none.eml': message()}
    opaque = message()
    # These are inert format-shaped bytes, not validated documents or malware.
    for name, mime, data in [
        ('letter.txt', 'text/plain', b'Attached https://attached-only.invalid/text'),
        ('letter.html', 'text/html', b'<a href="https://attached-only.invalid/html">x</a>'),
        ('sheet.css', 'text/css', b'a{background:url(https://attached-only.invalid/css)}'),
        ('notice.pdf', 'application/pdf', b'%PDF-1.4\n% inert https://attached-only.invalid/pdf'),
        ('document.doc', 'application/msword', b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 inert VBA Project'),
        ('archive.rar', 'application/vnd.rar', b'Rar!\x1a\x07\x00 inert payload'),
        ('archive.7z', 'application/x-7z-compressed', b'7z\xbc\xaf\x27\x1c inert payload'),
        ('archive.gz', 'application/gzip', b'\x1f\x8b inert payload'),
        ('event.ics', 'text/calendar', b'BEGIN:VCALENDAR\nURL:https://attached-only.invalid/calendar'),
        ('empty.bin', 'application/octet-stream', b''),
        ('claimed.png', 'image/png', b'Plain bytes, not independently detected as PNG'),
    ]:
        main, sub = mime.split('/')
        opaque.add_attachment(data, maintype=main, subtype=sub, filename=name)
    rows['opaque.eml'] = opaque
    inline = message()
    inline.add_attachment(b'<img src="https://inline-only.invalid/a">', maintype='text',
                          subtype='html', disposition='inline', filename='inline.html')
    inline.add_attachment(b'a{background:url(https://inline-only.invalid/b)}',
                          maintype='text', subtype='css')
    rows['inline.eml'] = inline
    inner = message()
    inner.replace_header('From', 'inner@unverified.invalid')
    inner.set_content('<a href="https://inner-only.invalid/a">inner</a>', subtype='html')
    embedded = message()
    embedded.add_attachment(inner, filename='inner.eml')
    rows['embedded.eml'] = embedded
    limited = message()
    limited.add_attachment(zip_bytes([(f'f{i}.txt', b'x') for i in range(1001)]),
                           maintype='application', subtype='zip', filename='entries.zip')
    limited.add_attachment(zip_bytes([('n'*5000, b'x')]), maintype='application',
                           subtype='zip', filename='names.zip')
    rows['zip-limits.eml'] = limited
    nested = zip_bytes([('inner.zip', zip_bytes([('inner.html', b'https://member-only.invalid/a')]))])
    declared = bytearray(zip_bytes([('encrypted.txt', b'Inert bytes; declaration only')]))
    central = declared.index(b'PK\x01\x02')
    struct.pack_into('<H', declared, central+8, 1)
    struct.pack_into('<H', declared, central+10, 99)
    special = message()
    for name, data in [('nested.zip', nested), ('declared.zip', bytes(declared)),
                       ('prefixed.exe', b'MZ inert prefix'+nested)]:
        special.add_attachment(data, maintype='application', subtype='zip', filename=name)
    rows['zip-content.eml'] = special
    good = zip_bytes([('member.html', b'https://member-only.invalid/b')])
    unsupported = bytearray(good)
    struct.pack_into('<H', unsupported, unsupported.index(b'PK\x01\x02')+6, 99)
    errors = message()
    for data in (good, b'PK\x03\x04broken', bytes(unsupported), good):
        errors.add_attachment(data, maintype='application', subtype='zip', filename='same.zip')
    rows['zip-errors.eml'] = errors
    related = message()
    related.set_content('<img src="logo.png"><img src="cid:logo@local.invalid">'
        '<div style="background:url(cid:logo@local.invalid)"></div>'
        '<img srcset="cid:logo@local.invalid 1x">', subtype='html')
    related['Content-Location'] = 'https://location-only.invalid/dir/page.html'
    related.add_related(b'Benign resource bytes', maintype='image', subtype='png',
                        cid='<logo@local.invalid>', filename='logo.png')
    rows['related.eml'] = related
    return {name: msg.as_bytes() for name, msg in rows.items()}


def check_case(case, raw):
    require_stopped_case(case)
    assert verify_case(str(case))
    assert (case/'input.eml').read_bytes() == raw
    execution = read(case/'execution.json')
    assert execution['no_egress'] and not execution['blocked_operations']
    parsed = BytesParser(policy=policy.default).parsebytes(raw)
    # Constructed messages have one outer body followed by flat attachments.
    expected = parsed.get_payload()[1:] if parsed.is_multipart() else []
    items = read(case/'attachments.json')
    assert len(items) == len(expected)
    for index, (item, part) in enumerate(zip(items, expected), 1):
        assert item['part_id'] == f'0.{index}'
        assert item['declared_mime'] == item['mime'] == part.get_content_type()
        assert item['filename'] == (part.get_filename() or '(unnamed)')
        payload = (b'\r\n'.join(child.as_bytes() for child in part.get_payload())
                   if part.get_content_maintype() == 'message' else part.get_payload(decode=True))
        assert item['size'] == len(payload)
        assert item['sha256'] == hashlib.sha256(payload).hexdigest()
        path = case/item['evidence_path']
        assert path.resolve().is_relative_to((case/'attachments').resolve())
        assert path.read_bytes() == payload
        content = item['content_analysis']
        assert content['schema_version'] == 1 and content['status'] == 'not_evaluated'
        assert content['scope'] == 'attachment_payload_content'
        assert content['not_evaluated'] == UNEVALUATED
        assert item['ole_macro'] is item['risk_score'] is None
        assert item['detected_mime'] is None and item['risk_level'] == 'not_evaluated'
        assert all(item[key]['status'] == 'not_evaluated'
                   for key in ('macro_analysis', 'malware_analysis', 'mime_detection'))
        if 'original_wire' in item:
            wire = item['original_wire']
            saved = (case/wire['evidence_path']).read_bytes()
            assert wire['status'] == 'captured'
            assert saved == raw[wire['offset']:wire['offset']+wire['size']]
            assert hashlib.sha256(saved).hexdigest() == wire['sha256']
            assert b'inner-only.invalid' in saved
    coverage = read(case/'analysis_coverage.json')
    stage = coverage['stages']['attachment_metadata']
    assert stage['schema_version'] == 1 and stage['count'] == len(items)
    assert stage['status'] == ('partial' if any(item['status'] == 'partial' for item in items) else 'completed')
    assert stage['content_analysis']['not_evaluated'] == UNEVALUATED
    assert stage['content_analysis']['status'] == 'not_evaluated'
    assert coverage == read(case/'report/score.json')['coverage']
    assert read(case/'url_evidence.json') == [] and read(case/'headers.json')['urls'] == []
    source_parts = {row['part_id'] for row in read(case/'url_source_inventory.json')['sources']
                    if row['kind'] == 'mime_body'}
    assert not source_parts.intersection(item['part_id'] for item in items)
    markup = (case/'report/technical.md').read_text(encoding='utf-8')
    tokens = MarkdownIt('commonmark').enable('table').parse(markup)
    block, section = None, None
    for index, token in enumerate(tokens):
        if token.type == 'heading_open' and token.tag == 'h2':
            section = tokens[index+1].content
        if token.type == 'fence' and token.info == 'json' and section == 'Attachment extraction coverage':
            assert block is None
            block = json.loads(token.content)
    assert block is not None and block['coverage'] == stage
    assert len(block['attachments']) == len(items)
    for row, item in zip(block['attachments'], items):
        assert row['part_id'] == item['part_id'] and row['sha256'] == item['sha256']
        assert row['content_analysis'] == item['content_analysis']
        assert row['archive'] == {key: item['archive'][key] for key in ARCHIVE_FIELDS if key in item['archive']}
        assert 'entries' not in row['archive']
    return items


def check_zip(archive, case, raw, prefix=''):
    assert archive.read(prefix+'input.eml') == raw
    for name in ('attachments.json', 'analysis_coverage.json', 'report/score.json',
                 'report/technical.md', 'url_evidence.json', 'url_source_inventory.json',
                 'mime_body_evidence.json', 'mime_header_inventory.json', 'mime_cid_inventory.json'):
        assert archive.read(prefix+name) == (case/name).read_bytes(), name
    for item in read(case/'attachments.json'):
        assert archive.read(prefix+item['evidence_path']) == (case/item['evidence_path']).read_bytes()
        if 'original_wire' in item:
            path = item['original_wire']['evidence_path']
            assert archive.read(prefix+path) == (case/path).read_bytes()


def main():
    samples = fixtures()
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-attachment-capabilities-') as temporary:
        root = Path(temporary)
        inputs = root/'inputs'; inputs.mkdir()
        for name, raw in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable, '-B', '-P', '-X', 'utf8', '-m', 'paw', 'full',
            str(inputs), '--no-egress', '--lang', 'en', '--deadline', '180', '--stage-timeout', '60'],
            cwd=root, env=env, capture_output=True, timeout=210)
        assert result.returncode == 0, (result.stdout+result.stderr).decode(errors='replace')[-6000:]
        cases = {read(case/'manifest.json')['source_name']: case for case in (root/'cases').glob('case-*')}
        assert set(cases) == set(samples)
        for name, case in cases.items():
            check_case(case, samples[name])
            exported = subprocess.run([sys.executable, '-B', '-P', '-m', 'paw', 'export',
                '--case', str(case), '--format', 'zip'], cwd=root, env=env, capture_output=True, timeout=30)
            assert exported.returncode == 0, exported.stdout+exported.stderr
            with zipfile.ZipFile(str(case)+'.zip') as archive: check_zip(archive, case, samples[name], case.name+'/')
        assert [item['archive']['status'] for item in read(cases['zip-errors.eml']/'attachments.json')] == [
            'metadata_only', 'error', 'error', 'metadata_only']
        limits = read(cases['zip-limits.eml']/'attachments.json')
        assert limits[0]['archive']['omitted_entry_count'] == limits[1]['archive']['limited_name_count'] == 1
        special = read(cases['zip-content.eml']/'attachments.json')
        assert special[0]['archive']['entry_count'] == 1
        assert special[1]['archive']['entries'][0]['encrypted'] is True
        assert special[2]['archive']['status'] == 'not_evaluated'
        cids = read(cases['related.eml']/'mime_cid_inventory.json')
        assert cids['total_observation_count'] == 3 and cids['total_link_count'] == 1
        data = root/'http'; data.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        def request(path, body=None, content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body, headers={'Content-Type':content_type}), timeout=15) as response:
                return response.read()
        with (root/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable, '-B', '-P', '-m', 'uvicorn', 'paw.web.api:app',
                '--app-dir', str(REPO), '--host', '127.0.0.1', '--port', str(port)],
                cwd=data, env=dict(env, PAW_DATA_DIR=str(data)), stdout=log, stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic() < end:
                    if server.poll() is not None: raise AssertionError('API bootstrap failed')
                    try: request('/health'); break
                    except (urllib.error.URLError, TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('none.eml', 'opaque.eml', 'embedded.eml', 'zip-limits.eml', 'zip-errors.eml', 'related.eml'):
                    raw = samples[name]; boundary = 'attachment-capability-fixture'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                        'Content-Type: message/rfc822\r\n\r\n').encode()+raw+f'\r\n--{boundary}--\r\n'.encode()
                    path = json.loads(request('/api/upload', upload, 'multipart/form-data; boundary='+boundary))['path']
                    job = json.loads(request('/api/analyze', json.dumps({'file_path':path, 'profile':'strict',
                        'options':{'no_egress':True}, 'limits':{'wall_seconds':120, 'stage_seconds':60}}).encode()))['analysis_id']
                    end = time.monotonic()+140
                    while time.monotonic() < end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued', 'running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status'] == 'completed' and state['supervisor']['tree_stopped'], state
                    case = data/'cases'/state['case_ids'][0]
                    items = check_case(case, raw)
                    detail = json.loads(request('/api/cases/'+case.name))
                    assert detail['attachments'] == items and detail['coverage'] == read(case/'analysis_coverage.json')
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        check_zip(archive, case, raw)
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: eight full no-egress CLI cases and six owned-loopback HTTP workers; opaque/inline/embedded '
          'payloads, explicit unavailable content/URL/resource interpretation, ZIP count/name omissions and '
          'reader errors, nested/encrypted declarations, Content-Location/CID non-resolution, source boundaries, '
          'report/JSON/API/ZIP parity, original bytes, stopped owners and seals. Fixtures are not format or accuracy truth.')


if __name__ == '__main__':
    main()
