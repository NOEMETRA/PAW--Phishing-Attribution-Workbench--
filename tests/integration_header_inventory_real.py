"""Actual offline CLI/HTTP header inventory, original bytes and sealed exports."""
import base64
from collections import Counter
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
from paw.core.verify import verify_case


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def check_case(case, raw, expected_status):
    assert (case/'input.eml').read_bytes() == raw
    assert verify_case(str(case))
    execution = read(case/'execution.json')
    assert execution['no_egress'] is True and not execution['blocked_operations']
    inventory = read(case/'header_inventory.json')
    assert inventory['status'] == expected_status, inventory['status']
    assert inventory['verified'] is False
    assert inventory['source'] == {'path':'input.eml', 'sha256':hashlib.sha256(raw).hexdigest()}
    # Independent standard-library parse; never rebuild expected raw values
    # through the implementation being checked.
    message = BytesParser(policy=policy.default).parsebytes(raw)
    pairs = list(message.raw_items())
    assert inventory['total_field_count'] == len(pairs)
    assert len(inventory['fields'])+inventory['omitted_field_count'] == len(pairs)
    counts = Counter()
    for field, (name, value) in zip(inventory['fields'], pairs):
        assert pairs[field['header_index']] == (name, value)
        if field['name'] is not None:
            assert field['name'] == name
            assert field['normalized_name'] == name.lower()
            assert field['occurrence_index'] == counts[name.lower()]
            counts[name.lower()] += 1
        if field['raw_status'] == 'captured':
            assert base64.b64decode(field['raw_value_base64'], validate=True) == value.encode('ascii','surrogateescape')
        else:
            assert field['raw_value_base64'] is None and field['issues']
    assert inventory['distinct_name_count'] == len(counts)
    assert inventory['duplicate_occurrence_count'] == sum(count-1 for count in counts.values())
    coverage = read(case/'analysis_coverage.json')['stages']['header_inventory']
    assert coverage == read(case/'report/score.json')['coverage']['stages']['header_inventory']
    for key in ('status','total_field_count','inventoried_field_count','omitted_field_count','limited_field_count'):
        assert coverage[key] == inventory[key]
    assert 'header_inventory.json' in (case/'report/technical.md').read_text(encoding='utf-8')
    return inventory


def main():
    prefix = b'From: a@example.invalid\r\nSubject: Inventory contract\r\n'
    samples = {
        'ordered.eml':prefix+b'To: first@example.invalid\r\ntO: second@example.invalid\r\nX-Fold: one\r\n\ttwo\r\nX-Encoded: =?utf-8?b?Y2Fmw6k=?=\r\n\r\nbody',
        'high-bytes.eml':prefix+b'X-Trace: raw \xff\xfe\r\n\r\nbody',
        'malformed.eml':prefix+b'not a header\r\nX-Body: body\r\n',
        'nested.eml':prefix+b'Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nX-Inner: hidden\r\n\r\nX-Body: body\r\n--b--\r\n',
        'field-limit.eml':prefix+b'X-Trace: value\r\n'*1025+b'\r\nbody',
        'name-limit.eml':prefix+b'X-'+b'a'*300+b': value\r\nX-Short: kept\r\n\r\nbody',
        'value-limit.eml':prefix+b'X-Trace: '+b'a'*17000+b'\r\nX-Short: kept\r\n\r\nbody',
        'budget-limit.eml':prefix+(b'X-Trace: '+b'a'*15000+b'\r\n')*20+b'\r\nbody',
        'body-decoding.eml':prefix+b'Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8'}
    completed = {'ordered.eml','nested.eml','body-decoding.eml'}
    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-header-inventory-', dir=REPO.parent) as temporary:
        base = Path(temporary).resolve()
        inputs = base/'inputs'; inputs.mkdir()
        for name, raw in samples.items(): (inputs/name).write_bytes(raw)
        result = subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','120','--stage-timeout','60','--memory-mib','1024'],
            cwd=base, env=env, capture_output=True, timeout=150)
        assert result.returncode == 0, (result.stdout+result.stderr).decode(errors='replace')[-6000:]
        cases = list((base/'cases').glob('case-*'))
        assert len(cases) == len(samples)
        inventories = {}
        for case in cases:
            name = read(case/'manifest.json')['source_name']
            inventories[name] = check_case(case,samples[name],'completed' if name in completed else 'partial')
            if name == 'body-decoding.eml':
                assert inventories[name]['message_defect_count'] == 0
                assert read(case/'mime_analysis.json')['status'] == 'partial'
        assert inventories['ordered.eml']['fields'][3]['occurrence_index'] == 1
        assert inventories['ordered.eml']['fields'][-1]['parsed_value'] == 'café'
        assert inventories['malformed.eml']['total_field_count'] == 2
        assert inventories['nested.eml']['total_field_count'] == 3
        assert inventories['field-limit.eml']['omitted_field_count'] == 3
        assert inventories['name-limit.eml']['limited_field_count'] == 1
        assert inventories['value-limit.eml']['limited_field_count'] == 1
        assert inventories['budget-limit.eml']['limited_field_count'] > 0

        root = base/'http'; root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        def request(path, method='GET', body=None, content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                    data=body,method=method,headers={'Content-Type':content_type}), timeout=15) as response:
                return response.read()
        with (base/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],
                cwd=root, env=dict(env,PAW_DATA_DIR=str(root)), stdout=log, stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API bootstrap failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('ordered.eml','field-limit.eml'):
                    raw = samples[name]
                    boundary = 'paw_header_inventory_fixture'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded = json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload = {'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':120.0,'stage_seconds':60.0}}
                    job = json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end = time.monotonic()+140
                    while time.monotonic()<end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status'] == 'completed' and state['supervisor']['tree_stopped'], state
                    case = root/'cases'/state['case_ids'][0]
                    inventory = check_case(case,raw,'completed' if name in completed else 'partial')
                    detail = json.loads(request('/api/cases/'+case.name))
                    assert detail['header_inventory'] == inventory
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('input.eml') == raw
                        assert json.loads(archive.read('header_inventory.json')) == inventory
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: nine actual full CLI cases and two loopback HTTP workers; ordered duplicate/raw/derived headers, source binding, explicit limits, separate body-decoding defects, original bytes, seals, API detail and ZIP export. Offline; fixtures are not accuracy labels.')


if __name__ == '__main__': main()
