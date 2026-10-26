"""Owned explicit representations through real CLI/HTTP; never sample execution."""
import argparse
import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[1]
FIXTURES = [
    ('empty', b'', 'html-utf8'),
    ('binary', b'\xff\xfe\x00\x80', 'html-utf8'),
    ('truncated', b'<html><script>throw new Error("owned")', 'html-utf8'),
    ('bad-base64-length', b'Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nZm9vZ', 'mime'),
    ('missing-padding', b'Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+eDwvYj4', 'mime'),
    ('dangling-qp', b'Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>owned=', 'mime'),
    ('duplicate', b'Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nZg==', 'mime'),
    ('open-boundary', b'Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/html\n\n<p>owned', 'mime'),
    ('nonascii-header', b'Content-Type: text/html; x=\xff\r\n\r\n<p>owned</p>', 'mime'),
    ('recovered-html', b'Content-Type: text/html; charset=us-ascii\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+b3duZWQ8L2I+Z', 'mime'),
    ('duplicate-charset', b'Content-Type: text/html; charset=us-ascii; charset=utf-8\r\n\r\n<p>owned</p>', 'mime'),
    ('broken-charset-quote', b'Content-Type: text/html; charset="us-ascii\r\n\r\n<p>owned</p>', 'mime'),
    ('duplicate-boundary', b'Content-Type: multipart/mixed; boundary=x; boundary=y\r\n\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>owned</p>\r\n--x--\r\n', 'mime'),
]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def verify_source_case(case, raw):
    from paw.core.verify import verify_case
    from paw.core.job_registry import require_stopped_case
    require_stopped_case(case)
    assert verify_case(case)
    assert (case/'source.bin').read_bytes() == raw
    manifest = json.loads((case/'manifest.json').read_bytes())
    assert manifest['case_kind'] == 'forensic_representations'
    assert manifest['classification'] == 'not_evaluated' and manifest['execution_authority'] == 'none'
    record = json.loads((case/'report/representations.json').read_bytes())
    reports = json.loads((case/'report/interpretations.json').read_bytes())
    json.dumps(reports, ensure_ascii=False).encode('utf-8', 'strict')
    assert record['root'] == manifest['representation_root']
    assert record['source_sha256'] == hashlib.sha256(raw).hexdigest()
    seen = set()
    for node in record['nodes']:
        assert hashlib.sha256(canonical({k: v for k, v in node.items() if k not in {'id', 'blob_path'}})).hexdigest() == node['id']
        assert all(parent in seen for parent in node['parents']); seen.add(node['id'])
        blob = (case/node['blob_path']).read_bytes()
        assert len(blob) == node['bytes'] and hashlib.sha256(blob).hexdigest() == node['sha256']
        assert node['origin_verified'] is False and node['execution_authority'] == 'none'
        if node['kind'] == 'original': assert not node['parents'] and blob == raw
        if node['kind'] == 'wire_body_slice':
            params = node['transform']['parameters']; assert blob == raw[params['start']:params['end']]
    assert len(record['nodes']) <= 64 and record['representation_bytes'] <= 24*1024**2
    assert record['work_bytes'] <= 64*1024**2
    execution = json.loads((case/'execution.json').read_bytes())
    if any(marker in raw for marker in (b'charset=us-ascii; charset=utf-8', b'charset="us-ascii', b'boundary=x; boundary=y')):
        assert reports['mime']['status'] == execution['coverage'] == 'partial'
        assert 'structured_declaration_defects' in reports['mime']['parts'][0]['issues']
    if raw.endswith(b'PGI+b3duZWQ8L2I+Z'):
        recovered = [view for view in reports['html'] if view['view_role'] == 'derived_candidate']
        assert len(recovered) == 1 and recovered[0]['start_tags'] == 1 and recovered[0]['end_tags'] == 1
        assert execution['coverage'] == 'partial'
    assert execution['limits']['address_space_bytes'] == 256*1024**2 and execution['limits']['cpu_seconds'] == 10
    assert not (case/'report/score.json').exists()
    archive_path = case.with_suffix('.zip')
    assert archive_path.stat().st_mode & 0o777 == 0o600
    inventory = {p.relative_to(case).as_posix(): p.read_bytes() for p in case.rglob('*') if p.is_file()}
    with zipfile.ZipFile(archive_path) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist())) == len(inventory)
        assert set(archive.namelist()) == {case.name+'/'+name for name in inventory}
        for name, blob in inventory.items(): assert archive.read(case.name+'/'+name) == blob
    return {'source_sha256': record['source_sha256'], 'nodes': len(record['nodes']), 'coverage': execution['coverage']}


@contextmanager
def validation_directory():
    from paw.core.process_recovery import recover_worker
    root = Path(tempfile.mkdtemp(prefix='paw-forensic-integration-')); success = False
    try:
        yield root
        success = True
    finally:
        stopped = True
        for control in root.glob('workspace/jobs/analysis_*'):
            if control.is_dir():
                try: stopped &= asyncio.run(recover_worker(control))['tree_stopped'] is True
                except Exception: stopped = False
        if success and stopped: shutil.rmtree(root)
        else: print('Preserved forensic acceptance evidence: '+str(root), file=sys.stderr)
        if success and not stopped: raise AssertionError('Unconfirmed worker stop; data preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed', action='store_true'); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    if not args.installed:
        env['PYTHONPATH'] = str(REPO); sys.path.insert(0, str(REPO))
    import paw
    if args.installed:
        assert Path(paw.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        assert not Path(paw.__file__).resolve().is_relative_to(REPO)
    results = []
    with validation_directory() as root:
        workspace = root/'workspace'; workspace.mkdir(); (workspace/'cases').mkdir(mode=0o755)
        for name, raw, interpretation in FIXTURES:
            source = root/(name+'.bin'); source.write_bytes(raw); source.chmod(0o400)
            run = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', 'inspect-representations', str(source),
                                  '--interpretation', interpretation], cwd=workspace, env=env,
                                 capture_output=True, text=True, timeout=55)
            assert run.returncode == 0, run.stdout+run.stderr
            value = json.loads(run.stdout); assert value['supervisor']['tree_stopped'] is True
            row = verify_source_case(workspace/'cases'/value['worker']['case_id'], raw)
            assert source.read_bytes() == raw
            results.append(dict(row, path='CLI', fixture=name))
        oversize = root/'oversize'; oversize.touch()
        with oversize.open('r+b') as stream: stream.truncate(8*1024**2+1)
        fifo = root/'fifo'; os.mkfifo(fifo)
        for refused in (str(oversize), str(fifo), 'https://owned.invalid/source'):
            run = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', 'inspect-representations', refused,
                                  '--interpretation', 'mime'], cwd=workspace, env=env,
                                 capture_output=True, text=True, timeout=20)
            assert run.returncode != 0, run.stdout+run.stderr
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(path, value=None, *, body=None, headers=None, expected=200):
            if value is not None: body = json.dumps(value).encode(); headers = {'Content-Type': 'application/json'}
            req = urllib.request.Request('http://127.0.0.1:'+str(port)+path, data=body, headers=headers or {})
            try:
                with client.open(req, timeout=50) as response: status, data = response.status, response.read()
            except urllib.error.HTTPError as error: status, data = error.code, error.read()
            assert status == expected, (path, status, data[:1500])
            return json.loads(data)
        (workspace/'paw.py').write_text('raise RuntimeError("workspace import forbidden")')
        with (root/'api.log').open('wb') as log:
            api = subprocess.Popen([sys.executable, '-P', '-B', '-m', 'paw', 'gui', '--no-browser',
                                    '--port', str(port), '--data-dir', str(workspace)], cwd=workspace,
                                   env=env, stdout=log, stderr=log)
            try:
                end = time.monotonic()+15
                while True:
                    assert api.poll() is None, (root/'api.log').read_text(errors='replace')
                    try: request('/health'); break
                    except (urllib.error.URLError, TimeoutError):
                        assert time.monotonic() < end; time.sleep(.05)
                for name, raw, interpretation in FIXTURES:
                    boundary = 'owned-forensic-upload'
                    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="owned.eml"\r\n\r\n').encode()+raw+f'\r\n--{boundary}--\r\n'.encode()
                    upload = request('/api/sources/upload', body=body, headers={'Content-Type': 'multipart/form-data; boundary='+boundary})
                    queued = request('/api/sources/representations', {'file_path': upload['path'], 'interpretation': interpretation})
                    end = time.monotonic()+50
                    while True:
                        job = request('/api/analysis/'+queued['analysis_id'])
                        if job['status'] not in {'queued', 'running'}: break
                        assert time.monotonic() < end; time.sleep(.05)
                    assert job['status'] == 'completed', job
                    case = workspace/'cases'/job['case_ids'][0]
                    row = verify_source_case(case, raw)
                    detail = request('/api/cases/'+case.name)
                    assert detail['status'] == 'completed' and detail['case_kind'] == 'forensic_representations'
                    assert detail['assessment_status'] == 'not_evaluated' and not detail['artifact_errors']
                    assert not {'email', 'score', 'assessment_view'} & detail.keys()
                    assert detail['representations']['root'] == detail['manifest']['representation_root']
                    results.append(dict(row, path='HTTP', fixture=name))
                listed = request('/api/cases?limit=100')['cases']
                assert len(listed) == 2*len(FIXTURES) and all(x['case_kind'] == 'forensic_representations' for x in listed)
                assert not any(x['artifact_errors'] for x in listed)
                for invalid in ({'file_path': 'https://owned.invalid/source', 'interpretation': 'mime'},):
                    request('/api/sources/representations', invalid, expected=400)
                for invalid in ({'file_path': upload['path']}, {'file_path': upload['path'], 'interpretation': 'auto'},
                                {'file_path': upload['path'], 'interpretation': 'mime', 'execute': True}):
                    request('/api/sources/representations', invalid, expected=422)
            finally:
                api.terminate()
                try: api.wait(timeout=10)
                except subprocess.TimeoutExpired: api.kill(); api.wait(timeout=5)
    summary = {'status': 'PASS', 'installed': args.installed, 'cases': results, 'case_count': 2*len(FIXTURES), 'cli_refusals': 3,
               'sample_execution': 'not_performed', 'cleanup': 'known_stopped'}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as stream: json.dump(summary, stream, indent=2)
    print(json.dumps(summary))


if __name__ == '__main__': main()
