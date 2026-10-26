"""Owned opaque bytes through actual CLI, HTTP, custody and ZIP; no execution.

Use --installed to exercise only an installed package outside the checkout.
"""
import argparse
import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
import shutil
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

@contextmanager
def validation_directory():
    from paw.core.process_recovery import recover_worker
    root = Path(tempfile.mkdtemp(prefix='paw-source-integration-'))
    success = False
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
        else: print('Preserved source acceptance evidence: '+str(root), file=sys.stderr)
        if success and not stopped: raise AssertionError('Worker shutdown not confirmed; data preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    if not args.installed:
        env['PYTHONPATH'] = str(REPO)
        sys.path.insert(0, str(REPO))
    import paw
    if args.installed:
        assert Path(paw.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        assert not Path(paw.__file__).resolve().is_relative_to(REPO)
    from paw.core.verify import verify_case
    from paw.core.job_registry import require_stopped_case
    from paw.core.process_recovery import recover_worker
    results = []
    with validation_directory() as temporary:
        root = Path(temporary); workspace = root/'workspace'; workspace.mkdir()
        canary = root/'never-created'
        fixtures = [b'', bytes(range(256)),
                    ('from pathlib import Path\nPath('+repr(str(canary))+').touch()\n').encode(),
                    b'Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%\xff']
        sources = []
        for index, raw in enumerate(fixtures):
            source = root/(str(index)+'.py'); source.write_bytes(raw); source.chmod(0o400); sources.append(source)
            p = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', 'inspect-source', str(source)],
                               cwd=workspace, env=env, capture_output=True, text=True, timeout=40)
            assert p.returncode == 0, p.stdout+p.stderr
            value = json.loads(p.stdout); case = workspace/'cases'/value['worker']['case_id']
            assert value['supervisor']['tree_stopped'] is True
            assert (case/'source.bin').read_bytes() == raw == source.read_bytes()
            assert not (case/'report/score.json').exists() and verify_case(case)
            execution = json.loads((case/'execution.json').read_text())
            assert execution['limits']['address_space_bytes'] == 256*1024**2 if os.name == 'posix' else True
            assert execution['limits']['cpu_seconds'] == 10 if os.name == 'posix' else True
            require_stopped_case(case)
            report = json.loads((case/'report/source-inspection.json').read_text())
            assert report['source']['sha256'] == hashlib.sha256(raw).hexdigest()
            assert report['coverage']['execution_authority'] == 'none'
            with zipfile.ZipFile(value['worker']['zip']) as archive:
                assert archive.read(case.name+'/source.bin') == raw
                assert set(archive.namelist()) == {case.name+'/'+p.relative_to(case).as_posix() for p in case.rglob('*') if p.is_file()}
            results.append({'path': 'CLI', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        oversize = root/'oversize'; oversize.touch()
        with oversize.open('r+b') as stream: stream.truncate(16*1024**2+1)
        refused = [str(oversize), 'https://owned.invalid/input']
        if os.name == 'posix':
            fifo = root/'fifo'; os.mkfifo(fifo); refused.append(str(fifo))
        for source in refused:
            p = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', 'inspect-source', source],
                               cwd=workspace, env=env, capture_output=True, text=True, timeout=35)
            assert p.returncode != 0, p.stdout+p.stderr
        # Source data cannot shadow either the CLI package or worker imports.
        (workspace/'paw.py').write_text('raise RuntimeError("untrusted workspace imported")')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        api_env = dict(env, PAW_DATA_DIR=str(workspace))
        with (root/'api.log').open('wb') as log:
            api = subprocess.Popen([sys.executable, '-P', '-B', '-m', 'paw', 'gui',
                                    '--no-browser', '--data-dir', str(workspace), '--port', str(port)], cwd=workspace, env=api_env,
                                   stdout=log, stderr=log)
            def request(path, data=None, headers=None, expected=200):
                req = urllib.request.Request('http://127.0.0.1:'+str(port)+path, data=data, headers=headers or {})
                try:
                    with urllib.request.urlopen(req, timeout=40) as response:
                        status, body = response.status, response.read()
                except urllib.error.HTTPError as error:
                    status, body = error.code, error.read()
                assert status == expected, (path, status, body[:1000])
                return body
            def post(path, value, expected=200):
                return json.loads(request(path, json.dumps(value).encode(), {'Content-Type': 'application/json'}, expected))
            try:
                end = time.monotonic()+15
                while True:
                    assert api.poll() is None, (root/'api.log').read_text(errors='replace')
                    try: request('/health'); break
                    except (urllib.error.URLError, TimeoutError):
                        if time.monotonic() > end: raise
                        time.sleep(.05)
                for raw in fixtures:
                    boundary = 'paw-owned-source-boundary'
                    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="owned.HTML"\r\n'
                            'Content-Type: application/octet-stream\r\n\r\n').encode()+raw+f'\r\n--{boundary}--\r\n'.encode()
                    upload = json.loads(request('/api/sources/upload', body, {'Content-Type': 'multipart/form-data; boundary='+boundary}))
                    queued = post('/api/sources/inspect', {'file_path': upload['path']})
                    end = time.monotonic()+35
                    while True:
                        job = json.loads(request('/api/analysis/'+queued['analysis_id']))
                        if job['status'] not in {'queued', 'running'}: break
                        assert time.monotonic() < end; time.sleep(.05)
                    assert job['status'] == 'completed', job
                    case = workspace/'cases'/job['case_ids'][0]
                    detail = json.loads(request('/api/cases/'+case.name))
                    assert detail['status'] == 'completed' and detail['case_kind'] == 'opaque_source_inspection'
                    assert detail['assessment_status'] == 'not_evaluated'
                    assert not {'score', 'email', 'assessment_view'} & detail.keys()
                    assert detail['source_inspection']['coverage']['format_interpretation'] == 'not_performed'
                    assert (case/'source.bin').read_bytes() == raw
                    assert not detail['artifact_errors'], detail
                    assert post('/api/cases/'+case.name+'/verify', {})['integrity'] == 'verified'
                    results.append({'path': 'HTTP', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
                listing = json.loads(request('/api/cases?limit=100'))['cases']
                assert len(listing) == 8 and all(x['assessment_status'] == 'not_evaluated' for x in listing)
                assert not any(x['artifact_errors'] for x in listing)
                for bad in ['https://owned.invalid/sample', str(root/'outside.py')]:
                    post('/api/sources/inspect', {'file_path': bad}, 400)
                post('/api/sources/inspect', {'file_path': sources[0].as_posix(), 'execute': True}, 422)
                request('/api/sources/upload', b'', {'Transfer-Encoding': 'chunked'}, 411)
                request('/api/sources/upload', b'', {'Content-Length': str(17*1024**2)}, 413)
                before = set((workspace/'uploads').iterdir())
                too_large = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="large"\r\n\r\n').encode()
                too_large += b'x'*(16*1024**2+1)+f'\r\n--{boundary}--\r\n'.encode()
                request('/api/sources/upload', too_large, {'Content-Type': 'multipart/form-data; boundary='+boundary}, 413)
                assert set((workspace/'uploads').iterdir()) == before, 'Failed upload left source bytes'
                assert not canary.exists(), 'Input source was executed'
            finally:
                api.terminate()
                try: api.wait(timeout=10)
                except subprocess.TimeoutExpired: api.kill(); api.wait(timeout=5)
                for control in (workspace/'jobs').glob('analysis_*'):
                    if control.is_dir():
                        outcome = asyncio.run(recover_worker(control)); assert outcome['tree_stopped'], outcome
        summary = {'status': 'PASS', 'installed': args.installed, 'owned_cases': results,
                   'case_count': 8, 'cli_refusals': len(refused), 'sample_execution': 'not_performed', 'cleanup': 'known_stopped'}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as stream: json.dump(summary, stream, indent=2)
    print(json.dumps(summary))


if __name__ == '__main__': main()
