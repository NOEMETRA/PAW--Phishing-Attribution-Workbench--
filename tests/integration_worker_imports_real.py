"""Actual offline CLI/HTTP workers against benign cwd import-shadow fixtures."""
import argparse
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


def shadow_fixture(directory, name):
    marker = directory/'shadow-imported.json'
    if name == 'paw':
        package = directory/'paw'; package.mkdir()
        module = package/'__init__.py'
    else:
        module = directory/'psutil.py'
    # Prove unexpected import using local marker + failure only. No sockets,
    # subprocesses, decoder replacement or fabricated analysis output.
    module.write_text('import json,os\nfrom pathlib import Path\nPath('+repr(str(marker))+
        ').write_text(json.dumps({"module":'+repr(name)+',"pid":os.getpid()}))\n'
        'raise RuntimeError("Benign cwd import-shadow fixture")\n', encoding='utf-8')
    return marker


def check_outcome(root, marker, state, original, expect_shadow):
    assert state['supervisor']['tree_stopped'] is True, state
    if expect_shadow:
        assert marker.is_file() and read(marker)['module'] in {'paw','psutil'}
        assert state['status'] == 'failed', state
        assert not list((root/'cases').glob('case-*'))
        return None
    assert not marker.exists(), 'Worker imported analysis-directory code'
    assert state['status'] == 'completed', state
    assert len(state['case_ids']) == 1, state
    case = root/'cases'/state['case_ids'][0]
    assert (case/'input.eml').read_bytes() == original
    assert verify_case(str(case))
    execution = read(case/'execution.json')
    assert execution['no_egress'] is True and not execution['blocked_operations'], execution
    return case


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expect-shadow', action='store_true',
        help='Before-fix reproduction: expect only benign import failure, never analysis output')
    expect_shadow = parser.parse_args().expect_shadow
    original = next((REPO/'inbox').glob('*.eml')).read_bytes()
    environment = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    environment.pop('PYTHONSAFEPATH', None)  # Test the production argv, not an inherited workaround.
    observations = []
    with tempfile.TemporaryDirectory(prefix='paw-worker-imports-', dir=REPO.parent) as temporary:
        base = Path(temporary)
        source = base/'original.eml'; source.write_bytes(original)
        # -P here establishes a trusted parent bootstrap, like an installed
        # console entry point. Worker safety depends on its own production argv.
        for name, preset in [('paw',preset) for preset in ('analyze','quick','full','forensic','trace')]+[('psutil','full')]:
            root = base/(name+'-'+preset); root.mkdir()
            marker = shadow_fixture(root, name)
            arguments = [preset, *(['--src'] if preset == 'trace' else []), str(source)]
            if preset != 'quick': arguments += ['--no-egress']
            result = subprocess.run([sys.executable,'-P','-X','utf8','-m','paw',*arguments,
                '--deadline','60','--stage-timeout','45'],cwd=root,env=environment,
                capture_output=True,timeout=90)
            assert (result.returncode != 0) if expect_shadow else (result.returncode == 0), (result.stdout+result.stderr).decode('utf-8',errors='replace')[-3000:]
            states = list((root/'jobs').glob('analysis_*.json'))
            assert len(states) == 1, states
            check_outcome(root, marker, read(states[0]), original, expect_shadow)
            observations.append({'entry':'cli','preset':preset,'shadow':name,
                'unexpected_import':marker.exists(),'tree_stopped':True,'sealed_original':not expect_shadow})

        for name in ('paw','psutil'):
            root = base/('api-'+name); root.mkdir()
            marker = shadow_fixture(root, name)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
            def request(path, method='GET', body=None, content_type='application/json'):
                with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                        data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:
                    return response.read()
            with (base/('api-'+name+'.log')).open('wb') as log:
                server = subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                    '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],cwd=root,
                    env=dict(environment,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
                try:
                    end = time.monotonic()+30
                    while time.monotonic()<end:
                        if server.poll() is not None:
                            raise AssertionError('Trusted API bootstrap failed: '+log.name+'\n'+
                                Path(log.name).read_text(encoding='utf-8',errors='replace')[-3000:])
                        try: request('/health'); break
                        except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                    else: raise TimeoutError('API startup')
                    assert not marker.exists(), 'Fixture affected parent instead of worker'
                    boundary = 'paw_import_fixture'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="original.eml"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+original+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded = json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    assert Path(uploaded['path']).read_bytes() == original
                    payload = {'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':60.0,'stage_seconds':45.0}}
                    job = json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end = time.monotonic()+75
                    while time.monotonic()<end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API worker')
                    case = check_outcome(root, marker, state, original, expect_shadow)
                    if case:
                        with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                            assert archive.read('input.eml') == original
                    observations.append({'entry':'http','preset':'strict','shadow':name,
                        'unexpected_import':marker.exists(),'tree_stopped':True,'sealed_original':not expect_shadow})
                finally:
                    server.terminate()
                    try: server.wait(timeout=15)
                    except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
        assert source.read_bytes() == original
    print(json.dumps({'mode':'before-fix' if expect_shadow else 'regression',
        'original_sha256':hashlib.sha256(original).hexdigest(),'runs':observations},indent=2))
    print('PASS: eight actual CLI/HTTP worker outcomes; local benign import fixtures only; no sample URL/DNS/attachment execution. '+
        ('Unsafe cwd imports reproduced without fabricated analysis.' if expect_shadow else
         'Cwd package/dependency imports excluded; original MIME, no-egress, seals, API ZIP and confirmed shutdown verified.'))


if __name__ == '__main__': main()
