"""R08: exercise an installed wheel from outside the checkout, without PYTHONPATH.

Run with the clean virtualenv's Python after installing the wheel and all its
dependencies. No browser, Docker, external endpoint or attachment is executed.
"""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import sysconfig
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


@contextmanager
def validation_directory(output, env):
    """Stop registered writers before deletion; preserve every failed run."""
    root = Path(tempfile.mkdtemp(prefix='paw-installed-')).resolve()
    succeeded = False
    try:
        yield root
        succeeded = True
    finally:
        cleanup = dict(data_directory=str(root), tree_stopped=False, preserved=True)
        try:
            # Import only the installed recovery implementation, not checkout
            # code. It checks boot/PID creation/group identity before killing.
            recovery = subprocess.run([sys.executable, '-I', '-c', '''
import asyncio,json,sys
from pathlib import Path
from paw.core.process_recovery import recover_worker
async def main():
    root = Path(sys.argv[1])
    outcomes = []
    for control in sorted(root.glob('*/jobs/analysis_*')):
        if control.is_dir():
            outcomes.append(dict(control=str(control.relative_to(root)), **await recover_worker(control)))
    print(json.dumps(dict(controls=outcomes, tree_stopped=all(o['tree_stopped'] is True for o in outcomes))))
asyncio.run(main())
''', str(root)], cwd=root, env=env, capture_output=True, timeout=60)
            (output / 'cleanup.log').write_bytes(recovery.stdout + recovery.stderr)
            assert recovery.returncode == 0, 'Installed recovery helper failed'
            cleanup.update(json.loads(recovery.stdout))
        except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
            cleanup['error'] = str(error)
        if succeeded and cleanup['tree_stopped'] is True:
            shutil.rmtree(root)
            cleanup['preserved'] = False
        (output / 'cleanup.json').write_text(json.dumps(cleanup, indent=2), encoding='utf-8')
        if cleanup['preserved']:
            print('Validation data preserved: ' + str(root), file=sys.stderr)
        if succeeded and cleanup['tree_stopped'] is not True:
            raise AssertionError('Worker shutdown unconfirmed; validation data preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    for key in ('PYTHONPATH', 'PYTHONHOME', 'PAW_DATA_DIR', 'PAW_PGP_PRIV', 'PAW_START_GATE'):
        env.pop(key, None)
    console = Path(sysconfig.get_path('scripts')) / ('paw.exe' if os.name == 'nt' else 'paw')
    results = []

    def run(command, cwd, name, success=True):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=180)
        (args.output / (name + '.log')).write_bytes(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, (name, result.stdout + result.stderr)
        return result

    with validation_directory(args.output, env) as root:
        assert not root.is_relative_to(REPO)
        location = run([sys.executable, '-I', '-c',
            'import json,paw,sys; print(json.dumps({"package":paw.__file__,"prefix":sys.prefix,'
            '"base_prefix":sys.base_prefix,"path":sys.path}))'], root, 'installed-location')
        location = json.loads(location.stdout)
        package = Path(location['package']).parent
        assert location['prefix'] != location['base_prefix'], 'Use a clean virtualenv'
        assert package.is_relative_to(Path(sys.prefix).resolve()) and not package.is_relative_to(REPO), location
        assert all(not Path(p).resolve().is_relative_to(REPO) for p in location['path']), location
        assert 'include-system-site-packages = false' in (Path(sys.prefix) / 'pyvenv.cfg').read_text()
        with zipfile.ZipFile(args.wheel) as archive:
            files = [name for name in archive.namelist() if name.startswith('paw/') and not name.endswith('/')]
            for name in files:
                assert (package.parent / name).read_bytes() == archive.read(name), name
        run([sys.executable, '-I', '-m', 'pip', 'check'], root, 'pip-check')
        run([str(console), '--help'], root, 'console-help')
        results.append(dict(check='installed wheel sources/assets and console', files=len(files), **location))
        raw = next((REPO / 'inbox').glob('*.eml')).read_bytes()
        source = root / 'original.eml'; source.write_bytes(raw)
        numeric = {}

        def check_case(case):
            assert (case / 'input.eml').read_bytes() == raw
            execution = read(case / 'execution.json')
            assert execution['status'] == 'completed' and execution['no_egress'] is True
            assert not execution['blocked_operations'], execution
            assert not (case / 'detonation').exists()
            run([str(console), 'verify', '--case', str(case)], root, case.parent.parent.name + '-verify')
            score = read(case / 'report/score.json')
            assert score['calibrated'] is False
            assert score['coverage'] == read(case / 'analysis_coverage.json')
            return {key: score[key] for key in ('profile', 'score_components', 'raw_score', 'score', 'decision_score', 'decision')}

        for command in ('quick', 'analyze', 'full', 'forensic', 'trace'):
            directory = root / command; directory.mkdir()
            arguments = [str(console), command]
            arguments += ['--src', str(source)] if command == 'trace' else [str(source)]
            # quick always enforces no-egress; all other presets request it explicitly.
            if command != 'quick': arguments += ['--no-egress']
            run(arguments, directory, command)
            case, = (directory / 'cases').glob('case-*')
            numeric[command] = check_case(case)
            control, = (directory / 'jobs').glob('analysis_*/supervisor.json')
            assert read(control)['tree_stopped'] is True
            before = {p.relative_to(case).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in case.rglob('*') if p.is_file()}
            run([str(console), 'export', '--case', str(case), '--format', 'zip'], root, command + '-zip')
            with zipfile.ZipFile(str(case) + '.zip') as archive:
                for name in before:
                    assert archive.read(case.name + '/' + name) == (case / name).read_bytes(), name
            assert before == {p.relative_to(case).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in case.rglob('*') if p.is_file()}
        assert numeric['quick'] == numeric['analyze'] == numeric['trace']
        assert numeric['full'] == numeric['forensic']
        results.append(dict(check='five installed CLI presets, seals, complete ZIP bytes', numeric=numeric))

        timed = root / 'deadline'; timed.mkdir()
        run([str(console), 'full', str(source), '--no-egress', '--deadline', '.05'], timed,
            'deadline', success=False)
        supervisor, = (timed / 'jobs').glob('analysis_*/supervisor.json')
        assert read(supervisor)['status'] == 'timed_out' and read(supervisor)['tree_stopped'] is True
        results.append(dict(check='installed CLI deadline and stopped tree', supervisor=read(supervisor)))

        data = root / 'api'; data.mkdir()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(path, body=None, content_type='application/json'):
            with client.open(urllib.request.Request(base + path, data=body,
                    headers={'Content-Type': content_type} if body is not None else {}), timeout=10) as response:
                return response.read()

        with (args.output / 'api.log').open('wb') as stream:
            server = subprocess.Popen([sys.executable, '-I', '-m', 'uvicorn', 'paw.web.api:app',
                '--host', '127.0.0.1', '--port', str(port)], cwd=data, env=env, stdout=stream, stderr=stream)
            try:
                for _ in range(200):
                    assert server.poll() is None, 'Installed API failed to start'
                    try: request('/health'); break
                    except (OSError, urllib.error.URLError): time.sleep(.1)
                else: raise TimeoutError('Installed API did not become ready')
                request('/'); request('/assets/app.js')
                boundary = 'paw-installed-r08'
                body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="original.eml"\r\n'
                        'Content-Type: message/rfc822\r\n\r\n').encode() + raw + f'\r\n--{boundary}--\r\n'.encode()
                upload = json.loads(request('/api/upload', body, 'multipart/form-data; boundary=' + boundary))
                job = json.loads(request('/api/analyze', json.dumps(dict(file_path=upload['path'],
                    profile='strict', options=dict(no_egress=True, stix=True, abuse=True))).encode()))
                for _ in range(600):
                    status = json.loads(request('/api/analysis/' + job['analysis_id']))
                    if status['status'] not in {'queued', 'running'}: break
                    time.sleep(.1)
                assert status['status'] == 'completed' and status['supervisor']['tree_stopped'] is True, status
                case = data / 'cases' / status['case_id']
                assert check_case(case) == numeric['full']
                detail = json.loads(request('/api/cases/' + case.name))
                assert detail['score'] == read(case / 'report/score.json')
                with zipfile.ZipFile(io.BytesIO(request('/api/export/' + case.name))) as archive:
                    for path in case.rglob('*'):
                        if path.is_file(): assert archive.read(path.relative_to(case).as_posix()) == path.read_bytes()
                results.append(dict(check='installed loopback API, static assets, worker, score parity and ZIP',
                                    supervisor=status['supervisor']))
            finally:
                server.terminate()
                try: server.wait(timeout=10)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=10)
        assert source.read_bytes() == raw
    report = dict(status='PASS', python=sys.version, checks=results,
                  limits='Offline public original only; no accuracy, browser, active provider or OS isolation acceptance.')
    (args.output / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
