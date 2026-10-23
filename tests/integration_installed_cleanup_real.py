"""Crash the owned loopback API during a real installed no-egress worker.

The outer observer deliberately suspends that identified POSIX worker, kills
its API supervisor, and verifies the acceptance harness stops it and preserves
the failed run. No engine/result is mocked and no detonation is requested.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import psutil

from integration_installed_package_real import validation_directory

REPO = Path(__file__).resolve().parents[1]


def alive(process):
    try:
        return process.is_running() and process.status() not in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}
    except psutil.NoSuchProcess:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'temporary'; temporary.mkdir()
    env = dict(os.environ, TMPDIR=str(temporary), PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    observed = None
    worker = server = harness = None
    owned = {}
    try:
        with (output / 'harness.log').open('wb') as log:
            harness = subprocess.Popen([sys.executable, '-I', str(REPO / 'tests/integration_installed_package_real.py'),
                '--wheel', str(args.wheel.resolve()), '--output', str(output / 'harness')],
                cwd=output, env=env, stdout=log, stderr=log)
            parent = psutil.Process(harness.pid)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                assert harness.poll() is None, 'Harness exited before controlled failure'
                for child in parent.children(recursive=True):
                    try:
                        owned[child.pid] = (child, child.create_time())
                        command = child.cmdline()
                        if 'uvicorn' in command: server = child
                        if 'paw.web.worker' not in command or Path(child.cwd()).name != 'api': continue
                        request = Path(command[command.index('paw.web.worker') + 1])
                        spec = json.loads(request.read_text())
                        assert spec['no_egress'] is True
                        control = request.parent / request.name.removesuffix('.request.json')
                        identity_bytes = (control / 'process.json').read_bytes()
                        identity = json.loads(identity_bytes)
                        assert identity['pid'] == child.pid and identity['created_at'] == child.create_time()
                        assert identity['pgid'] == identity['sid'] == child.pid
                        child.suspend(); worker = child
                        data = Path(child.cwd()).parent
                        original = Path(spec['file_path']); raw = original.read_bytes()
                        observed = dict(data_directory=str(data), worker_pid=child.pid,
                            identity=identity, original_sha256=hashlib.sha256(raw).hexdigest())
                        (output / 'before-crash.json').write_text(json.dumps(observed, indent=2), encoding='utf-8')
                        server.kill()
                        break
                    except (psutil.NoSuchProcess, FileNotFoundError): continue
                if observed: break
                time.sleep(.005)
            assert observed, 'No real API worker identity observed'
            assert harness.wait(timeout=90) != 0, 'Injected API crash was hidden as success'
            assert not alive(worker), 'Acceptance harness left a registered worker alive'
            cleanup = json.loads((output / 'harness/cleanup.json').read_text())
            assert cleanup['tree_stopped'] is True and cleanup['preserved'] is True, cleanup
            assert data.is_dir() and original.read_bytes() == raw
            assert (control / 'process.json').read_bytes() == identity_bytes
            assert json.loads((control / 'supervisor.json').read_text())['tree_stopped'] is True
            # The test has now independently confirmed stop and preservation.
            shutil.rmtree(data)
    finally:
        if harness is not None and harness.poll() is None:
            harness.kill(); harness.wait(timeout=10)
        for process, created in owned.values():
            try:
                if process.create_time() == created and alive(process): process.kill()
            except psutil.NoSuchProcess: pass
        psutil.wait_procs([process for process, _ in owned.values()], timeout=5)

    # An incomplete trusted control journal has no asserted live writer. It
    # exercises refusal to delete when recovery cannot establish shutdown.
    unknown = output / 'unknown'; unknown.mkdir()
    try:
        with validation_directory(unknown, env) as data:
            control = data / 'api/jobs/analysis_unknown'; control.mkdir(parents=True)
            (control / 'worker.log').write_bytes(b'Preserve this stopped-state-unknown fixture')
    except AssertionError as error:
        assert 'shutdown unconfirmed' in str(error), error
    else:
        raise AssertionError('Unknown worker shutdown was accepted')
    cleanup = json.loads((unknown / 'cleanup.json').read_text())
    assert cleanup['tree_stopped'] is False and cleanup['preserved'] is True
    assert (control / 'worker.log').read_bytes() == b'Preserve this stopped-state-unknown fixture'
    shutil.rmtree(data)  # This second fixture deliberately had no actual process.
    report = dict(status='PASS', api_crash=dict(worker_stopped=True, failed_data_preserved=True,
        original_and_identity_bytes_preserved=True), unknown_shutdown_refuses_success_and_deletion=True,
        scope='Owned POSIX loopback API and actual installed offline worker; no OS isolation or detonation claim')
    (output / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
