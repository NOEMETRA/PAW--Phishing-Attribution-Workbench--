"""Trusted controller for a single immutable job; no arbitrary host execution."""
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import sys
import time
import tty

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_guest import GROUP, WORK, clean, emit, group, isolated_process, no_network

ACTIVE = None
OUTPUT = {'stdout': bytearray(), 'stderr': bytearray()}
SELECTOR = selectors.DefaultSelector()
STARTED = None
USED = False
LIMIT = 1024


def start():
    global ACTIVE, STARTED, USED
    if USED: raise ValueError('single_job_only')
    USED = True
    clean(); group()
    source = Path('/opt/paw-input/sample.py')
    config = json.loads(Path('/etc/paw-input.json').read_text())
    if hashlib.sha256(source.read_bytes()).hexdigest() != config['source_sha256']:
        raise ValueError('guest_input_digest')
    def admission():
        import ctypes
        (GROUP / 'cgroup.procs').write_text(str(os.getpid()))
        for key, maximum in [(resource.RLIMIT_AS, 192 * 1024**2), (resource.RLIMIT_FSIZE, 4096),
                             (resource.RLIMIT_CPU, 2), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 32)]:
            resource.setrlimit(key, (maximum, maximum))
        os.setgroups([]); os.setgid(65534); os.setuid(65534)
        if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0: os._exit(125)
    ACTIVE = isolated_process(['/usr/bin/python3', '-I', '-B', str(source)], admission, WORK)
    for name in OUTPUT:
        pipe = getattr(ACTIVE, name); os.set_blocking(pipe.fileno(), False)
        SELECTOR.register(pipe, selectors.EVENT_READ, name)
    STARTED = time.monotonic()
    return {'started': True, 'pid': ACTIVE.pid, 'source_sha256': config['source_sha256'],
            'job_sha256': config['job_sha256'], 'prior_marker_absent': not (WORK / 'previous-job-marker').exists()}


def poll():
    if ACTIVE is None: raise ValueError('job_not_started')
    overflow = False
    for key, _ in SELECTOR.select(timeout=0):
        name = key.data; data = os.read(key.fileobj.fileno(), LIMIT + 1)
        if not data: SELECTOR.unregister(key.fileobj); continue
        if len(OUTPUT[name]) + len(data) > LIMIT: overflow = True
        OUTPUT[name].extend(data[:max(0, LIMIT - len(OUTPUT[name]))])
    status = ACTIVE.poll()
    expired = time.monotonic() - STARTED > 4
    if status is None and not overflow and not expired: return {'done': False}
    # Kill the complete cgroup even when the leader exited with live descendants.
    (GROUP / 'cgroup.kill').write_text('1'); ACTIVE.wait(timeout=2)
    deadline = time.monotonic() + 2
    while (GROUP / 'pids.current').read_text().strip() != '0' and time.monotonic() < deadline: time.sleep(.02)
    if (GROUP / 'pids.current').read_text().strip() != '0': raise ValueError('guest_writers_alive')
    for key, _ in SELECTOR.select(timeout=0):
        name = key.data; data = os.read(key.fileobj.fileno(), LIMIT + 1)
        if len(OUTPUT[name]) + len(data) > LIMIT: overflow = True
        OUTPUT[name].extend(data[:max(0, LIMIT - len(OUTPUT[name]))])
    events = {name: (GROUP / name).read_text().strip() for name in ['memory.events', 'pids.events', 'pids.current']}
    clean()
    records = [{'name': name + '.bin', 'bytes_hex': bytes(data).hex(),
                'sha256': hashlib.sha256(data).hexdigest(), 'scope': 'opaque untrusted job output'}
               for name, data in OUTPUT.items()]
    return {'done': True, 'returncode': ACTIVE.returncode, 'status': 'output_budget' if overflow else 'timeout' if expired else 'completed' if status == 0 else 'failed',
            'events': events, 'records': records, 'writers_stopped': True, 'output_truncated': overflow}


def main():
    no_network(); tty.setraw(0)
    WORK.mkdir(mode=0o700, exist_ok=True); os.chown(WORK, 65534, 65534)
    emit({'ready': True, 'network_interfaces': ['lo']})
    while True:
        raw = sys.stdin.buffer.readline(1025)
        if not raw: return
        if len(raw) > 1024: raise ValueError('control_budget')
        command = json.loads(raw)
        try:
            no_network()
            if set(command) != {'id', 'op'}: raise ValueError('control_shape')
            if command['op'] == 'start': data = start()
            elif command['op'] == 'poll': data = poll()
            else: raise ValueError('unsupported_operation')
            emit({'id': command['id'], 'ok': True, 'data': data})
        except Exception as error: emit({'id': command.get('id'), 'ok': False, 'error': str(error)})


if __name__ == '__main__': main()
