"""Trusted no-NIC control plane for fixed benign adversarial guest fixtures."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import tty

HERE = Path(__file__).resolve().parent
WORK = Path('/tmp/paw-gate-fixture')
GROUP = Path('/sys/fs/cgroup/paw-synthetic-job')
CONFIG = Path('/etc/paw-gate-fixture.json')
ACTIVE = None


def no_network():
    if sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']:
        raise ValueError('no_nic_required')


def emit(value):
    data = ('PAW14 ' + json.dumps(value) + '\n').encode()
    while data: data = data[os.write(1, data):]


def group():
    GROUP.mkdir()
    for name, value in [('memory.max', str(64 * 1024**2)), ('memory.swap.max', '0'),
                        ('memory.oom.group', '1'), ('pids.max', '16'), ('cpu.max', '20000 100000')]:
        (GROUP / name).write_text(value)


def clean():
    if GROUP.exists():
        (GROUP / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 2
        while (GROUP / 'pids.current').read_text().strip() != '0' and time.monotonic() < deadline: time.sleep(.02)
        if (GROUP / 'pids.current').read_text().strip() != '0': raise ValueError('guest_writers_alive')
        GROUP.rmdir()


def spawn(case):
    no_network(); clean(); group()
    config = json.loads(CONFIG.read_text()); config['cgroup'] = str(GROUP); CONFIG.write_text(json.dumps(config))
    def admission():
        (GROUP / 'cgroup.procs').write_text(str(os.getpid()))
        resource.setrlimit(resource.RLIMIT_AS, (192 * 1024**2, 192 * 1024**2))
        maximum = 1024 if case == 'file' else 64 * 1024**2 if case == 'storage' else 4096
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        os.setgroups([]); os.setgid(65534); os.setuid(65534)
        if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0: os._exit(125)
    return subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(HERE / 'gate_payload.py'), case],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=admission,
                            start_new_session=True, cwd=WORK)


def execute(case):
    child = spawn(case)
    try:
        stdout, stderr = child.communicate(timeout=8)
        if len(stdout) > 8192 or len(stderr) > 8192: raise ValueError('job_output_budget')
        events = {name: (GROUP / name).read_text().strip() for name in
                  ['memory.events', 'memory.peak', 'pids.events', 'pids.peak', 'pids.current']}
        if case == 'memory':
            if child.returncode != -signal.SIGKILL or int(dict(line.split() for line in events['memory.events'].splitlines())['oom_kill']) < 1:
                raise ValueError('FAILED_INJECTION_guest_oom')
            data = {'actual_guest_cgroup_oom': True}
        else:
            if child.returncode != 0: raise ValueError('job_failed:' + stderr.decode(errors='replace')[:256])
            data = json.loads(stdout)
        if (GROUP / 'pids.current').read_text().strip() != '0': raise ValueError('child_tree_not_stopped')
        return {'case': case, 'data': data, 'events': events, 'returncode': child.returncode, 'child_reaped': True}
    finally:
        if child.poll() is None: child.kill()
        child.wait(timeout=2); clean()


def dispatch(command):
    global ACTIVE
    op = command['op']; no_network()
    if op in {'boundary', 'fork', 'memory', 'file', 'reset'}:
        return execute(op)
    if op == 'outputs':
        data = b'<script>owned inert output</script>'
        valid = {'name': 'owned.html', 'bytes_hex': data.hex(), 'sha256': hashlib.sha256(data).hexdigest(), 'scope': 'opaque synthetic'}
        return {'valid': [valid], 'invalid': [[{**valid, 'name': '../escape'}], [{**valid, 'sha256': '0' * 64}],
                                           [valid, valid], [{**valid, 'bytes_hex': '00' * 1025}]]}
    if op == 'stubborn':
        ACTIVE = spawn('stubborn')
        import select
        if not select.select([ACTIVE.stdout], [], [], 3)[0]: raise ValueError('stubborn_start_deadline')
        line = ACTIVE.stdout.readline(1025)
        if len(line) > 1024: raise ValueError('stubborn_frame')
        return json.loads(line)
    if op == 'corrupt':
        os.write(1, b'PAW14 []\n')
        return None
    if op == 'storage':
        ACTIVE = spawn('storage')
        return {'started_pid': ACTIVE.pid}
    raise ValueError('fixed_synthetic_operations_only')


def main():
    no_network(); tty.setraw(0)
    WORK.mkdir(mode=0o700, exist_ok=True); os.chown(WORK, 65534, 65534)
    positive = WORK / 'positive.txt'; positive.write_text('owned positive control'); os.chown(positive, 65534, 65534)
    emit({'ready': True, 'network_interfaces': ['lo']})
    while True:
        raw = sys.stdin.buffer.readline(4097)
        if not raw: return
        if len(raw) > 4096: raise ValueError('command_budget')
        command = json.loads(raw)
        try:
            data = dispatch(command)
            if command['op'] != 'corrupt': emit({'id': command['id'], 'ok': True, 'data': data})
        except Exception as error:
            emit({'id': command.get('id'), 'ok': False, 'error': str(error)})


if __name__ == '__main__': main()
