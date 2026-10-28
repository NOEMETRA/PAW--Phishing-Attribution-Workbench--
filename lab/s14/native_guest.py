"""Trusted one-use shell/AMD64 controller, usable only in the signed no-NIC guest.

No specimen is interpreted by Python. A ready/go pipe lets the trusted parent
observe the dropped child in /proc before fixed-path guest execve, without a
blocking Popen preexec handshake. The host must still prove whole-VM stop.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import selectors
import signal
import stat
import sys
import time
import tty

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_guest import GROUP, WORK, clean, emit, group, no_network

CONFIG = Path('/etc/paw-native.json')
SOURCE = Path('/opt/paw-input/sample.bin')
KERNEL = '6.8.0-147-generic'
SHELL = 'linux-posix-shell-offline-v1'
ELF = 'linux-x86_64-elf-offline-v1'
INTERPRETERS = {None, '/lib64/ld-linux-x86-64.so.2', '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'}
LIMITS = {'memory.max': str(64*1024**2), 'memory.swap.max': '0', 'memory.oom.group': '1',
          'pids.max': '16', 'cpu.max': '20000 100000'}
RLIMITS = {resource.RLIMIT_AS: 192*1024**2, resource.RLIMIT_FSIZE: 4096,
           resource.RLIMIT_CPU: 2, resource.RLIMIT_CORE: 0, resource.RLIMIT_NOFILE: 32}
ACTIVE = None
USED = False
STARTED = None
OUTPUT = {'stdout': bytearray(), 'stderr': bytearray()}
SELECTOR = None
STREAMS = []
BOUNDARY = None
LIMIT = 1024


def require(value, reason):
    if not value: raise ValueError(reason)


def guest_only():
    require(os.geteuid() == 0 and os.uname().release == KERNEL, 'native_trusted_guest_required')
    no_network()


def read_source():
    raw = CONFIG.read_bytes(); require(len(raw) <= 4096, 'native_seed_budget')
    config = json.loads(raw)
    require(type(config) is dict and set(config) == {'schema', 'profile', 'source_sha256', 'source_bytes',
            'job_sha256', 'request_id', 'elf_interpreter'} and config['schema'] == 'paw-native-seed-v1', 'native_seed_shape')
    require(type(config['profile']) is str and config['profile'] in {SHELL, ELF} and
            all(type(config[k]) is str and re.fullmatch('[0-9a-f]{64}', config[k]) for k in ['source_sha256', 'job_sha256']) and
            type(config['request_id']) is str and re.fullmatch('[0-9a-f]{32}', config['request_id']), 'native_seed_identity')
    maximum = 64*1024 if config['profile'] == SHELL else 1024**2
    require(type(config['source_bytes']) is int and 0 < config['source_bytes'] <= maximum and
            (config['elf_interpreter'] is None or type(config['elf_interpreter']) is str) and
            config['elf_interpreter'] in INTERPRETERS and
            (config['profile'] != SHELL or config['elf_interpreter'] is None), 'native_seed_profile')
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                stat.S_IMODE(before.st_mode) == (0o444 if config['profile'] == SHELL else 0o555) and
                before.st_size == config['source_bytes'], 'native_input_protection')
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum+1-len(data)))
            if not chunk: break
            data.extend(chunk)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
                len(data) == config['source_bytes'] and hashlib.sha256(data).hexdigest() == config['source_sha256'],
                'native_input_digest')
    finally: os.close(fd)
    if config['profile'] == SHELL:
        data.decode('utf-8', 'strict'); require(b'\0' not in data, 'native_shell_nul')
    else: require(data[:7] == b'\x7fELF\x02\x01\x01', 'native_elf_identity')
    return config


def inspect():
    guest_only(); config = read_source()
    interpreter = '/bin/dash' if config['profile'] == SHELL else config['elf_interpreter']
    return {**config, 'kernel_release': KERNEL, 'network_interfaces': ['lo'],
            'prior_marker_absent': not (WORK/'previous-job-marker').exists(),
            'guest_controller_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'interpreter': interpreter,
            'interpreter_sha256': None if interpreter is None else hashlib.sha256(Path(interpreter).read_bytes()).hexdigest()}


def argv_for(config):
    require(config['profile'] in {SHELL, ELF}, 'native_fixed_profile')
    return ['/bin/dash', '--', str(SOURCE)] if config['profile'] == SHELL else [str(SOURCE)]


def child_admission():
    (GROUP/'cgroup.procs').write_text(str(os.getpid()))
    for key, maximum in RLIMITS.items(): resource.setrlimit(key, (maximum, maximum))
    last = int(Path('/proc/sys/kernel/cap_last_cap').read_text()); require(0 <= last <= 63, 'native_capability_range')
    libc = ctypes.CDLL(None, use_errno=True)
    # PR_CAPBSET_DROP is performed while CAP_SETPCAP is still effective.
    for cap in range(last+1): require(libc.prctl(24, cap, 0, 0, 0) == 0, 'native_drop_bounding_set')
    os.setgroups([]); os.setgid(65534); os.setuid(65534)
    require(libc.prctl(38, 1, 0, 0, 0) == 0, 'native_no_new_privileges')


def validate_status(raw):
    require(type(raw) is str and len(raw) <= 16384, 'native_status_budget')
    fields = {}
    for line in raw.splitlines():
        if ':' not in line: continue
        key, value = line.split(':', 1); require(key not in fields, 'native_duplicate_status'); fields[key] = value.split()
    require(fields.get('Uid') == ['65534']*4 and fields.get('Gid') == ['65534']*4 and
            fields.get('Groups') == [] and fields.get('NoNewPrivs') == ['1'], 'native_uid_groups_nnp')
    for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        value = fields.get(key)
        require(type(value) is list and len(value) == 1 and re.fullmatch('[0-9a-fA-F]{1,16}', value[0]) and
                int(value[0], 16) == 0, 'native_capabilities')
    return {'uid': 65534, 'gid': 65534, 'groups': [], 'no_new_privileges': True, 'capabilities': 'all zero including bounding'}


def observe_boundary(pid):
    proc = Path('/proc')/str(pid)
    def identity():
        raw = (proc/'stat').read_text(); return raw.rsplit(')', 1)[1].split()[19]
    before = identity(); result = validate_status((proc/'status').read_text())
    fields = (proc/'stat').read_text().rsplit(')', 1)[1].split()
    require(fields[2:5] == [str(pid), str(pid), '0'], 'native_session_or_controlling_tty')
    require((proc/'cgroup').read_text().strip() == '0::/'+GROUP.name and
            str(pid) in (GROUP/'cgroup.procs').read_text().split() and os.readlink(proc/'fd/0') == '/dev/null',
            'native_child_cgroup_or_stdin')
    limits = {name: (GROUP/name).read_text().strip() for name in LIMITS}
    require(limits == LIMITS, 'native_effective_cgroup_limits')
    expected = {'Max cpu time': 2, 'Max file size': 4096, 'Max core file size': 0,
                'Max open files': 32, 'Max address space': 192*1024**2}
    observed = {}
    for line in (proc/'limits').read_text().splitlines()[1:]:
        for name, maximum in expected.items():
            if line.startswith(name+' '):
                values = line[len(name):].split(); require(values[:2] == [str(maximum)]*2, 'native_effective_rlimits')
                observed[name] = maximum
    require(observed == expected and identity() == before, 'native_child_identity_or_rlimits')
    return {**result, 'pid': pid, 'pid_identity': before, 'stdin': '/dev/null', 'cgroup': '/'+GROUP.name,
            'limits': limits, 'rlimits': observed, 'session_id': pid, 'controlling_tty': None,
            'observed_before_exec': True}


def _reap(pid, seconds=2):
    end = time.monotonic()+seconds
    while time.monotonic() < end:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid: return os.waitstatus_to_exitcode(status)
        time.sleep(.01)
    raise ValueError('native_child_not_reaped')


def spawn(config):
    pipes = []; opened = set(); child = None; transferred = False
    try:
        for _ in range(4):
            pair = os.pipe2(os.O_CLOEXEC); pipes.append(pair); opened.update(pair)
        (out_r, out_w), (err_r, err_w), (ready_r, ready_w), (go_r, go_w) = pipes
        null = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC); opened.add(null)
        child = os.fork()
        if child == 0:
            try:
                os.setsid()
                for name in ['SIGPIPE', 'SIGXFSZ', 'SIGXCPU']:
                    signal.signal(getattr(signal, name), signal.SIG_DFL)
                os.dup2(null, 0); os.dup2(out_w, 1); os.dup2(err_w, 2)
                keep = sorted([ready_w, go_r]); low = 3
                for fd in keep: os.closerange(low, fd); low = fd+1
                os.closerange(low, 1024*1024)
                child_admission(); os.write(ready_w, b'R'); os.close(ready_w)
                require(os.read(go_r, 1) == b'G', 'native_missing_parent_go'); os.close(go_r)
                os.execve(argv_for(config)[0], argv_for(config), {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8'})
            except BaseException:
                os.write(2, b'native child admission/exec refused\n'); os._exit(126)
        for fd in [null, out_w, err_w, ready_w, go_r]: os.close(fd); opened.remove(fd)
        require(select.select([ready_r], [], [], 3)[0] and os.read(ready_r, 1) == b'R', 'native_child_admission_deadline')
        proof = observe_boundary(child)
        os.write(go_w, b'G')
        for fd in [ready_r, go_w]: os.close(fd); opened.remove(fd)
        transferred = True
        return {'pid': child, 'returncode': None, 'boundary': proof}, [out_r, err_r]
    except BaseException:
        if child:
            try: os.kill(child, signal.SIGKILL)
            except ProcessLookupError: pass
            _reap(child)
        raise
    finally:
        if not transferred:
            for fd in opened:
                try: os.close(fd)
                except OSError: pass


def start():
    global USED, ACTIVE, STARTED, SELECTOR, STREAMS, BOUNDARY
    guest_only(); require(not USED, 'native_single_job_only'); USED = True
    proof = inspect(); require(proof['prior_marker_absent'], 'native_reset_marker_survived')
    clean(); group(); config = read_source()
    try:
        ACTIVE, STREAMS = spawn(config); BOUNDARY = ACTIVE['boundary']; STARTED = time.monotonic()
        SELECTOR = selectors.DefaultSelector()
        for name, fd in zip(OUTPUT, STREAMS): os.set_blocking(fd, False); SELECTOR.register(fd, selectors.EVENT_READ, name)
    except BaseException:
        if ACTIVE is not None and ACTIVE['returncode'] is None:
            try: os.kill(ACTIVE['pid'], signal.SIGKILL)
            except ProcessLookupError: pass
            ACTIVE['returncode'] = _reap(ACTIVE['pid'])
        clean(); raise
    return {'started': True, 'pid': ACTIVE['pid'], 'source_sha256': config['source_sha256'],
            'job_sha256': config['job_sha256'], 'profile': config['profile'], 'prior_marker_absent': True,
            'boundary': BOUNDARY, 'inspection': proof}


def drain():
    overflow = False
    for key, _ in SELECTOR.select(timeout=0):
        data = os.read(key.fd, LIMIT+1); name = key.data
        if not data: SELECTOR.unregister(key.fd); continue
        if len(OUTPUT[name])+len(data) > LIMIT: overflow = True
        OUTPUT[name].extend(data[:max(0, LIMIT-len(OUTPUT[name]))])
    return overflow


def poll(cancel=False):
    require(ACTIVE is not None, 'native_job_not_started')
    overflow = drain(); code = ACTIVE['returncode']
    if code is None:
        pid, status = os.waitpid(ACTIVE['pid'], os.WNOHANG)
        if pid: code = ACTIVE['returncode'] = os.waitstatus_to_exitcode(status)
    expired = time.monotonic()-STARTED > 4
    if code is None and not overflow and not expired and not cancel: return {'done': False}
    (GROUP/'cgroup.kill').write_text('1')
    if code is None: code = ACTIVE['returncode'] = _reap(ACTIVE['pid'])
    end = time.monotonic()+2
    while (GROUP/'pids.current').read_text().strip() != '0' and time.monotonic() < end: time.sleep(.02)
    require((GROUP/'pids.current').read_text().strip() == '0', 'native_guest_writers_alive')
    overflow |= drain()
    events = {name: (GROUP/name).read_text().strip() for name in
              ['memory.events', 'memory.peak', 'pids.events', 'pids.peak', 'pids.current']}
    oom = int(dict(line.split() for line in events['memory.events'].splitlines())['oom_kill']) > 0
    for fd in STREAMS: os.close(fd)
    SELECTOR.close(); clean()
    target = WORK/'resource-file.bin'
    try:
        info = target.lstat(); file_observation = {'regular': stat.S_ISREG(info.st_mode), 'bytes': info.st_size}
    except FileNotFoundError: file_observation = None
    records = [{'name': name+'.bin', 'bytes_hex': bytes(data).hex(), 'sha256': hashlib.sha256(data).hexdigest(),
                'scope': 'opaque untrusted native output'} for name, data in OUTPUT.items()]
    status = ('memory_budget' if oom else 'output_budget' if overflow else 'cancelled' if cancel else
              'timeout' if expired else 'completed' if code == 0 else 'failed')
    return {'done': True, 'status': status, 'returncode': code, 'records': records, 'events': events,
            'boundary': BOUNDARY, 'writers_stopped': True, 'file_observation': file_observation}


def main():
    guest_only(); tty.setraw(0); WORK.mkdir(mode=0o700, exist_ok=True); os.chown(WORK, 65534, 65534)
    emit({'ready': True, 'network_interfaces': ['lo']})
    while True:
        raw = sys.stdin.buffer.readline(4097)
        if not raw: return
        require(len(raw) <= 4096, 'native_command_budget'); command = json.loads(raw)
        try:
            require(type(command) is dict and set(command) == {'id', 'op'} and
                    type(command['id']) is int and 0 < command['id'] <= 2**31 and
                    type(command['op']) is str, 'native_command_shape')
            operation = command['op']; guest_only()
            if operation == 'inspect': result = inspect()
            elif operation == 'start': result = start()
            elif operation == 'poll': result = poll()
            elif operation == 'cancel': result = poll(cancel=True)
            else: raise ValueError('native_fixed_operations_only')
            emit({'id': command['id'], 'ok': True, 'data': result})
        except Exception as error: emit({'id': command.get('id'), 'ok': False, 'error': str(error)[:256]})


if __name__ == '__main__': main()
