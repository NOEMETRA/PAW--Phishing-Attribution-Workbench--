"""Trusted serial broker for one opaque HTML file in a fresh no-NIC Chrome VM."""
import ctypes
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time
import tty

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser_policy import chrome_arguments, JOB_MEMORY, JOB_TASKS, MAX_HTML, MAX_DOM, MAX_NETLOG, JOB_SECONDS
from browser_sandbox import RendererWitness

GROUP = Path('/sys/fs/cgroup/paw-browser-job')
WORK = Path('/run/paw-browser-job')
MOUNT = Path('/mnt/paw-browser-input')
MARKER = Path('/var/lib/paw-browser-job-used')
USED = False
ACTIVE = None
STARTED = None
CONFIG = None
DONE = None
OUTPUT = {'stdout': bytearray(), 'stderr': bytearray()}
SELECTOR = selectors.DefaultSelector()
WITNESS = RendererWitness()
SANDBOX = WITNESS.flags()


def require(value, reason):
    if not value: raise ValueError(reason)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1024**2), b''): h.update(raw)
    return h.hexdigest()


def emit(value):
    raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    require(len(raw) <= 60000, 'browser_response_budget')
    print('PAW14 ' + raw, flush=True)


class DOM(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.in_title = False; self.title = ''; self.counts = {k: 0 for k in ['script', 'form', 'input', 'iframe', 'a']}
    def handle_starttag(self, tag, attrs):
        if tag == 'title': self.in_title = True
        if tag in self.counts: self.counts[tag] += 1
    def handle_endtag(self, tag):
        if tag == 'title': self.in_title = False
    def handle_data(self, data):
        if self.in_title: self.title = (self.title + data)[:32]


def inspect():
    require(sorted(os.listdir('/sys/class/net')) == ['lo'], 'browser_network_interface')
    info = json.loads(Path('/etc/paw-browser-image.json').read_text())
    return {'chrome_version': info['chrome_version'], 'chrome_binary_sha256': digest('/opt/google/chrome/chrome'),
            'kernel_release': os.uname().release, 'network_interfaces': ['lo'], 'prior_marker_absent': not MARKER.exists()}


def observe_sandbox():
    WITNESS.observe(GROUP)
    SANDBOX.update(WITNESS.flags())

def start():
    global USED, ACTIVE, STARTED, CONFIG
    require(not USED and not MARKER.exists() and sorted(os.listdir('/sys/class/net')) == ['lo'], 'fresh_single_browser_job_only')
    USED = True; MARKER.write_text('used\n'); MARKER.chmod(0o600)
    CONFIG = json.loads(Path('/etc/paw-browser-job.json').read_text())
    require(type(CONFIG) is dict and set(CONFIG) == {'source_sha256', 'source_bytes', 'job_sha256', 'request_id'}, 'browser_job_config')
    MOUNT.mkdir(parents=True, exist_ok=True)
    subprocess.run(['/usr/bin/mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/PAWBROWSERINPUT', str(MOUNT)], check=True, timeout=10)
    source = MOUNT / 'input.html'
    require(source.is_file() and not source.is_symlink() and source.stat().st_size == CONFIG['source_bytes'] and
            0 < source.stat().st_size <= MAX_HTML and digest(source) == CONFIG['source_sha256'], 'browser_exact_input_digest')
    WORK.mkdir(mode=0o700); os.chown(WORK, 65534, 65534)
    Path('/sys/fs/cgroup/cgroup.subtree_control').write_text('+cpu +memory +pids'); GROUP.mkdir()
    for name, value in {'memory.max': str(JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(JOB_TASKS), 'memory.oom.group': '1'}.items():
        (GROUP / name).write_text(value)
    parent = os.getpid()
    def admission():
        (GROUP / 'cgroup.procs').write_text(str(os.getpid()))
        for key, limit in [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 32*1024**2), (resource.RLIMIT_NOFILE, 512)]:
            resource.setrlimit(key, (limit, limit))
        os.setgroups([]); os.setgid(65534); os.setuid(65534)
        libc = ctypes.CDLL(None)
        if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent: os._exit(125)
    ACTIVE = subprocess.Popen(chrome_arguments(source, WORK/'profile', WORK/'netlog.json'), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=admission,
        env={'PATH': '/usr/bin:/bin', 'HOME': str(WORK), 'LANG': 'C.UTF-8', 'XDG_CONFIG_HOME': str(WORK), 'XDG_CACHE_HOME': str(WORK)})
    for name in OUTPUT:
        stream = getattr(ACTIVE, name); os.set_blocking(stream.fileno(), False); SELECTOR.register(stream, selectors.EVENT_READ, name)
    STARTED = time.monotonic()
    return {'started': True, 'source_sha256': CONFIG['source_sha256'], 'job_sha256': CONFIG['job_sha256'],
            'prior_marker_absent': True, 'pid': ACTIVE.pid,
            'job_limits': {'memory.max': str(JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(JOB_TASKS)}}


def drain():
    overflow = False
    for key, _ in SELECTOR.select(timeout=0):
        name = key.data; limit = MAX_DOM if name == 'stdout' else 8192
        try: raw = os.read(key.fileobj.fileno(), 8192)
        except BlockingIOError: continue
        if not raw: SELECTOR.unregister(key.fileobj); continue
        if len(OUTPUT[name]) + len(raw) > limit: overflow = True
        OUTPUT[name].extend(raw[:max(0, limit-len(OUTPUT[name]))])
    return overflow


def finish(status):
    global DONE
    if DONE is not None: return DONE
    (GROUP/'cgroup.kill').write_text('1'); ACTIVE.wait(timeout=3)
    end = time.monotonic() + 3
    while (GROUP/'pids.current').read_text().strip() != '0' and time.monotonic() < end: time.sleep(.02)
    require((GROUP/'pids.current').read_text().strip() == '0', 'browser_guest_writers_alive')
    overflow = False
    for _ in range(100):
        overflow |= drain()
        if not SELECTOR.get_map(): break
    events = {name: (GROUP/name).read_text().strip() for name in ['memory.events', 'pids.events', 'pids.current']}
    memory = dict(row.split() for row in events['memory.events'].splitlines())
    netlog = WORK/'netlog.json'; net_bytes = netlog.stat().st_size if netlog.exists() else 0
    if int(memory.get('oom_kill', '0')): status = 'memory_budget'
    elif overflow or net_bytes > MAX_NETLOG: status = 'output_budget'
    elif status == 'completed' and not all(SANDBOX.values()): status = 'failed'
    observations = {'dom_bytes': len(OUTPUT['stdout']), 'dom_sha256': hashlib.sha256(OUTPUT['stdout']).hexdigest(),
                    'sandbox': SANDBOX, 'network_interfaces': ['lo'], 'scope': 'untrusted guest observations, no verdict'}
    if status == 'completed':
        parser = DOM(); parser.feed(bytes(OUTPUT['stdout']).decode('utf-8', 'replace'))
        observations.update(title=parser.title, tags=parser.counts)
    if netlog.exists() and net_bytes <= MAX_NETLOG:
        data = netlog.read_bytes(); observations['netlog_sha256'] = hashlib.sha256(data).hexdigest()
        try: observations['network_event_count'] = len(json.loads(data).get('events', []))
        except (ValueError, TypeError, AttributeError): observations['network_events_unavailable'] = True
    observations_raw = (json.dumps(observations, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode()
    require(len(observations_raw) <= 1024, 'browser_observations_budget')
    record = {'name': 'observations.json', 'bytes_hex': observations_raw.hex(), 'sha256': hashlib.sha256(observations_raw).hexdigest(),
              'scope': 'opaque untrusted guest browser output'}
    DONE = {'done': True, 'status': status, 'returncode': ACTIVE.returncode, 'records': [] if status == 'cancelled' else [record],
            'writers_stopped': True, 'events': events, 'output_truncated': status == 'output_budget', 'sandbox': SANDBOX}
    return DONE


def poll():
    require(ACTIVE is not None, 'browser_not_started')
    if DONE is not None: return DONE
    observe_sandbox(); overflow = drain(); code = ACTIVE.poll()
    netlog = WORK/'netlog.json'
    if overflow or (netlog.exists() and netlog.stat().st_size > MAX_NETLOG): return finish('output_budget')
    if time.monotonic()-STARTED > JOB_SECONDS: return finish('timeout')
    if code is not None: return finish('completed' if code == 0 else 'failed')
    return {'done': False}


def reserve_control_console():
    """Keep guest printk in its ring buffer, off the broker's serial wire."""
    path = Path('/proc/sys/kernel/printk')
    levels = path.read_text().split()
    require(len(levels) == 4 and all(v.isdecimal() for v in levels), 'browser_console_levels')
    path.write_text('0 ' + ' '.join(levels[1:]) + '\n')
    require(path.read_text().split() == ['0', *levels[1:]], 'browser_console_not_reserved')


def main():
    reserve_control_console()
    os.chmod('/dev/ttyS0', 0o600); tty.setraw(sys.stdin.fileno())
    require(sorted(os.listdir('/sys/class/net')) == ['lo'], 'browser_network_present')
    emit({'ready': True, 'network_interfaces': ['lo']})
    try:
        for line in sys.stdin:
            ident = None
            try:
                require(len(line) <= 4096, 'browser_command_budget'); command = json.loads(line); ident = command['id']
                require(type(command) is dict and set(command) == {'id', 'op'} and type(ident) is int, 'browser_command_shape')
                op = command['op']
                if op == 'inspect' and not USED: value = inspect()
                elif op == 'start': value = start()
                elif op == 'poll': value = poll()
                elif op == 'cancel' and ACTIVE is not None: value = finish('cancelled')
                else: raise ValueError('unsupported_browser_operation')
                emit({'id': ident, 'ok': True, 'data': value})
            except Exception as error: emit({'id': ident, 'ok': False, 'error': type(error).__name__+':'+str(error)[:4096]})
    finally:
        if ACTIVE is not None:
            try: (GROUP/'cgroup.kill').write_text('1')
            except FileNotFoundError: pass


if __name__ == '__main__': main()
