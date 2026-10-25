"""Trusted image provisioner inside a no-NIC guest; signed approved packages only."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
import tty

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser_policy import chrome_arguments, JOB_MEMORY, JOB_TASKS
from browser_sandbox import RendererWitness

MOUNT = Path('/mnt/paw-browser-packages')
CACHE = Path('/var/cache/apt/archives')
GROUP = Path('/sys/fs/cgroup/paw-browser-image-probe')
USED = False


def require(value, reason):
    if not value: raise ValueError(reason)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1024**2), b''): h.update(raw)
    return h.hexdigest()


def emit(value):
    encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=True)
    require(len(encoded) < 60000, 'build_response_budget')
    print('PAW14 ' + encoded, flush=True)


def probe_evidence(returncode, dom, error, observed, events, tasks, calibration=False, renderer_states=None):
    """The128-task calibration can report a measured PID refusal, never accept it."""
    require(tasks in {128, JOB_TASKS} and (not calibration or tasks == 128), 'owned_probe_task_budget')
    pid_events = dict(row.split() for row in events['pids.events'].splitlines())
    memory_events = dict(row.split() for row in events['memory.events'].splitlines())
    no_oom = all(key in memory_events and int(memory_events[key]) == 0 for key in ['oom', 'oom_kill', 'oom_group_kill'])
    no_pid_refusal = int(pid_events.get('max', '0')) == 0
    okay = returncode == 0 and len(dom) <= 65536 and b'<title>PAW-BROWSER-PROBE</title>' in dom and all(observed.values()) and no_oom and no_pid_refusal
    diagnostics = {'returncode': returncode, 'dom_bytes': len(dom), 'title_match': b'<title>PAW-BROWSER-PROBE</title>' in dom,
                   'tasks': tasks, 'events': events, 'sandbox': dict(observed), 'renderer_states': renderer_states}
    measured_pid_refusal = not no_pid_refusal and no_oom
    if not okay and calibration and measured_pid_refusal:
        return {'accepted': False, 'calibration_only': True, 'diagnostics': diagnostics}
    require(okay, 'owned_browser_probe_failed:' + json.dumps(diagnostics, separators=(',', ':')) + ':' + error.decode('utf-8', 'replace')[-1800:])
    return {**observed, 'accepted': True, 'title': 'PAW-BROWSER-PROBE',
            'dom_sha256': hashlib.sha256(dom).hexdigest(), 'source_executed': 'owned script only', 'diagnostics': diagnostics}


def probe(*, tasks=JOB_TASKS, calibration=False):
    """Only an owned title-changing script; no real page or external URL."""
    root = Path('/run/paw-browser-image-probe'); root.mkdir(mode=0o700); os.chown(root, 65534, 65534)
    html = root / 'owned.html'; html.write_text('<!doctype html><title>before</title><script>document.title="PAW-BROWSER-PROBE";</script>')
    html.chmod(0o444)
    Path('/sys/fs/cgroup/cgroup.subtree_control').write_text('+cpu +memory +pids')
    GROUP.mkdir()
    for k, v in {'memory.max': str(JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(tasks), 'memory.oom.group': '1'}.items():
        (GROUP / k).write_text(v)
    def admission():
        (GROUP / 'cgroup.procs').write_text(str(os.getpid()))
        for key, limit in [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 32*1024**2), (resource.RLIMIT_NOFILE, 512)]:
            resource.setrlimit(key, (limit, limit))
        os.setgroups([]); os.setgid(65534); os.setuid(65534)
        require(ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) == 0, 'probe_nnp')
    args = chrome_arguments(html, root / 'profile')
    witness = RendererWitness()
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LANG': 'C.UTF-8', 'XDG_CONFIG_HOME': str(root), 'XDG_CACHE_HOME': str(root)}
    with (root / 'stdout').open('wb') as stdout, (root / 'stderr').open('wb') as stderr:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=env, preexec_fn=admission, start_new_session=True)
        deadline = time.monotonic() + 35
        try:
            while child.poll() is None and time.monotonic() < deadline:
                witness.observe(GROUP)
                time.sleep(.02)
        finally:
            (GROUP / 'cgroup.kill').write_text('1'); child.wait(timeout=3)
            end = time.monotonic() + 3
            while (GROUP / 'pids.current').read_text().strip() != '0' and time.monotonic() < end: time.sleep(.02)
            require((GROUP / 'pids.current').read_text().strip() == '0', 'probe_writers_alive')
    dom = (root / 'stdout').read_bytes(); error = (root / 'stderr').read_bytes()[-4096:]
    events = {name: (GROUP / name).read_text().strip() for name in
              ['pids.events', 'pids.peak', 'pids.current', 'memory.events', 'memory.peak', 'memory.max', 'memory.swap.max', 'pids.max']}
    require(events['pids.current'] == '0' and events['pids.max'] == str(tasks) and
            events['memory.max'] == str(JOB_MEMORY) and events['memory.swap.max'] == '0', 'owned_probe_effective_limits')
    try: return probe_evidence(child.returncode, dom, error, witness.flags(), events, tasks, calibration, witness.details())
    finally: GROUP.rmdir(); shutil.rmtree(root)


def installation_failure(path, returncode):
    """Bounded trusted-package diagnostics; never dump a whole guest file."""
    with path.open('rb') as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - 3000))
        tail = stream.read(3000).decode('utf-8', 'replace')
    return 'guest_offline_package_install_failed:exit=' + str(returncode) + ':' + tail


def cached_package(path, item):
    """Give APT an already verified absolute archive, including for upgrades."""
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / item['file']
    require(CACHE.is_absolute() and path.is_absolute() and Path(item['file']).name == item['file'], 'absolute_guest_package_cache')
    if not target.exists() and not target.is_symlink():
        with path.open('rb') as source, target.open('xb') as output:
            shutil.copyfileobj(source, output, length=1024**2)
    require(target.is_file() and not target.is_symlink() and target.stat().st_size == item['bytes'] and
            digest(target) == item['sha256'], 'cached_package_digest')
    target.chmod(0o444)
    return str(target)


def installation_command(paths):
    require(paths and all(Path(p).is_absolute() and Path(p).parent == CACHE for p in paths), 'absolute_install_archives')
    return ['/usr/bin/apt-get', '--no-download', '--no-remove', '--no-install-recommends', '--assume-yes',
            '-o', 'Dir::Cache::archives=' + str(CACHE) + '/', 'install', *paths]


def provision():
    global USED
    require(not USED and os.geteuid() == 0 and sorted(os.listdir('/sys/class/net')) == ['lo'], 'trusted_build_only_no_nic')
    USED = True
    config = json.loads(Path('/etc/paw-browser-build.json').read_text())
    MOUNT.mkdir(parents=True, exist_ok=True)
    subprocess.run(['/usr/bin/mount', '-o', 'ro,nodev,nosuid,noexec', '/dev/disk/by-label/PAWBROWSERPKG', str(MOUNT)], check=True, timeout=15)
    raw = (MOUNT / 'manifest.json').read_bytes(); require(len(raw) <= 256*1024 and hashlib.sha256(raw).hexdigest() == config['manifest_sha256'], 'build_manifest_digest')
    manifest = json.loads(raw); packages = manifest['packages']
    require(manifest['schema'] == 'paw-browser-build-packages-v1' and type(packages) is list and 1 <= len(packages) <= 512, 'build_manifest_shape')
    require(sum(v['bytes'] for v in packages) <= 1024**3, 'build_package_total')
    paths = []
    for item in packages:
        require(type(item) is dict and set(item) == {'file', 'package', 'version', 'architecture', 'bytes', 'sha256'} and
                type(item['file']) is str and re.fullmatch(r'[A-Za-z0-9+_.%:~=-]{1,200}\.deb', item['file']), 'build_package_name')
        path = MOUNT / 'packages' / item['file']
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item['bytes'] and digest(path) == item['sha256'], 'build_package_digest')
        paths.append(cached_package(path, item))
    require({v.name for v in (MOUNT / 'packages').iterdir()} == {v['file'] for v in packages}, 'build_package_inventory')
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', LC_ALL='C')
    with Path('/var/log/paw-browser-install.log').open('wb') as log:
        result = subprocess.run(installation_command(paths),
                                env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode != 0:
        raise ValueError(installation_failure(Path('/var/log/paw-browser-install.log'), result.returncode))
    profile = Path('/etc/apparmor.d/chrome')
    require(profile.is_file(), 'official_chrome_apparmor_profile_missing')
    subprocess.run(['/usr/sbin/apparmor_parser', '-r', str(profile)], check=True, timeout=30)
    require(Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y', 'guest_apparmor_disabled')
    require(Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns').read_text().strip() == '1', 'guest_userns_global_restriction_changed')
    inventory = subprocess.check_output(['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n'], timeout=20)
    installed = {row.split('\t')[0]: row.split('\t')[1:] for row in inventory.decode().splitlines()}
    require(all(installed.get(v['package']) == [v['version'], v['architecture']] for v in packages), 'installed_package_version_mismatch')
    binary = Path('/opt/google/chrome/chrome')
    version = subprocess.check_output([str(binary), '--version'], text=True, timeout=15).strip()
    calibration = probe(tasks=128, calibration=True)
    try: observed = probe()
    except ValueError as error:
        prior = {'accepted': calibration['accepted'], 'events': calibration['diagnostics']['events']}
        raise ValueError('calibration_128=' + json.dumps(prior, separators=(',', ':')) + ';final=' + str(error)) from error
    observed['calibration_128'] = calibration
    info = {'schema': 'paw-browser-image-guest-v1', 'chrome_version': version, 'chrome_binary_sha256': digest(binary),
            'kernel_release': os.uname().release, 'inventory_sha256': hashlib.sha256(inventory).hexdigest(),
            'inventory_text': inventory.decode(), 'approved_packages': len(packages), 'probe': observed,
            'cpu_sensitive_features_absent': not ({'avx', 'avx2', 'xsave', 'vmx', 'svm'} & set(next(v for v in Path('/proc/cpuinfo').read_text().splitlines() if v.startswith('flags')).split(':',1)[1].split())),
            'apparmor_profile_sha256': digest(profile), 'userns_restriction': '1', 'network_interfaces': ['lo']}
    require(len(info['inventory_text']) < 40000, 'guest_inventory_budget')
    Path('/etc/paw-browser-image.json').write_text(json.dumps(info, sort_keys=True) + '\n')
    for name in ['ssh.service', 'ssh.socket', 'systemd-networkd-wait-online.service', 'apt-daily.timer', 'apt-daily-upgrade.timer']:
        subprocess.run(['/usr/bin/systemctl', 'mask', '--now', name], check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['/usr/bin/apt-get', 'clean'], check=True, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['/usr/bin/cloud-init', 'clean', '--logs', '--machine-id'], check=True, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['/usr/bin/umount', str(MOUNT)], check=True, timeout=15)
    for path in Path('/etc/ssh').glob('ssh_host_*'): path.unlink()
    os.sync(); return info


def main():
    os.chmod('/dev/ttyS0', 0o600)
    tty.setraw(sys.stdin.fileno())
    require(sorted(os.listdir('/sys/class/net')) == ['lo'], 'build_network_present')
    emit({'ready': True, 'network_interfaces': ['lo']})
    for line in sys.stdin:
        ident = None
        try:
            require(len(line) <= 4096, 'build_command_budget'); value = json.loads(line); ident = value['id']
            require(type(ident) is int and type(value) is dict and set(value) == {'id', 'op'}, 'build_command_shape')
            if value['op'] == 'provision': data = provision()
            elif value['op'] == 'shutdown' and USED:
                os.sync(); emit({'id': ident, 'ok': True, 'data': {'shutdown_requested': True}})
                time.sleep(.5); subprocess.Popen(['/usr/bin/systemctl', '--no-block', 'poweroff']); return
            else: raise ValueError('unsupported_build_operation')
            emit({'id': ident, 'ok': True, 'data': data})
        except Exception as error: emit({'id': ident, 'ok': False, 'error': type(error).__name__ + ':' + str(error)[:4096]})


if __name__ == '__main__': main()
