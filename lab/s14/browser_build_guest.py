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

MOUNT = Path('/mnt/paw-browser-packages')
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


def probe():
    """Only an owned title-changing script; no real page or external URL."""
    root = Path('/run/paw-browser-image-probe'); root.mkdir(mode=0o700); os.chown(root, 65534, 65534)
    html = root / 'owned.html'; html.write_text('<!doctype html><title>before</title><script>document.title="PAW-BROWSER-PROBE";</script>')
    html.chmod(0o444)
    Path('/sys/fs/cgroup/cgroup.subtree_control').write_text('+cpu +memory +pids')
    GROUP.mkdir()
    for k, v in {'memory.max': str(JOB_MEMORY), 'memory.swap.max': '0', 'pids.max': str(JOB_TASKS), 'memory.oom.group': '1'}.items():
        (GROUP / k).write_text(v)
    def admission():
        (GROUP / 'cgroup.procs').write_text(str(os.getpid()))
        for key, limit in [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 32*1024**2), (resource.RLIMIT_NOFILE, 512)]:
            resource.setrlimit(key, (limit, limit))
        os.setgroups([]); os.setgid(65534); os.setuid(65534)
        require(ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) == 0, 'probe_nnp')
    args = chrome_arguments(html, root / 'profile')
    observed = {'renderer_seen': False, 'renderer_nnp': True, 'renderer_seccomp': True, 'all_uids_nonroot': True, 'renderer_pid_namespace': False}
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LANG': 'C.UTF-8', 'XDG_CONFIG_HOME': str(root), 'XDG_CACHE_HOME': str(root)}
    with (root / 'stdout').open('wb') as stdout, (root / 'stderr').open('wb') as stderr:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=env, preexec_fn=admission, start_new_session=True)
        deadline = time.monotonic() + 35
        try:
            while child.poll() is None and time.monotonic() < deadline:
                for pid in (GROUP / 'cgroup.procs').read_text().split():
                    try:
                        status = Path('/proc', pid, 'status').read_text()
                        command = Path('/proc', pid, 'cmdline').read_bytes()
                    except (FileNotFoundError, ProcessLookupError): continue
                    observed['all_uids_nonroot'] &= all(int(v) != 0 for v in next(v for v in status.splitlines() if v.startswith('Uid:')).split()[1:])
                    if b'--type=renderer' in command:
                        observed['renderer_seen'] = True
                        observed['renderer_nnp'] &= 'NoNewPrivs:\t1' in status
                        observed['renderer_seccomp'] &= 'Seccomp:\t2' in status
                        try: observed['renderer_pid_namespace'] |= os.readlink('/proc/'+pid+'/ns/pid') != os.readlink('/proc/1/ns/pid')
                        except (FileNotFoundError, ProcessLookupError): pass
                time.sleep(.02)
        finally:
            (GROUP / 'cgroup.kill').write_text('1'); child.wait(timeout=3)
            end = time.monotonic() + 3
            while (GROUP / 'pids.current').read_text().strip() != '0' and time.monotonic() < end: time.sleep(.02)
            require((GROUP / 'pids.current').read_text().strip() == '0', 'probe_writers_alive')
    dom = (root / 'stdout').read_bytes(); error = (root / 'stderr').read_bytes()[-4096:]
    require(child.returncode == 0 and len(dom) <= 65536 and b'<title>PAW-BROWSER-PROBE</title>' in dom,
            'owned_browser_probe_failed:' + error.decode('utf-8', 'replace'))
    require(all(observed.values()), 'chrome_renderer_sandbox_not_observed')
    observed.update(title='PAW-BROWSER-PROBE', dom_sha256=hashlib.sha256(dom).hexdigest(), source_executed='owned script only')
    GROUP.rmdir(); shutil.rmtree(root)
    return observed


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
        paths.append(str(path))
    require({v.name for v in (MOUNT / 'packages').iterdir()} == {v['file'] for v in packages}, 'build_package_inventory')
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', LC_ALL='C')
    with Path('/var/log/paw-browser-install.log').open('wb') as log:
        result = subprocess.run(['/usr/bin/apt-get', '--no-download', '--no-install-recommends', '--assume-yes', 'install', *paths],
                                env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    require(result.returncode == 0, 'guest_offline_package_install_failed')
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
    observed = probe()
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
