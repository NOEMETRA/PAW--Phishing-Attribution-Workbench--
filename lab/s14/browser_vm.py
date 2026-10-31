"""Separate no-NIC browser VM lifecycle; old Python budgets/lifecycle unchanged."""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hash_offline_adapter import HashGate
import hash_authorization as platform
from benign_guest_validation import BASE, digest, guard_fingerprint, process_identity
from gw_validation import atomic
from gate_channel import GateChannel

BROWSER_BASE = BASE.parent / 'browser-v1.qcow2'
BROWSER_META = BASE.parent / 'browser-v1.json'
LIMITS = {'memory.max': str(1536 * 1024**2), 'memory.swap.max': '0', 'pids.max': '64', 'cpu.max': '50000 100000'}
LIFETIME = {'build': 1200, 'job': 360, 'owned_cdp': 360}
FILE_CAP = {'build': 2 * 1024**3, 'job': 256 * 1024**2, 'owned_cdp': 256 * 1024**2}


def require(value, reason):
    if not value: raise ValueError(reason)


def owner_command(config_path):
    # -I ignores Python environment settings; the parent's -B is not inherited
    # by a new interpreter. Keep immutable host snapshots free of .pyc writes.
    return ['/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), '--owner', str(config_path)]


def validate_xml(root):
    require(not any(root.findall('devices/' + name) for name in ['interface', 'filesystem', 'hostdev', 'vsock', 'graphics']), 'browser_device_exposure')
    require(all((root.find(tag).get('unit'), root.findtext(tag)) in {('MiB', '1024'), ('KiB', '1048576')} for tag in ['memory', 'currentMemory']), 'browser_guest_memory')
    require(root.findtext('vcpu') == '1' and root.find('memoryBacking/nosharepages') is not None, 'browser_cpu_or_merge')
    require(root.findtext('resource/partition') == '/machine/paws14' and root.find('features/pmu').get('state') == 'off' and
            root.find('features/vmport').get('state') == 'off', 'browser_partition_or_cpu_surface')
    from owned_grant_fixtures import CPU_DISABLED
    require((set(CPU_DISABLED) | {'vmx', 'svm'}) <= {v.get('name') for v in root.findall('cpu/feature') if v.get('policy') == 'disable'}, 'browser_cpu_features')
    require(all(v.get('model') == 'none' for v in root.findall('devices/controller') if v.get('type') == 'usb'), 'browser_usb')
    disks = root.findall('devices/disk')
    require(len(disks) == 3 and {v.find('target').get('dev') for v in disks} == {'vda', 'vdb', 'vdc'}, 'browser_disk_inventory')
    require(all(v.find('readonly') is not None for v in disks if v.find('target').get('dev') != 'vda'), 'browser_readonly_media')


def validate_owner_config(config, path):
    require(type(config) is dict and set(config) == {'phase', 'parent_pid', 'parent_identity', 'guard', 'qemu_sha256',
            'xml', 'control', 'ready', 'result'} and config['phase'] in LIFETIME, 'browser_owner_config_shape')
    require(type(config['parent_pid']) is int and config['parent_pid'] > 1 and type(config['parent_identity']) is str and
            config['parent_identity'].isdigit(), 'browser_owner_parent')
    import re
    require(all(type(config[k]) is str and re.fullmatch('[0-9a-f]{64}', config[k]) for k in ['guard', 'qemu_sha256']),
            'browser_owner_context_hashes')
    require(path.is_absolute() and path.parent.is_relative_to('/var/lib/paw-s14/control'), 'browser_owner_namespace')
    for key in ['xml', 'control', 'ready', 'result']:
        target = Path(config[key])
        require(target.parent == path.parent and target.suffix == ('.xml' if key == 'xml' else '.json'), 'browser_owner_output_paths')


def scope_root(cgroup):
    parts = Path(cgroup).parts
    require(len(parts) >= 4 and parts[:3] == ('/', 'machine.slice', 'machine-paws14.slice') and
            parts[3].endswith('.scope') and '..' not in parts, 'browser_scope_partition')
    return Path('/sys/fs/cgroup', *parts[1:4])


def owner(config_path):
    """PID1-owned libvirt connection destroys the VM on owner/controller loss."""
    import libvirt
    with platform.fs.root_directory(config_path.parent) as fd:
        config = json.loads(platform.fs.read(fd, config_path.name, 65536))
    validate_owner_config(config, config_path)
    require(os.geteuid() == 0, 'browser_owner_phase')
    ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)
    if os.getppid() != config['parent_pid'] or process_identity(config['parent_pid']) != config['parent_identity']: return
    stopped = False
    def requested(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, requested)
    libvirt.virEventRegisterDefaultImpl()
    timer = libvirt.virEventAddTimeout(100, lambda timer, opaque: None, None)
    connection = libvirt.open('qemu:///system'); reason = 'owner_error'
    shutdown_event = {'observed': False}; events = []; expected_uuid = None
    def lifecycle(conn, domain, event, detail, opaque):
        if domain.UUIDString() != expected_uuid: return
        if len(events) < 16: events.append({'event': event, 'detail': detail})
        if event == libvirt.VIR_DOMAIN_EVENT_STOPPED and detail == libvirt.VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN:
            shutdown_event['observed'] = True
    connection.domainEventRegisterAny(None, libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE, lifecycle, None)
    try:
        require(guard_fingerprint() == config['guard'], 'browser_guard_before_creation')
        xml = Path(config['xml']).read_bytes(); validate_xml(ET.fromstring(xml))
        expected_uuid = ET.fromstring(xml).findtext('uuid')
        domain = connection.createXML(xml.decode(), libvirt.VIR_DOMAIN_START_PAUSED | libvirt.VIR_DOMAIN_START_AUTODESTROY)
        pid = int(Path('/run/libvirt/qemu', domain.name() + '.pid').read_text())
        identity = process_identity(pid); require(identity is not None, 'browser_process_identity')
        cg = next(v.split('::', 1)[1] for v in Path('/proc', str(pid), 'cgroup').read_text().splitlines() if v.startswith('0::'))
        unit = next(p for p in Path(cg).parts if p.endswith('.scope'))
        require('machine-paws14.slice' in Path(cg).parts, 'browser_scope_partition')
        subprocess.run(['/usr/bin/systemctl', 'set-property', '--runtime', unit, 'TasksMax=64', 'MemoryMax=1536M',
                        'MemorySwapMax=0', 'CPUQuota=50%'], check=True, timeout=15)
        cap = FILE_CAP[config['phase']]
        subprocess.run(['/usr/bin/prlimit', '--pid', str(pid), '--fsize=' + str(cap) + ':' + str(cap), '--core=0:0'], check=True, timeout=10)
        scope = scope_root(cg)
        limits = {k: (scope / k).read_text().strip() for k in LIMITS}; require(limits == LIMITS, 'browser_effective_limits')
        status = Path('/proc', str(pid), 'status').read_text(); apparmor = Path('/proc', str(pid), 'attr/current').read_text().strip()
        require(all(int(v) != 0 for v in next(v for v in status.splitlines() if v.startswith('Uid:')).split()[1:]) and
                'Seccomp:\t2' in status and apparmor.startswith('libvirt-') and '(enforce)' in apparmor, 'browser_host_controls')
        require(digest(Path('/proc', str(pid), 'exe')) == config['qemu_sha256'], 'browser_qemu_binary')
        command = Path('/proc', str(pid), 'cmdline').read_bytes()
        require(b'mem-merge=off' in command or b'"merge":false' in command, 'browser_qemu_merge')
        actual = {'uuid': domain.UUIDString(), 'name': domain.name(), 'pid': pid, 'pid_identity': identity,
                  'scope': str(scope), 'apparmor': apparmor, 'limits': limits, 'qemu_binary_sha256': config['qemu_sha256'],
                  'memory_merge_disabled': True, 'host_status': status, 'file_cap': cap}
        atomic(config['ready'], actual)
        began = time.monotonic(); offset = time.time() - began; resumed = False
        while not stopped:
            libvirt.virEventRunDefaultImpl()
            control = json.loads(Path(config['control']).read_text())
            if process_identity(config['parent_pid']) != config['parent_identity']: reason = 'controller_lost'; break
            if time.monotonic() - began > LIFETIME[config['phase']]: reason = 'deadline'; break
            if control.get('heartbeat', 0) < time.monotonic() - 5: reason = 'heartbeat_lost'; break
            if abs(time.time() - time.monotonic() - offset) > 3: reason = 'clock_changed'; break
            if guard_fingerprint() != config['guard']: reason = 'guard_changed'; break
            if process_identity(pid) != identity:
                until = time.monotonic() + 1
                while not shutdown_event['observed'] and time.monotonic() < until: libvirt.virEventRunDefaultImpl()
                reason = 'guest_shutdown' if shutdown_event['observed'] else 'qemu_exited'
                break
            if {k: (scope / k).read_text().strip() for k in LIMITS} != LIMITS: reason = 'limits_changed'; break
            if control.get('resume') is True and not resumed: domain.resume(); resumed = True
            time.sleep(.25)
        if stopped: reason = 'requested_stop'
    finally:
        connection.close()
        libvirt.virEventRemoveTimeout(timer)
        atomic(config['result'], {'reason': reason, 'connection_closed': True, 'guest_shutdown_event': shutdown_event['observed'],
                                  'vm_uuid': expected_uuid, 'events': events})


class BrowserVM(HashGate):
    def __init__(self, args, *, phase, media, seed_config):
        require(phase in LIFETIME and os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined', 'browser_root_operator')
        super().__init__(args); self.phase = phase; self.media = Path(media); self.seed_config = seed_config
        platform.fs.trusted(self.media.stat()); require(not self.media.is_symlink() and not self.media.stat().st_mode & 0o222, 'browser_media_immutable')
        if phase in {'job', 'owned_cdp'}:
            import pwd
            group = pwd.getpwnam('libvirt-qemu').pw_gid
            require(self.media.stat().st_gid == group and self.media.stat().st_mode & 0o777 == 0o440 and
                    self.media.parent.stat().st_uid == 0 and self.media.parent.stat().st_gid == group and
                    self.media.parent.stat().st_mode & 0o777 == 0o750, 'browser_private_input_media')
        self.hash_context = platform.capture(); platform.validate_context(self.hash_context)
        self.active_vm = None; self._heartbeat_stop = threading.Event(); self._control_lock = threading.Lock()
        self.report.update(scope='separate no-NIC Chrome HTML profile', vms=[], real_connections=0, phase=phase)

    def seed(self, folder, role, job_id, token):
        worker = ('browser_build_guest.py' if self.phase == 'build' else
                  'browser_owned_cdp_guest.py' if self.phase == 'owned_cdp' else 'browser_guest.py')
        worker_source = (HERE.parents[1]/'paw/core'/worker if self.phase == 'owned_cdp' else HERE/worker)
        service = ('[Unit]\nAfter=cloud-final.service\n[Service]\nExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/' + worker + '\n'
                   'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n'
                   + ('TasksMax=128\nMemoryMax=768M\n' if self.phase == 'build' else 'TasksMax=32\nMemoryMax=128M\n')
                   + 'MemorySwapMax=0\nCPUQuota=100%\n')
        config_name = ('/etc/paw-browser-build.json' if self.phase == 'build' else
                       '/etc/paw-owned-cdp.json' if self.phase == 'owned_cdp' else '/etc/paw-browser-job.json')
        files = [('/usr/local/lib/paw-s14/' + worker, worker_source.read_bytes()),
                 ('/usr/local/lib/paw-s14/browser_policy.py', (HERE / 'browser_policy.py').read_bytes()),
                 ('/usr/local/lib/paw-s14/browser_sandbox.py', (HERE / 'browser_sandbox.py').read_bytes()),
                 (config_name, json.dumps(self.seed_config).encode()), ('/etc/systemd/system/paw-browser.service', service.encode())]
        if self.phase == 'owned_cdp':
            files.append(('/usr/local/lib/paw-s14/browser_cdp.py',
                          (HERE.parents[1]/'paw/core/browser_cdp.py').read_bytes()))
        cloud = {'package_update': False, 'package_upgrade': False, 'ssh_pwauth': False,
                 'write_files': [{'path': p, 'encoding': 'b64', 'content': base64.b64encode(b).decode(), 'permissions': '0644'} for p, b in files],
                 'runcmd': [['systemctl', 'mask', '--now', 'ssh.service', 'ssh.socket', 'serial-getty@ttyS0.service', 'systemd-networkd-wait-online.service'],
                            ['systemctl', 'daemon-reload'], ['systemctl', '--no-block', 'start', 'paw-browser.service']]}
        (folder / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud))
        (folder / 'meta-data').write_text(json.dumps({'instance-id': job_id, 'local-hostname': 'paw-offline-browser'}))
        (folder / 'network-config').write_text(json.dumps({'version': 2, 'ethernets': {}}))
        self.run(['/usr/bin/genisoimage', '-quiet', '-output', str(folder / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                  str(folder / 'user-data'), str(folder / 'meta-data'), str(folder / 'network-config')]); (folder / 'seed.iso').chmod(0o444)

    def descriptor(self, role, case, *args, **kwargs):
        node = super().descriptor(role, 'browser-' + case, *args, **kwargs)
        if self.phase in {'job', 'owned_cdp'}:
            platform.fs.trusted(BROWSER_BASE.stat()); require(BROWSER_BASE.stat().st_mode & 0o777 == 0o444, 'browser_base_readonly')
            node['overlay'].unlink()
            self.run(['/usr/bin/qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(BROWSER_BASE), str(node['overlay'])])
            import pwd
            qemu = pwd.getpwnam('libvirt-qemu'); os.chown(node['overlay'], qemu.pw_uid, qemu.pw_gid); node['overlay'].chmod(0o600)
        else: self.run(['/usr/bin/qemu-img', 'resize', str(node['overlay']), '8G'])
        root = ET.fromstring(node['xml'].read_bytes())
        for name in ['vmx', 'svm']:
            ET.SubElement(root.find('cpu'), 'feature', {'name': name, 'policy': 'disable'})
        for tag in ['memory', 'currentMemory']: root.find(tag).text = '1024'; root.find(tag).set('unit', 'MiB')
        for tag in ['hard_limit', 'swap_hard_limit']: root.find('memtune/' + tag).text = '1536'
        disk = ET.SubElement(root.find('devices'), 'disk', {'type': 'file', 'device': 'disk'})
        ET.SubElement(disk, 'driver', {'name': 'qemu', 'type': 'raw'}); ET.SubElement(disk, 'source', {'file': str(self.media)})
        ET.SubElement(disk, 'target', {'dev': 'vdc', 'bus': 'virtio'}); ET.SubElement(disk, 'readonly')
        ET.SubElement(root, 'defaultiothread', {'thread_pool_min': '0', 'thread_pool_max': '8'})
        for item in root.findall('devices/disk'):
            item.find('driver').set('error_policy', 'stop'); item.find('driver').set('rerror_policy', 'stop')
        validate_xml(root); node['xml'].write_bytes(ET.tostring(root)); return node

    def _control(self, **changes):
        with self._control_lock:
            self._control_value.update(changes, heartbeat=time.monotonic()); atomic(self._control_path, self._control_value)

    def start(self, label, boot=True):
        require(self.active_vm is None and not self.connection.listAllDomains(0) and guard_fingerprint(), 'browser_busy_or_guard')
        node = self.descriptor('extractor', label, str(uuid.uuid4()), uuid.uuid4().hex)
        if self.phase == 'build': self.last_build_node = node
        self._control_path = self.output / (label + '-control.json'); self._control_value = {'resume': False}
        self._control(); self._heartbeat_stop.clear()
        def heartbeat():
            while not self._heartbeat_stop.wait(.5): self._control()
        self._heartbeat_thread = threading.Thread(target=heartbeat, daemon=True); self._heartbeat_thread.start()
        ready = self.output / (label + '-ready.json')
        config = {'phase': self.phase, 'parent_pid': os.getpid(), 'parent_identity': process_identity(os.getpid()),
                  'guard': guard_fingerprint(), 'qemu_sha256': self.hash_context['qemu_binary_sha256'], 'xml': str(node['xml']),
                  'control': str(self._control_path), 'ready': str(ready), 'result': str(self.output / (label + '-owner-result.json'))}
        path = self.output / (label + '-owner.json'); atomic(path, config)
        child = self.spawn(owner_command(path), label + '-owner')
        vm = {'node': node, 'owner': child, 'control': self._control_path, 'label': label, 'owner_result_path': config['result']}; self.active_vm = vm
        vm['actual'] = self.wait_file(ready, 35); vm['fsize_limit'] = FILE_CAP[self.phase]
        runtime = ET.fromstring(self.connection.lookupByUUIDString(node['uuid']).XMLDesc(0)); validate_xml(runtime)
        self.validate_runtime(runtime); vm['host_status'] = vm['actual']['host_status']
        (self.output / (label + '-domain.xml')).write_bytes(ET.tostring(runtime))
        if boot:
            vm['channel'] = GateChannel(runtime.find('devices/serial/source').get('path'), self.output / (label + '-serial.log'))
            self._control(resume=True); vm['channel'].ready(360 if self.phase == 'build' else 120)
        return vm

    def stop(self, vm, kill=False):
        try: return super().stop(vm, kill=kill)
        finally:
            self._heartbeat_stop.set()
            if hasattr(self, '_heartbeat_thread'): self._heartbeat_thread.join(timeout=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--owner', type=Path, required=True)
    owner(parser.parse_args().owner)
