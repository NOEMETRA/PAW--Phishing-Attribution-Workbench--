"""Offline two-VM adversarial isolation checks; fixed harmless fixtures only.

No arbitrary payload, browser, network target, host mount or deployment API.
Passing these vectors does not enable the absent general hostile-code launcher.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from gw_validation import Matrix, atomic
from benign_guest_validation import BASE, digest, supervisor_child, guard_fingerprint, process_identity
from validate_uplink_namespace import Validation
from gate_channel import GateChannel
from gw_quarantine import validate_records, publish


def observe_cpu_quota(actual):
    """Read the applied scope limit after set-property, before guest resume."""
    value = (Path(actual['scope']) / 'cpu.max').read_text().strip()
    if value != '50000 100000':
        raise ValueError('host_cpu_quota_not_applied')
    actual['limits']['cpu.max'] = value


def owner_command(config):
    # Isolated mode ignores PYTHONDONTWRITEBYTECODE. The fixed owner imports
    # from this Root snapshot, so -B must be explicit in the child interpreter.
    return ['/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), '--owner', str(config)]


class Gate(Matrix):
    snapshot_host = Validation.snapshot_host
    def validate_runtime(self, runtime):
        """Additional fixed-policy admission for a more restrictive adapter."""
        pass
    def seed(self, folder, role, job_id, token):
        service = ('[Unit]\nAfter=cloud-final.service\n[Service]\n'
                   'ExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/gate_guest.py\n'
                   'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n'
                   'TasksMax=32\nMemoryMax=128M\nMemorySwapMax=0\nCPUQuota=50%\n')
        files = [('/usr/local/lib/paw-s14/' + n, (HERE / n).read_bytes()) for n in ['gate_guest.py', 'gate_payload.py']]
        files += [('/etc/paw-gate-fixture.json', json.dumps({'host_canary': str(self.canary)}).encode()),
                  ('/etc/systemd/system/paw-gate.service', service.encode())]
        cloud = {'package_update': False, 'package_upgrade': False, 'ssh_pwauth': False, 'ssh_genkeytypes': [],
                 'write_files': [{'path': p, 'encoding': 'b64', 'content': base64.b64encode(b).decode(), 'permissions': '0644'} for p, b in files],
                 'runcmd': [['systemctl', 'mask', '--now', 'ssh.service', 'ssh.socket', 'serial-getty@ttyS0.service'],
                            ['systemctl', 'daemon-reload'], ['systemctl', '--no-block', 'start', 'paw-gate.service']]}
        (folder / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud))
        (folder / 'meta-data').write_text(json.dumps({'instance-id': job_id, 'local-hostname': 'paw-synthetic-gate'}))
        (folder / 'network-config').write_text(json.dumps({'version': 2, 'ethernets': {}}))
        self.run(['/usr/bin/genisoimage', '-quiet', '-output', str(folder / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                  str(folder / 'user-data'), str(folder / 'meta-data'), str(folder / 'network-config')])
        (folder / 'seed.iso').chmod(0o444)

    def record(self, name, **value):
        self.report['checks'].append({'name': name, 'result': 'PASS', **value})
        print('PASS: ' + name, flush=True)

    def start(self, label, boot=True):
        assert not self.connection.listAllDomains(0) and guard_fingerprint()
        node = self.descriptor('extractor', 'synthetic-' + label, str(uuid.uuid4()), uuid.uuid4().hex)
        xml = ET.fromstring(node['xml'].read_text())
        assert not xml.findall('devices/interface') and not xml.findall('devices/filesystem') and not xml.findall('devices/hostdev')
        ET.SubElement(xml, 'defaultiothread', {'thread_pool_min': '0', 'thread_pool_max': '8'})
        for disk in xml.findall('devices/disk'):
            disk.find('driver').set('error_policy', 'stop'); disk.find('driver').set('rerror_policy', 'stop')
        node['xml'].write_bytes(ET.tostring(xml))
        control = self.output / (label + '-control.json'); ready = self.output / (label + '-ready.json')
        atomic(control, {'resume': False, 'expiry': time.monotonic() + 260})
        config = {'parent_pid': os.getpid(), 'guard_fingerprint': guard_fingerprint(), 'xml': str(node['xml']),
                  'ready': str(ready), 'control': str(control), 'result': str(self.output / (label + '-owner-result.json')), 'health': []}
        path = self.output / (label + '-owner.json'); atomic(path, config)
        child = self.spawn(owner_command(path), label + '-owner')
        vm = {'node': node, 'owner': child, 'control': control, 'label': label}; self.active_vm = vm
        actual = self.wait_file(ready, 30); vm['actual'] = actual
        self.run(['/usr/bin/systemctl', 'set-property', '--runtime', Path(actual['scope']).name, 'CPUQuota=50%'])
        observe_cpu_quota(actual)
        self.run(['/usr/bin/prlimit', '--pid', str(actual['pid']), '--fsize=268435456:268435456', '--core=0:0'])
        vm['fsize_limit'] = 256 * 1024**2
        vm['host_file_size_limit'] = next(line for line in Path('/proc', str(actual['pid']), 'limits').read_text().splitlines() if line.startswith('Max file size'))
        runtime = ET.fromstring(self.connection.lookupByUUIDString(node['uuid']).XMLDesc(0))
        assert not runtime.findall('devices/interface') and runtime.find('defaultiothread').get('thread_pool_max') == '8'
        self.validate_runtime(runtime)
        (self.output / (label + '-domain.xml')).write_bytes(ET.tostring(runtime))
        status = Path('/proc', str(actual['pid']), 'status').read_text()
        assert next(line for line in status.splitlines() if line.startswith('Seccomp:')).split()[1] == '2'
        vm['host_status'] = status
        if not boot:
            return vm
        vm['channel'] = GateChannel(runtime.find('devices/serial/source').get('path'), self.output / (label + '-serial.log'))
        atomic(control, {'resume': True, 'expiry': time.monotonic() + 240})
        vm['channel'].ready(220)
        atomic(control, {'resume': True, 'expiry': time.monotonic() + 40})
        return vm

    def absent(self, vm):
        try: self.connection.lookupByUUIDString(vm['node']['uuid']); present = True
        except self.libvirt.libvirtError: present = False
        if present: return False
        actual = vm.get('actual')
        if actual and process_identity(actual['pid']) == actual['pid_identity']: return False
        pattern = b'-uuid\0' + vm['node']['uuid'].encode() + b'\0'
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    if pattern in (proc / 'cmdline').read_bytes(): return False
                except (FileNotFoundError, ProcessLookupError, PermissionError): pass
        return True

    def stop(self, vm, kill=False):
        began = time.monotonic()
        owner = vm['owner']
        if owner.poll() is None:
            if kill: owner.kill()
            else: owner.terminate()
        owner.wait(timeout=12)
        deadline = began + 12
        while not self.absent(vm) and time.monotonic() < deadline: time.sleep(.05)
        assert self.absent(vm), 'unknown_stop_blocks_publication'
        if 'channel' in vm: vm['channel'].close()
        vm['stopped'] = True; vm['stop_seconds'] = time.monotonic() - began
        vm['overlay_sha256_after_stop'] = digest(vm['node']['overlay'])
        # Startup can fail before admission assigns/applies the file cap. Stop
        # still must be recorded, without claiming an unknown limit was applied.
        vm['fsize_limit'] = vm.get('fsize_limit')
        if vm['fsize_limit'] is not None:
            assert vm['node']['overlay'].stat().st_size <= vm['fsize_limit']
        self.report['vms'].append({k: v for k, v in vm.items() if k not in {'owner', 'channel', 'control', 'node'}} |
                                  {'uuid': vm['node']['uuid'], 'overlay_bytes': vm['node']['overlay'].stat().st_size})
        self.active_vm = None
        return vm['stop_seconds']

    def vectors(self):
        vm = self.start('boundaries'); channel = vm['channel']
        boundary = channel.call('boundary')
        data = boundary['data']
        assert data['uid'] == data['gid'] == 65534 and data['no_new_privs'] == '1' and int(data['cap_eff'], 16) == 0
        assert data['stdin_path'] == '/dev/null', 'control_descriptor_inherited'
        assert data['interfaces'] == ['lo'] and data['positive_read']
        assert all(data['denied_paths'].values()) and all(v['denied'] for v in data['network'])
        assert data['setuid_denied'] and data['mount_denied'] and data['cgroup_write_denied']
        self.record('unprivileged_no_nic_host_canary_socket_mount_and_capability_denials', observation=boundary)
        for case in ['fork', 'memory', 'file']:
            value = channel.call(case)
            if case == 'fork':
                assert value['data']['denied'] and value['data']['spawned'] == value['data']['reaped']
                assert int(dict(line.split() for line in value['events']['pids.events'].splitlines())['max']) > 0
                assert int(value['events']['pids.peak']) <= 16
            elif case == 'memory': assert value['data']['actual_guest_cgroup_oom']
            else: assert value['data']['refused'] and value['data']['bytes'] <= 1024
            self.record('kernel_enforced_' + case + '_budget', observation=value)
        outputs = channel.call('outputs'); validate_records(outputs['valid']); self.good_records = outputs['valid']
        for records in outputs['invalid']:
            try: validate_records(records)
            except ValueError: pass
            else: raise AssertionError('host_accepted_malformed_guest_output')
        unpublished = self.output / 'must-not-publish-live'
        try: publish(unpublished, outputs['valid'], stopped=False)
        except ValueError: pass
        else: raise AssertionError('live_output_publication')
        assert not unpublished.exists()
        self.record('untrusted_output_and_live_publication_refused', invalid_batches=len(outputs['invalid']))
        stubborn = channel.call('stubborn', seconds=5)
        assert stubborn['descendant'] > 0 and stubborn['late_write_after_seconds'] == 10
        start = time.monotonic()
        try: channel.call('corrupt', seconds=2)
        except ValueError: pass
        else: raise AssertionError('invalid_guest_protocol_accepted')
        assert channel.failure and 'frame_object_required' in channel.failure
        stopped = self.stop(vm, kill=True)
        assert time.monotonic() - start < 10 and stopped < 12
        self.record('malformed_protocol_and_owner_loss_stop_stubborn_descendants_before_late_write',
                    stubborn=stubborn, channel_failure=channel.failure, stop_seconds=stopped)
        vm = self.start('reset-storage'); channel = vm['channel']
        reset = channel.call('reset'); assert reset['data']['prior_marker_absent']
        self.record('fresh_overlay_excludes_previous_job_marker', observation=reset)
        overlay = vm['node']['overlay']
        maximum = ((overlay.stat().st_size + 1024**2 - 1) // 1024**2 + 2) * 1024**2
        assert maximum <= vm['fsize_limit']
        log_path = Path('/var/log/libvirt/qemu') / (ET.fromstring(vm['node']['xml'].read_bytes()).find('name').text + '.log')
        log_offset = log_path.stat().st_size
        self.run(['/usr/bin/prlimit', '--pid', str(vm['actual']['pid']), '--fsize=' + str(maximum) + ':' + str(maximum)])
        vm['fsize_limit'] = maximum
        before = time.monotonic(); channel.call('storage', seconds=3)
        trigger = None
        while time.monotonic() - before < 10:
            if self.absent(vm): trigger = 'qemu_exited'; break
            try:
                if self.connection.lookupByUUIDString(vm['node']['uuid']).info()[0] == self.libvirt.VIR_DOMAIN_PAUSED:
                    trigger = 'io_error_paused'; break
            except self.libvirt.libvirtError: trigger = 'qemu_exited'; break
            time.sleep(.05)
        assert trigger, 'FAILED_INJECTION_host_overlay_file_cap'
        self.stop(vm)
        assert overlay.stat().st_size <= maximum
        witness = '\n'.join(line for line in log_path.read_bytes()[log_offset:].decode(errors='replace').splitlines() if 'IO error' in line and 'File too large' in line)
        assert witness, 'FAILED_INJECTION_no_emulator_file_cap_error'
        self.record('host_enforced_overlay_cap_stops_vm_without_filling_host_disk', trigger=trigger,
                    cap_bytes=maximum, overlay_bytes=overlay.stat().st_size, fault_seconds=time.monotonic() - before,
                    emulator_io_error=witness)
        vm = self.start('host-oom', boot=False)
        scope = Path(vm['actual']['scope']); limit = 1024**2
        score = int(Path('/proc', str(vm['actual']['pid']), 'oom_score_adj').read_text())
        assert score > -1000, 'FAILED_INJECTION_oom_protected_vm'
        resident = int((scope / 'memory.current').read_text()); assert resident > limit
        since = '@' + str(int(time.time()) - 1); began = time.monotonic()
        code = "from pathlib import Path;Path(" + repr(str(scope / 'memory.max')) + ").write_text('1048576')"
        subprocess.run(['/usr/bin/python3', '-I', '-c', code], check=True, timeout=5)
        while not self.absent(vm) and time.monotonic() - began < 10: time.sleep(.05)
        assert self.absent(vm), 'FAILED_INJECTION_host_vm_oom'
        witness = ''
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            value = self.run(['/usr/bin/journalctl', '-k', '--since', since, '--no-pager', '-g', 'Killed process ' + str(vm['actual']['pid']) + ' '], required=False)
            witness = value.stdout
            if 'Memory cgroup out of memory' in witness: break
            time.sleep(.1)
        assert 'Memory cgroup out of memory' in witness, 'FAILED_INJECTION_no_kernel_vm_oom_witness'
        self.stop(vm)
        self.record('host_cgroup_oom_before_admission_stops_only_identified_vm', initial_bytes=resident,
                    injected_limit_bytes=limit, kernel_witness=witness, fault_seconds=time.monotonic() - began,
                    guest_payload_started=False, initial_oom_score_adj=score)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path); parser.add_argument('--synthetic-matrix', action='store_true')
    parser.add_argument('--output', type=Path); parser.add_argument('--export', type=Path)
    args = parser.parse_args()
    if args.owner: supervisor_child(args.owner); return
    assert args.synthetic_matrix and os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined'
    assert shutil.disk_usage('/var/lib/libvirt/images').free >= 10 * 1024**3
    gate = Gate(args); gate.active_vm = None; gate.good_records = []
    gate.report.update(scope='fixed benign offline adversarial fixtures only', checks=[], vms=[], real_connections=0,
                       general_hostile_launcher='NOT_IMPLEMENTED', stable_publication=False)
    gate.canary = args.output / 'host-owned-canary.bin'; gate.canary.write_bytes(os.urandom(32)); gate.canary.chmod(0o600)
    canary_hash = digest(gate.canary); before = gate.snapshot_host()
    try:
        gate.vectors(); gate.report['result'] = 'PASS'
    except Exception as error:
        gate.report.update(error=str(error), traceback=traceback.format_exc()); print(gate.report['traceback'], flush=True)
    finally:
        try:
            if gate.active_vm: gate.stop(gate.active_vm)
            assert not gate.connection.listAllDomains(0) and before == gate.snapshot_host()
            assert digest(gate.canary) == canary_hash and digest(BASE) == gate.root_image_sha
            assert all(digest(HERE / n) == h for n, h in gate.source_hashes.items())
            gate.report.update(host_before=before, host_after=gate.snapshot_host(), host_restored=True,
                               source_freeze_unchanged=True, base_unchanged=True, host_canary_unchanged=True, writers_stopped=True)
            if gate.report['result'] == 'PASS':
                gate.report['quarantine'] = publish(args.output / 'quarantine', gate.good_records, stopped=True)
                gate.report['stable_publication'] = True
            gate.connection.close()
        except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error))
        (args.output / 'results.json').write_text(json.dumps(gate.report, indent=2) + '\n')
        args.export.mkdir(mode=0o700, parents=True, exist_ok=False)
        for path in args.output.iterdir():
            if path.is_file() and path.suffix in {'.json', '.xml', '.log'}:
                shutil.copyfile(path, args.export / path.name); os.chown(args.export / path.name, 1000, 1000)
        for name in ['sources', 'quarantine']:
            if (args.output / name).exists():
                shutil.copytree(args.output / name, args.export / name)
                for p in (args.export / name).iterdir(): os.chown(p, 1000, 1000)
                os.chown(args.export / name, 1000, 1000)
        os.chown(args.export, 1000, 1000)
        print('Synthetic offline adversarial gate: ' + gate.report['result'], flush=True)
    if gate.report['result'] != 'PASS': raise SystemExit(1)


if __name__ == '__main__': main()
