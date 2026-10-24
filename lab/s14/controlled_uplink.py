"""Explicit one-shot trusted KVM connectivity test, separate from PAW collectors.

Default operation is owned-fixture-only. Public mode additionally requires an
explicit flag and successful root-owned local evidence on identical sources.
No persistent activation, arbitrary URL, browser, sample or detonation is supported.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from benign_guest_validation import supervisor_child, guard_fingerprint, process_identity
from gw_validation import atomic, Channel
from prepare_uplink import current_uplink
from uplink_policy import (address, validate, match_uplink, guard_tables, bridge_table,
                           nat_table, interop_commands, admit, lease_transaction, fingerprint)
from validate_uplink_vm import VMValidation, TABLES, policy_fingerprint
from controlled_scope import PUBLIC_HOST, PUBLIC_TARGETS, public_scope


def wait_ready(channel, abort, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if abort.is_set():
            raise RuntimeError('boot_monitor_aborted')
        try:
            value = channel.ready(min(.5, max(.001, deadline - time.monotonic())))
        except queue.Empty:
            continue
        if abort.is_set():
            raise RuntimeError('boot_monitor_aborted')
        return value
    raise TimeoutError('guest_ready_deadline')


def observe_dns(host=PUBLIC_HOST):
    """A single exact-name query through the host's existing resolver; no guest DNS."""
    if host not in PUBLIC_TARGETS.values():
        raise ValueError('fixed_dns_name_only')
    started = time.monotonic()
    result = subprocess.run(['/usr/bin/dig', '-r', '@127.0.0.53', host + '.', 'A',
                             '+noall', '+answer', '+tries=1', '+time=2', '+nosearch'],
                            capture_output=True, text=True, check=True, timeout=4)
    records = []
    for line in result.stdout.splitlines():
        if not line or line.startswith(';'):
            continue
        name, ttl, cls, kind, value = line.split()
        if cls != 'IN' or kind not in {'A', 'CNAME'}:
            raise ValueError('unexpected_dns_record')
        records.append({'name': name.lower(), 'ttl': int(ttl), 'type': kind, 'value': value})
    owners = {host + '.'}
    for _ in range(8):
        owners.update(r['value'].lower() for r in records if r['name'] in owners.copy() and r['type'] == 'CNAME')
    if not records or any(r['name'] not in owners or r['ttl'] <= 0 for r in records):
        raise ValueError('dns_chain_or_ttl')
    answers = sorted({address(r['value']) for r in records if r['type'] == 'A'})
    if not 1 <= len(answers) <= 4:
        raise ValueError('dns_answer_count')
    return {'answers': answers, 'ttl': min(3600, min(r['ttl'] for r in records)),
            'observed_monotonic': started, 'records': records,
            'dnssec_or_ownership': 'not independently established'}


class Controlled(VMValidation):
    def __init__(self, args):
        super().__init__(args)
        self.public = args.mode == 'public'
        self.target_host, self.target_url = public_scope(args.target)
        self.offline_phase = False
        self.abort = threading.Event()
        self.absolute_limit = time.monotonic() + 220
        self.report['scope'] = 'one trusted KVM HTTPS GET; no worker, collector or detonation'
        self.report['mode'] = args.mode
        self.report['case'] = args.case
        self.report['target_id'] = args.target
        self.report['synthetic_requested'] = args.synthetic_fixture
        self.report['public_get_attempted'] = False

    def prepare(self):
        if not self.public:
            super().prepare()
            return
        assert Path('/proc/self/attr/current').read_text().strip() == 'unconfined'
        assert not self.connection.listAllDomains(0) and guard_fingerprint()
        assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1'
        assert not Path('/sys/class/net/pawbr-up').exists()
        for family, table in TABLES[3:]:
            assert self.run(['/usr/sbin/nft', 'list', 'table', family, table], required=False).returncode
        assert 'paw-s14-uplink-prepared' not in self.run(['/usr/sbin/iptables', '-S', 'DOCKER-USER']).stdout
        assert 'nf_tables' in self.run(['/usr/sbin/iptables', '-V']).stdout
        self.prepared_profile = validate(json.loads((self.args.prepared / 'profile.json').read_text()))
        match_uplink(self.prepared_profile, current_uplink())
        assert self.prepared_profile['mode'] == 'wifi-routed'
        assert len(self.prepared_profile['targets']) == 1
        assert self.prepared_profile['targets'][0]['url'] == self.target_url
        assert not self.prepared_profile['targets'][0]['pinned_ipv4']
        self.profile = copy.deepcopy(self.prepared_profile)
        self.before = self.snapshot_host()
        self.nft(guard_tables(self.profile) + bridge_table(self.profile) + nat_table(self.profile)); self.rules = True
        self.run(['/usr/sbin/ip', 'link', 'add', 'pawbr-up', 'type', 'bridge']); self.bridge = True
        self.run(['/usr/sbin/ip', 'link', 'set', 'pawbr-up', 'address', '52:54:00:14:41:01'])
        self.run(['/usr/sbin/sysctl', '-w', 'net.ipv6.conf.pawbr-up.disable_ipv6=1'])
        self.run(['/usr/sbin/ip', 'address', 'add', '198.18.41.1/30', 'dev', 'pawbr-up'])
        self.run(['/usr/sbin/ip', 'link', 'set', 'pawbr-up', 'up'])
        for argv in interop_commands(self.profile):
            self.run(argv); self.interop.append(argv)
        shutil.copyfile('/etc/ssl/certs/ca-certificates.crt', self.output / 'ca.pem')
        self.capture = self.capture_on('pawbr-up', 'uplink-vm.pcap')
        self.expected = policy_fingerprint(); assert self.expected

    def capture_on(self, interface, name, *bpf):
        path = self.output / name
        with path.open('wb') as data, (self.output / (name + '.log')).open('wb') as log:
            process = subprocess.Popen(['/usr/bin/prlimit', '--fsize=8388608:8388608', '--',
                                        '/usr/bin/tcpdump', '-i', interface, '-nn', '-s', '256', '-U',
                                        '-Z', 'tcpdump', '-w', '-', *bpf], stdout=data, stderr=log)
        self.processes.append(process)
        deadline = time.monotonic() + 3
        while path.stat().st_size < 24 and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        assert process.poll() is None and path.stat().st_size >= 24, 'capture_not_ready'
        return process

    def seed(self, folder, role, job_id, token):
        service = ('[Unit]\nAfter=cloud-final.service\n[Service]\n'
                   'ExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/controlled_guest.py\n'
                   'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n'
                   'TasksMax=32\nMemoryMax=128M\nMemorySwapMax=0\nCPUQuota=50%\n')
        files = [('/usr/local/lib/paw-s14/' + n, (HERE / n).read_bytes())
                 for n in ['controlled_guest.py', 'controlled_scope.py', 'benign_synthetic.py', 'uplink_policy.py', 'gw_admission.py']]
        files += [('/etc/paw-controlled-ca.pem', (self.output / 'ca.pem').read_bytes()),
                  ('/etc/paw-controlled.json', json.dumps({'mode': self.args.mode, 'target': self.args.target}).encode()),
                  ('/etc/systemd/system/paw-controlled.service', service.encode())]
        cloud = {'package_update': False, 'package_upgrade': False, 'ssh_pwauth': False, 'ssh_genkeytypes': [],
                 'write_files': [{'path': p, 'encoding': 'b64', 'content': base64.b64encode(data).decode(),
                                  'permissions': '0644'} for p, data in files],
                 'runcmd': [['systemctl', 'mask', '--now', 'ssh.service', 'ssh.socket', 'serial-getty@ttyS0.service'],
                            ['systemctl', 'daemon-reload'], ['systemctl', '--no-block', 'start', 'paw-controlled.service']]}
        network = {'version': 2, 'ethernets': {'wan0': {'match': {'macaddress': '52:54:00:14:41:02'},
                   'set-name': 'wan0', 'addresses': ['198.18.41.2/30'], 'dhcp4': False, 'dhcp6': False,
                   'accept-ra': False, 'link-local': [], 'routes': [{'to': 'default', 'via': '198.18.41.1'}]}}}
        (folder / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud))
        (folder / 'meta-data').write_text(json.dumps({'instance-id': job_id, 'local-hostname': 'paw-controlled'}))
        (folder / 'network-config').write_text(json.dumps(network))
        self.run(['/usr/bin/genisoimage', '-quiet', '-output', str(folder / 'seed.iso'), '-volid', 'cidata',
                  '-joliet', '-rock', str(folder / 'user-data'), str(folder / 'meta-data'), str(folder / 'network-config')])
        (folder / 'seed.iso').chmod(0o444)

    def start_vm(self):
        node = self.descriptor('worker', 'controlled', str(uuid.uuid4()), uuid.uuid4().hex)
        xml = ET.fromstring(node['xml'].read_text()); nic = xml.find('devices/interface')
        ET.SubElement(xml, 'defaultiothread', {'thread_pool_min': '0', 'thread_pool_max': '8'})
        nic.set('type', 'bridge'); nic.find('source').attrib = {'bridge': 'pawbr-up'}
        nic.find('mac').set('address', '52:54:00:14:41:02'); nic.find('target').set('dev', 'pu-gw')
        node['xml'].write_bytes(ET.tostring(xml)); self.vm = node
        self.control = self.output / 'owner-control.json'
        atomic(self.control, {'resume': False, 'expiry': self.absolute_limit})
        ready = self.output / 'owner-ready.json'
        config = {'parent_pid': os.getpid(), 'guard_fingerprint': guard_fingerprint(), 'xml': str(node['xml']),
                  'ready': str(ready), 'control': str(self.control), 'result': str(self.output / 'owner-result.json'),
                  'health': [{'pid': p.pid, 'identity': process_identity(p.pid)} for p in self.processes]}
        path = self.output / 'owner-config.json'; atomic(path, config)
        self.child = self.spawn(['/usr/bin/python3', '-I', str(Path(__file__).resolve()), '--owner', str(path)], 'owner')
        actual = self.wait_file(ready, 30); self.actual = actual
        self.run(['/usr/bin/systemctl', 'set-property', '--runtime', Path(actual['scope']).name, 'CPUQuota=50%'])
        actual['limits_after_parent_tightening'] = {n: (Path(actual['scope']) / n).read_text().strip()
                                                  for n in ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max']}
        domain = self.connection.lookupByUUIDString(node['uuid']); runtime = ET.fromstring(domain.XMLDesc(0))
        (self.output / 'actual-domain.xml').write_bytes(ET.tostring(runtime))
        assert runtime.find('defaultiothread').attrib == {'thread_pool_min': '0', 'thread_pool_max': '8'}
        self.report['domain'] = {**actual, 'uuid': node['uuid'], 'overlay': str(node['overlay'])}
        self.report['resources'] = {'pids_peak_sampled': 0, 'memory_peak_sampled': 0, 'pids_events_max': 0}
        self.channel = Channel(runtime.find('devices/serial/source').get('path'), self.output / 'guest-serial.log')
        def monitor():
            while not self.monitor_done:
                try:
                    scope = Path(actual['scope'])
                    values = self.report['resources']
                    values['pids_peak_sampled'] = max(values['pids_peak_sampled'], int((scope / 'pids.current').read_text()))
                    values['memory_peak_sampled'] = max(values['memory_peak_sampled'], int((scope / 'memory.current').read_text()))
                    values['pids_events_max'] = int(dict(line.split() for line in (scope / 'pids.events').read_text().splitlines())['max'])
                    assert values['pids_events_max'] == 0, 'pids_controller_rejected_fork'
                    assert policy_fingerprint() == self.expected, 'effective_policy_changed'
                    assert process_identity(actual['pid']) == actual['pid_identity'], 'qemu_identity_lost'
                    ports = {p.name for p in Path('/sys/class/net/pawbr-up/brif').iterdir()}
                    assert (ports <= {'pu-gw'} if self.offline_phase else ports == {'pu-gw'}), 'unexpected_bridge_ports:' + str(ports)
                    match_uplink(self.prepared_profile, current_uplink())
                    statuses = {str(p.pid): p.poll() for p in self.processes}
                    assert all(v is None for v in statuses.values()), 'health_process_exit:' + str(statuses)
                    if self.public and self.report.get('plan'):
                        route = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'route', 'get', self.report['plan']['address']], timeout=3))[0]
                        assert route['dev'] == self.profile['uplink']['interface'] and route['prefsrc'] == self.profile['uplink']['host_ipv4']
                    atomic(self.control, {'resume': True, 'expiry': self.absolute_limit})
                except Exception as error:
                    self.report['monitor_abort'] = str(error) or type(error).__name__
                    self.abort.set()
                    try: self.clear()
                    finally: atomic(self.control, {'resume': False, 'expiry': 0})
                    return
                time.sleep(.4)
        self.monitor = threading.Thread(target=monitor, daemon=True); self.monitor.start()
        wait_ready(self.channel, self.abort)
        self.absolute_limit = min(self.absolute_limit, time.monotonic() + 30)
        self.report['guest_state'] = self.channel.call('state')
        assert not self.abort.is_set()

    def tests(self):
        if self.args.case != 'success':
            start = time.monotonic()
            if self.args.case == 'guard-loss':
                self.nft('flush chain inet paw_s14_up_floor forward\n')
                assert self.abort.wait(5), 'monitor_failed_to_notice_guard_change'
            else:
                self.child.kill(); self.child.wait(timeout=3)
            assert self.stopped(), 'fault_stop_oracle'
            self.report['fault_stop_seconds'] = time.monotonic() - start
            assert self.report['fault_stop_seconds'] < 12
            self.record('local_fault_stopped_without_lease')
            return
        if self.public:
            first = observe_dns(self.target_host); second = observe_dns(self.target_host)
            assert first['answers'] == second['answers'], 'dns_binding_changed'
            self.profile['targets'][0]['pinned_ipv4'] = first['answers']
            self.profile['targets'][0]['authorization_ref'] = 'User authorized final-URL discovery and controlled GET on squishylab.fun, 2026-10-24'
            self.report['dns_observations'] = [first, second]
            observation = second
            self.wifi_capture = self.capture_on(self.profile['uplink']['interface'], 'wifi-target.pcap',
                                                'tcp', 'port', '443', 'and', 'host', observation['answers'][0])
        else:
            observation = {'answers': ['198.18.43.10'], 'ttl': 30, 'observed_monotonic': time.monotonic()}
        match_uplink(self.prepared_profile, current_uplink())
        assert not self.abort.is_set() and policy_fingerprint() == self.expected
        plan = admit(self.profile, self.profile['targets'][0]['id'], self.profile['targets'][0]['url'],
                     observation['answers'], time.monotonic() - observation['observed_monotonic'],
                     observation['ttl'], self.absolute_limit - time.monotonic())
        self.report['plan'] = plan; self.report['profile'] = self.profile
        if self.public:
            route = json.loads(self.run(['/usr/sbin/ip', '-j', 'route', 'get', plan['address']]).stdout)[0]
            assert route['dev'] == self.profile['uplink']['interface'] and route['prefsrc'] == self.profile['uplink']['host_ipv4']
            self.report['target_route'] = route
        self.nft(lease_transaction(self.profile, plan))
        try:
            remaining_ms = int((plan['expires_monotonic'] - time.monotonic()) * 1000)
            assert remaining_ms > 0 and not self.abort.is_set()
            self.report['public_get_attempted'] = self.public
            result = self.channel.call('fetch', seconds=10, address=plan['address'], lease_ms=remaining_ms)
            self.report['fetch'] = result
        finally:
            self.clear()
        assert result['status'] == 'completed' and result['tls_verified'] and result['http_status'] == 200, result
        assert result['peer'] == plan['address'] and result['requests'] == 1 and result['redirects'] == 0 and result['bytes'] <= 8192
        refused = self.channel.call('fetch', address=plan['address'], lease_ms=1000)
        assert refused['status'] == 'refused' and refused['reason'] == 'request_budget'
        self.report['second_request'] = refused
        assert not self.abort.is_set()
        self.record('one_pinned_verified_get_and_retry_refusal')
        if self.args.synthetic_fixture:
            self.synthetic()

    def synthetic(self):
        assert self.report['fetch']['status'] == 'completed' and not self.abort.is_set()
        self.clear()
        sets = [json.loads(self.run(['/usr/sbin/nft', '-j', 'list', 'set', 'inet', name, 'targets4']).stdout)
                for name in ['paw_s14_up_floor', 'paw_s14_up_lease']]
        assert all(not item.get('set', {}).get('elem') for data in sets for item in data['nftables'])
        self.offline_phase = True
        domain = self.connection.lookupByUUIDString(self.vm['uuid'])
        xml = ET.fromstring(domain.XMLDesc(0))
        nic = xml.find('devices/interface'); assert nic is not None
        domain.detachDeviceFlags(ET.tostring(nic).decode(), self.libvirt.VIR_DOMAIN_AFFECT_LIVE)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            state = self.channel.call('state')
            if not Path('/sys/class/net/pu-gw').exists() and state['network_interfaces'] == ['lo']:
                break
            time.sleep(.1)
        assert not Path('/sys/class/net/pu-gw').exists() and state['network_interfaces'] == ['lo']
        after = ET.fromstring(domain.XMLDesc(0)); assert not after.findall('devices/interface')
        (self.output / 'networkless-domain.xml').write_bytes(ET.tostring(after))
        assert not self.abort.is_set()
        result = self.channel.call('synthetic', seconds=5)
        assert result.get('returncode') == 0 and result['child_reaped'] and result['network_interfaces'] == ['lo'], result
        from benign_synthetic import MARKER
        assert bytes.fromhex(result['marker_hex']) == MARKER
        assert result['marker_sha256'] == hashlib.sha256(MARKER).hexdigest()
        assert not self.abort.is_set()
        self.report['synthetic'] = {**result, 'lease_sets_empty': True, 'tap_removed': True,
                                    'guest_nic_absent': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path); parser.add_argument('--prepared', type=Path)
    parser.add_argument('--output', type=Path); parser.add_argument('--export', type=Path)
    parser.add_argument('--mode', choices=['fixture', 'public'], default='fixture')
    parser.add_argument('--case', choices=['success', 'guard-loss', 'owner-loss'], default='success')
    parser.add_argument('--target', choices=sorted(PUBLIC_TARGETS), default='apex')
    parser.add_argument('--synthetic-fixture', action='store_true')
    parser.add_argument('--authorize-public-one-get', action='store_true')
    parser.add_argument('--local-evidence', type=Path)
    args = parser.parse_args()
    if args.owner:
        supervisor_child(args.owner); return
    assert os.geteuid() == 0 and args.prepared and args.output and args.export
    if args.mode == 'public':
        assert args.authorize_public_one_get and args.case == 'success' and args.local_evidence
        from verify_controlled_uplink import verify
        for case in ['success', 'guard-loss', 'owner-loss']:
            root = args.local_evidence / case
            assert root.stat().st_uid == 0 and root.stat().st_mode & 0o022 == 0
            verify(root, 'fixture', case, current_sources=HERE)
    validation = Controlled(args)
    try:
        validation.prepare(); validation.start_vm(); validation.tests(); validation.report['result'] = 'PASS'
    except Exception as error:
        validation.report['error'] = str(error); validation.report['traceback'] = traceback.format_exc()
        print(validation.report['traceback'], flush=True)
    finally:
        try: validation.cleanup()
        except Exception as error:
            validation.report['cleanup_error'] = str(error); validation.report['result'] = 'FAIL'
            print(traceback.format_exc(), flush=True)
        (args.output / 'results.json').write_text(json.dumps(validation.report, indent=2) + '\n')
        args.export.mkdir(mode=0o700, parents=True, exist_ok=False)
        for path in args.output.iterdir():
            if path.is_file() and path.suffix in {'.json', '.jsonl', '.xml', '.log', '.pcap', '.pem'}:
                shutil.copyfile(path, args.export / path.name); os.chown(args.export / path.name, 1000, 1000)
        shutil.copytree(args.output / 'sources', args.export / 'sources')
        for path in (args.export / 'sources').iterdir(): os.chown(path, 1000, 1000)
        for path in [args.export / 'sources', args.export]: os.chown(path, 1000, 1000)
        print('Controlled uplink: ' + validation.report['result'], flush=True)
    if validation.report['result'] != 'PASS': raise SystemExit(1)


if __name__ == '__main__':
    main()
