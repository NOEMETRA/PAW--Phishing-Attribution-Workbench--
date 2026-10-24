"""Fixed benign execution after verified HTTP200 metadata, without any VM NIC.

An oversized HTTP body remains refused. Its authenticated HTTP200 headers may
authorize this independent benign-only fixture, never downloaded code.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from benign_synthetic import MARKER

CONTROLLED_PRODUCER_SOURCES = frozenset('''fixture_server.py machine-paws14.slice
test_uplink_policy.py paused-probe.xml benign_guest_validation.py paw-s14-guard.service
test_controlled_uplink.py gw_admission.py host_task_budget_probe.py guest_agent.py
gateway-wan.xml gateway-host.nft gw_fixture.py gw_fault_validation.py fetch_trusted_image.py
internal-network.xml controlled_uplink.py test_uplink_vm_evidence.py all-guards.nft
uplink_policy.py uplink_guest_probe.py controlled_scope.py verify_controlled_uplink.py
verify_gateway_evidence.py gw_node.py verify_uplink_vm_evidence.py verify_gateway_reboot.py
host-guard.nft validate_uplink_namespace.py validate_uplink_vm.py gw_quarantine.py
prepare_uplink.py gw_validation.py controlled_guest.py libvirtd-guard.conf
verify_uplink_evidence.py gateway-bridge.nft gateway-guest.nft gw_broker.py
verify_benign_evidence.py benign_synthetic.py test_gw_contracts.py'''.split())


def verify_prior_sources(root, manifest):
    from verify_synthetic_gate import verify_sources
    verify_sources(root, manifest, required=CONTROLLED_PRODUCER_SOURCES)
    for name, expected in manifest.items():
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != expected:
            raise ValueError('current_producer_source_changed:' + name)


def header_authority(fetch):
    obs = fetch.get('observation', {})
    if not (fetch.get('status') == 'refused' and fetch.get('reason') == 'response_budget' and
            obs.get('http_status') == 200 and obs.get('tls_verified') is True and
            obs.get('tls_hostname') == 'www.squishylab.fun' and obs.get('requests') == 1 and
            obs.get('redirects') == 0 and obs.get('body_bytes_read') == 8193 and
            re.fullmatch('[0-9a-f]{64}', obs.get('certificate_sha256', '')) and 0 <= obs.get('elapsed_seconds', 99) <= 5.5):
        raise ValueError('verified_http200_metadata_required')
    return {'target': 'https://www.squishylab.fun/', 'http_status': 200,
            'tls_verified': True, 'certificate_sha256': obs['certificate_sha256'],
            'body_accepted': False, 'application_fetch_result': 'FAIL_RESPONSE_BUDGET',
            'authority_scope': 'one fixed benign networkless fixture; no web content execution'}


def emit(value):
    data = ('PAW14 ' + json.dumps(value) + '\n').encode()
    while data: data = data[os.write(1, data):]


def guest():
    import tty
    tty.setraw(0)
    def networkless():
        if sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']:
            raise ValueError('guest_has_network_device')
    networkless()
    authority = json.loads(Path('/etc/paw-synthetic-authority.json').read_text())
    if authority['http_status'] != 200 or authority['tls_verified'] is not True or authority['body_accepted'] is not False:
        raise ValueError('metadata_authority')
    emit({'ready': True, 'network_interfaces': ['lo'], 'mode': 'fixed-benign-networkless'})
    used = False
    while True:
        raw = sys.stdin.buffer.readline(1025)
        if not raw: return
        if len(raw) > 1024: raise ValueError('frame_budget')
        command = json.loads(raw)
        try:
            if used or set(command) != {'id', 'op'} or command['op'] != 'run-known-fixture':
                raise ValueError('fixed_once_operation')
            used = True; networkless()
            with subprocess.Popen(['/usr/bin/python3', '-I', str(HERE / 'benign_synthetic.py')],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
                try: stdout, stderr = child.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill(); child.communicate(timeout=1); raise ValueError('fixture_deadline')
                if child.returncode != 0 or len(stdout) > 4096 or len(stderr) > 4096:
                    raise ValueError('fixture_execution')
                result = json.loads(stdout)
                if result['pid'] != child.pid or bytes.fromhex(result['marker_hex']) != MARKER:
                    raise ValueError('child_or_marker')
                networkless()
                emit({'id': command['id'], 'ok': True, 'data': {**result, 'returncode': 0, 'child_reaped': True}})
        except Exception as error:
            emit({'id': command.get('id'), 'ok': False, 'error': str(error)})


def host(args):
    from gw_validation import Matrix, Channel, atomic
    from benign_guest_validation import supervisor_child, guard_fingerprint, process_identity, BASE, digest
    from validate_uplink_namespace import Validation
    from verify_controlled_uplink import positive_packets
    from verify_gateway_evidence import pcap
    from uplink_policy import validate, fingerprint
    if args.owner: supervisor_child(args.owner); return
    assert os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined'
    assert args.prior.stat().st_uid == 0 and not args.prior.stat().st_mode & 0o022
    prior = json.loads((args.prior / 'results.json').read_text())
    authority = header_authority(prior['fetch'])
    assert prior['result'] == 'FAIL' and not prior.get('cleanup_error') and not prior.get('monitor_abort')
    assert all(prior[k] for k in ['writers_stopped', 'host_network_restored', 'source_freeze_unchanged', 'base_unchanged'])
    assert prior['host_before'] == prior['host_after']
    verify_prior_sources(args.prior, prior['source_hashes'])
    profile = validate(prior['profile']); plan = prior['plan']; obs = prior['fetch']['observation']
    assert plan['profile_sha256'] == fingerprint(profile) and plan['url'] == profile['targets'][0]['url'] == authority['target']
    assert obs['peer'] == plan['address'] in profile['targets'][0]['pinned_ipv4']
    assert prior['dns_observations'][0]['answers'] == prior['dns_observations'][1]['answers'] == plan['all_addresses']
    for name, source, arp in [('uplink-vm.pcap', '198.18.41.2', True),
                              ('wifi-target.pcap', profile['uplink']['host_ipv4'], False)]:
        positive_packets(pcap(args.prior / name), source, plan['address'], arp)

    class Offline(Matrix):
        snapshot_host = Validation.snapshot_host
        def seed(self, folder, role, job_id, token):
            service = ('[Unit]\nAfter=cloud-final.service\n[Service]\n'
                       'ExecStart=/usr/bin/python3 -I -u /usr/local/lib/paw-s14/networkless_synthetic.py --guest\n'
                       'StandardInput=tty-force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n'
                       'TasksMax=32\nMemoryMax=128M\nMemorySwapMax=0\nCPUQuota=50%\n')
            files = [('/usr/local/lib/paw-s14/' + n, (HERE / n).read_bytes())
                     for n in ['networkless_synthetic.py', 'benign_synthetic.py']]
            files += [('/etc/paw-synthetic-authority.json', json.dumps(authority).encode()),
                      ('/etc/systemd/system/paw-networkless.service', service.encode())]
            cloud = {'package_update': False, 'package_upgrade': False, 'ssh_pwauth': False, 'ssh_genkeytypes': [],
                     'write_files': [{'path': p, 'encoding': 'b64', 'content': base64.b64encode(data).decode(), 'permissions': '0644'} for p, data in files],
                     'runcmd': [['systemctl', 'mask', '--now', 'ssh.service', 'ssh.socket', 'serial-getty@ttyS0.service'],
                                ['systemctl', 'daemon-reload'], ['systemctl', '--no-block', 'start', 'paw-networkless.service']]}
            (folder / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud))
            (folder / 'meta-data').write_text(json.dumps({'instance-id': job_id, 'local-hostname': 'paw-networkless'}))
            (folder / 'network-config').write_text(json.dumps({'version': 2, 'ethernets': {}}))
            self.run(['/usr/bin/genisoimage', '-quiet', '-output', str(folder / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                      str(folder / 'user-data'), str(folder / 'meta-data'), str(folder / 'network-config')])
            (folder / 'seed.iso').chmod(0o444)

    run = Offline(args); before = run.snapshot_host(); child = None; channel = None; node = None
    run.report.update(scope='fixed benign synthetic only; networkless from creation', authority=authority, new_gets=0)
    try:
        assert not run.connection.listAllDomains(0) and guard_fingerprint()
        node = run.descriptor('extractor', 'networkless-synthetic', str(uuid.uuid4()), uuid.uuid4().hex)
        xml = ET.fromstring(node['xml'].read_text()); assert not xml.findall('devices/interface')
        ET.SubElement(xml, 'defaultiothread', {'thread_pool_min': '0', 'thread_pool_max': '8'})
        node['xml'].write_bytes(ET.tostring(xml))
        control = args.output / 'owner-control.json'; ready = args.output / 'owner-ready.json'
        atomic(control, {'resume': False, 'expiry': time.monotonic() + 260})
        config = {'parent_pid': os.getpid(), 'guard_fingerprint': guard_fingerprint(), 'xml': str(node['xml']),
                  'ready': str(ready), 'control': str(control), 'result': str(args.output / 'owner-result.json'), 'health': []}
        path = args.output / 'owner-config.json'; atomic(path, config)
        child = run.spawn(['/usr/bin/python3', '-I', str(Path(__file__).resolve()), '--owner', str(path)], 'owner')
        actual = run.wait_file(ready, 30); scope = Path(actual['scope'])
        run.run(['/usr/bin/systemctl', 'set-property', '--runtime', scope.name, 'CPUQuota=50%'])
        domain = run.connection.lookupByUUIDString(node['uuid']); runtime = ET.fromstring(domain.XMLDesc(0))
        assert not runtime.findall('devices/interface') and not runtime.findall('devices/filesystem') and not runtime.findall('devices/hostdev')
        (args.output / 'networkless-domain.xml').write_bytes(ET.tostring(runtime))
        run.report['domain'] = actual
        channel = Channel(runtime.find('devices/serial/source').get('path'), args.output / 'guest-serial.log')
        atomic(control, {'resume': True, 'expiry': time.monotonic() + 240})
        # The immutable image waits ~120 s for network-online with no NIC.
        # This budget applies only to this networkless VM, never a live lease.
        state = channel.ready(220); assert state['network_interfaces'] == ['lo']
        atomic(control, {'resume': True, 'expiry': time.monotonic() + 30})
        result = channel.call('run-known-fixture', seconds=5)
        assert result['returncode'] == 0 and result['child_reaped'] and result['network_interfaces'] == ['lo']
        assert bytes.fromhex(result['marker_hex']) == MARKER and result['marker_sha256'] == hashlib.sha256(MARKER).hexdigest()
        resource = {n: (scope / n).read_text().strip() for n in ['pids.peak', 'pids.events', 'memory.peak', 'pids.max', 'memory.max', 'memory.swap.max', 'cpu.max']}
        assert resource['pids.max'] == '64' and resource['memory.max'] == str(768 * 1024**2) and resource['memory.swap.max'] == '0'
        assert int(resource['pids.peak']) <= 64 and int(resource['memory.peak']) <= 768 * 1024**2
        assert dict(line.split() for line in resource['pids.events'].splitlines())['max'] == '0'
        run.report.update(synthetic=result, resources=resource, result='PASS')
    except Exception as error:
        run.report.update(error=str(error), traceback=traceback.format_exc()); print(run.report['traceback'], flush=True)
    finally:
        try:
            if child:
                if child.poll() is None: child.terminate()
                child.wait(timeout=12)
            if node:
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    try: run.connection.lookupByUUIDString(node['uuid']); present = True
                    except run.libvirt.libvirtError: present = False
                    if not present and process_identity(actual['pid']) != actual['pid_identity']: break
                    time.sleep(.1)
                assert not present and process_identity(actual['pid']) != actual['pid_identity']
            if channel: channel.close()
            assert before == run.snapshot_host() and not run.connection.listAllDomains(0)
            assert all(hashlib.sha256((HERE / n).read_bytes()).hexdigest() == h for n, h in run.source_hashes.items())
            assert digest(BASE) == run.root_image_sha
            run.report.update(host_before=before, host_after=run.snapshot_host(), host_restored=True, writers_stopped=True, source_freeze_unchanged=True, base_unchanged=True)
            run.connection.close()
        except Exception as error:
            run.report.update(result='FAIL', cleanup_error=str(error))
        (args.output / 'results.json').write_text(json.dumps(run.report, indent=2) + '\n')
        args.export.mkdir(mode=0o700, parents=True, exist_ok=False)
        for p in args.output.iterdir():
            if p.is_file() and p.suffix in {'.json', '.xml', '.log'}:
                shutil.copyfile(p, args.export / p.name); os.chown(args.export / p.name, 1000, 1000)
        shutil.copytree(args.output / 'sources', args.export / 'sources')
        for p in (args.export / 'sources').iterdir(): os.chown(p, 1000, 1000)
        for p in [args.export / 'sources', args.export]: os.chown(p, 1000, 1000)
    print('Networkless fixed benign fixture: ' + run.report['result'], flush=True)
    if run.report['result'] != 'PASS': raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', action='store_true'); parser.add_argument('--owner', type=Path)
    parser.add_argument('--prior', type=Path); parser.add_argument('--output', type=Path); parser.add_argument('--export', type=Path)
    args = parser.parse_args()
    if args.guest: guest()
    else: host(args)
