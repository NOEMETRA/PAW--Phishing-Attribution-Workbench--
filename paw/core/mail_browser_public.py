"""Finite reviewed real-mail adapter around PAW's existing no-NIC browser.

No public work follows from import. The privileged entry must first admit the
protected native three-source scope. Only a confined nonroot transport may open
IPv4 sockets; the guest continues to have no NIC. HTTP/TLS parsing is reused.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve()
if __package__:
    from . import browser_cdp as cdp, browser_owned_broker_guest as captured
    from . import browser_owned_cdp_guest as fixed, browser_mediator as mediator
    from . import browser_broker_wire as wire, mail_browser_dns as dns
    from . import owned_kernel_runtime as kernel
else:
    sys.path.insert(0, str(HERE.parent))
    import browser_cdp as cdp, browser_owned_broker_guest as captured
    import browser_owned_cdp_guest as fixed, browser_mediator as mediator
    import browser_broker_wire as wire, mail_browser_dns as dns
    import owned_kernel_runtime as kernel

TABLES = ('paw_mail_floor', 'paw_mail_gate')
UID = 65520
CASE_REQUESTS = 32//3
CASE_BYTES = (4*1024**2)//3
PROGRAMS = ('mail_browser_public.py', 'browser_cdp.py', 'browser_owned_cdp_guest.py',
            'browser_owned_broker_guest.py', 'browser_broker_console.py', 'browser_mediator.py',
            'browser_broker_wire.py', 'mail_browser_dns.py', 'owned_kernel_runtime.py',
            'owned_kernel_policy.py', 'browser_owned_protocol.py')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(job, epoch, release, serial=0):
    need(all(type(v) is str and re.fullmatch('[0-9a-f]{32}', v) for v in [job, epoch]) and
         type(release) is str and re.fullmatch('[0-9a-f]{40}', release), 'mail_public_identity')
    need(type(serial) is int and 0 <= serial < 8, 'mail_public_probe_serial')
    prefix = 'paw-owned-kernel-'+job+'-'+epoch[:12]
    return {'job': job, 'epoch': epoch, 'release': release, 'parent': 'paw-vm-owned-'+job+'.service',
            'directory': '/var/lib/paw-vm/jobs/'+job+'/mail-network/'+epoch,
            **{role: prefix+'-mail-'+role+('-'+str(serial) if role == 'probe' else '')+'.service'
               for role in ['keeper', 'probe', 'fixture']}}


def rules(cgroup, interface, source_addresses):
    """Only this vacant UID's output and this cgroup's incoming sockets.

    Socket cgroupv2 lookup also selects untracked replies; the ingress chain
    refuses them. Existing host sockets, marks, routes and interfaces are not
    changed. None of these data compilers installs a rule or grants authority.
    """
    need(type(interface) is str and re.fullmatch('[A-Za-z0-9_.-]{1,15}', interface),
         'mail_public_bound_interface')
    need(type(source_addresses) is list and 1 <= len(source_addresses) <= 2 and
         len(set(source_addresses)) == len(source_addresses), 'mail_public_source_addresses')
    import ipaddress
    for address in source_addresses:
        need(type(address) is str and str(ipaddress.IPv4Address(address)) == address,
             'mail_public_source_address')
    if cgroup is not None:
        need(type(cgroup) is str and re.fullmatch(
            r'/system\.slice/paw-owned-kernel-[0-9a-f]{32}-[0-9a-f]{12}-mail-probe-[0-7]\.service', cgroup),
             'mail_public_exact_worker_cgroup')
    denied = ', '.join(str(v) for v in mediator.DENIED)
    sources = ', '.join(source_addresses)
    selected = '' if cgroup is None else 'socket cgroupv2 level 2 "'+cgroup[1:]+'" jump ingress'
    out = []
    for name, priority in zip(TABLES, [0, 10]):
        out.append(f'''table inet {name} {{
 set tcp4 {{ type ipv4_addr . inet_service; flags timeout; timeout 5s; size 1; }}
 set udp4 {{ type ipv4_addr . inet_service; flags timeout; timeout 5s; size 1; }}
 chain egress {{
  meta nfproto ipv6 drop
  oifname != "{interface}" drop
  ip saddr != {{ {sources} }} drop
  ct state untracked drop
  ip daddr {{ {denied} }} drop
  ip daddr . tcp dport @tcp4 accept
  ip daddr . udp dport @udp4 accept
  drop
 }}
 chain ingress {{
  meta nfproto ipv6 drop
  iifname != "{interface}" drop
  ip saddr {{ {denied} }} drop
  ip saddr . tcp sport @tcp4 ct state established accept
  ip saddr . udp sport @udp4 ct state established accept
  drop
 }}
 chain input_guard {{ type filter hook input priority {priority}; policy accept;
  {selected}
 }}
 chain output_guard {{ type filter hook output priority {priority}; policy accept;
  meta skuid {UID} jump egress
 }}
}}''')
    return '\n'.join(out)+'\n'


def revoke():
    return ''.join(f'flush set inet {table} {name}\n' for table in TABLES for name in ['tcp4', 'udp4'])


def lease(kind, address, milliseconds):
    need(kind in {'dns', 'http', 'https'} and type(milliseconds) is int and 1 <= milliseconds <= 3000,
         'mail_public_kernel_lease')
    need(mediator.public_answers([address]) == [address], 'mail_public_numeric_pin')
    if kind == 'dns':
        need(address == dns.RESOLVER[0], 'mail_public_fixed_resolver')
    port = {'dns':53, 'http':80, 'https':443}[kind]
    name = 'udp4' if kind == 'dns' else 'tcp4'
    return revoke()+''.join(f'add element inet {table} {name} {{ {address} . {port} timeout {milliseconds}ms }}\n'
                            for table in TABLES)



class BatchBudget:
    """Three fixed allocations, never three independent4MiB/32-request grants."""
    def __init__(self, seeds, previous=None):
        need(type(seeds) is list and len(seeds) == 3, 'mail_public_three_seeds')
        self.hosts = {mediator.endpoint(v)['host'] for v in seeds}
        self.used = [0, 0, 0]; self.bytes = [0, 0, 0]; self.reserved = [0, 0, 0]
        if previous is not None:
            need(type(previous) is dict and set(previous) == set(self.facts()), 'mail_public_budget_handoff_shape')
            hosts = previous['hostname_slots']
            need(type(hosts) is list and hosts == sorted(set(hosts)) and
                 self.hosts <= set(hosts) and len(hosts) <= 8, 'mail_public_budget_handoff_hosts')
            for host in hosts: dns.host_name(host)
            for key, cap in [('request_slots', CASE_REQUESTS),
                             ('response_bytes_or_unrecoverable_reservations', CASE_BYTES)]:
                rows = previous[key]
                need(type(rows) is list and len(rows) == 3 and
                     all(type(v) is int and 0 <= v <= cap for v in rows), 'mail_public_budget_handoff_counts')
            self.hosts = set(hosts); self.used = list(previous['request_slots'])
            self.bytes = list(previous['response_bytes_or_unrecoverable_reservations'])
            need(canonical(previous) == canonical(self.facts()), 'mail_public_budget_handoff_contract')
    def _slot(self, slot):
        need(type(slot) is int and 0 <= slot < 3, 'mail_public_case_slot')
    def request(self, slot):
        self._slot(slot)
        need(self.used[slot] < CASE_REQUESTS,
             'mail_public_case_request_budget')
        self.used[slot] += 1
    def hostname(self, host):
        dns.host_name(host)
        if host not in self.hosts:
            need(len(self.hosts) < 8, 'mail_public_batch_hostname_budget')
            self.hosts.add(host)
    def reserve(self, slot):
        self._slot(slot)
        need(self.reserved[slot] == 0, 'mail_public_pending_byte_reservation')
        remaining = CASE_BYTES-self.bytes[slot]
        need(remaining > 0, 'mail_public_case_byte_budget')
        self.reserved[slot] = remaining
        return remaining
    def complete(self, slot, actual):
        self._slot(slot)
        need(self.reserved[slot] > 0 and type(actual) is int and 0 <= actual <= self.reserved[slot],
             'mail_public_reserved_response_budget')
        self.bytes[slot] += actual; self.reserved[slot] = 0
    def uncertain(self, slot):
        self._slot(slot)
        need(self.reserved[slot] > 0, 'mail_public_pending_reservation_missing')
        self.bytes[slot] += self.reserved[slot]; self.reserved[slot] = 0
    def facts(self):
        need(sum(self.used) <= 32 and sum(self.bytes)+sum(self.reserved) <= 4*1024**2,
             'mail_public_aggregate_budget')
        return {'hostname_slots': sorted(self.hosts), 'request_slots': list(self.used),
                'response_bytes_or_unrecoverable_reservations': [v+r for v,r in zip(self.bytes,self.reserved)],
                'effective_per_case_requests': CASE_REQUESTS, 'effective_per_case_response_bytes': CASE_BYTES,
                'batch_http_ceiling':32, 'batch_response_ceiling':4*1024**2, 'batch_host_ceiling':8}


class PublicRuntime(captured.Runtime):
    def _start_nonce(self):
        config = cdp.strict_json(Path('/etc/paw-mail-browser.json').read_bytes())
        need(type(config) is dict and set(config) == {'kind', 'nonce', 'url'} and
             config['kind'] == 'mail-public-browser-v1' and type(config['nonce']) is str and
             re.fullmatch('[0-9a-f]{32}', config['nonce']), 'mail_public_guest_seed')
        mediator.endpoint(config['url'])
        self.seed = config['url']; return config['nonce']
    def _make_controller(self):
        # The existing controller already denies downloads and permissions,
        # intercepts before navigation and closes unsupported child targets.
        return captured.CaptureController(self.seed, self.nonce, self._send, self._request)
    def inspect(self):
        result=super().inspect()
        result['purpose']='Selected mail URL; no-NIC main-page browser capture'
        return result
    def _snapshot_due(self):
        return self.driver.stage == 'running' and self.requests >= 1 and self.driver.fetch.pending is None and \
            not self.driver.queue and time.monotonic()-self.started >= 3
    def _validate_completed(self):
        need(type(self.driver.dom) is bytes and 0 < len(self.driver.dom) <= 256*1024 and
             all(self.witness.flags().values()),
             'mail_public_actual_dom_or_sandbox_missing')
    def start(self):
        result = super().start()
        result['purpose'] = 'Selected mail URL, no-NIC main-page brokered capture'
        return result
    def finish(self, status, error=None):
        value = super().finish(status, error)
        value['scope'] = 'Main-page no-NIC browser capture; broker TLS, not browser TLS fingerprint'
        value['unsupported_targets'] = list(self.driver.missing) if self.driver is not None else []
        return value


class PublicTransport:
    """Typed Root channel only; reuse the existing DNS and HTTP/TLS I/O."""
    def __init__(self, nonce, deadline_ns, dns_transport, http_transport):
        need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce) and
             type(deadline_ns) is int and time.monotonic_ns() < deadline_ns <= time.monotonic_ns()+10**10,
             'mail_public_transport_session')
        self.nonce = nonce; self.deadline = deadline_ns; self.dns = dns_transport; self.http = http_transport
        self.sequence = 0; self.bytes = 0; self.closed = False
    def dispatch(self, nonce, sequence, kind, fields, body):
        need(not self.closed, 'mail_public_transport_closed')
        try:
            need(nonce == self.nonce and type(sequence) is int and sequence == self.sequence and
                 sequence < 66 and type(fields) is dict and type(body) is bytes and body == b'' and
                 kind in {'dns', 'http', 'stop'} and time.monotonic_ns() < self.deadline,
                 'mail_public_transport_envelope')
            self.sequence += 1
            if kind == 'stop':
                need(not fields, 'mail_public_stop_shape'); self.closed = True
                return {'request_sequence':sequence, 'operation':'stop', 'stopped':True}, b''
            if kind == 'dns':
                need(set(fields) == {'host', 'ident', 'deadline_ns'} and type(fields['ident']) is int and
                     0 <= fields['ident'] <= 65535 and type(fields['deadline_ns']) is int and
                     time.monotonic_ns() < fields['deadline_ns'] <= self.deadline, 'mail_public_dns_frame')
                mediator.endpoint('https://'+fields['host']+'/')
                raw = self.dns(fields['host'], fields['ident'], fields['deadline_ns'])
                need(type(raw) is bytes and 12 <= len(raw) <= 4096, 'mail_public_dns_bytes')
                return {'request_sequence':sequence, 'operation':'dns', 'host':fields['host'],
                        'ident':fields['ident'], 'received_ns':time.monotonic_ns()}, raw
            need(set(fields) == {'plan', 'remaining_bytes'} and type(fields['plan']) is dict and
                 type(fields['remaining_bytes']) is int and 0 <= fields['remaining_bytes'] <= CASE_BYTES,
                 'mail_public_http_frame')
            plan = fields['plan']; mediator.endpoint(plan.get('url'))
            need(plan.get('nonce') == nonce and type(plan.get('expires_ns')) is int and
                 plan['expires_ns'] <= self.deadline and
                 mediator.public_answers(plan.get('all_ipv4')) == plan['all_ipv4'] and
                 plan.get('peer_ipv4') in plan['all_ipv4'], 'mail_public_http_peer')
            remaining = min(fields['remaining_bytes'], CASE_BYTES-self.bytes)
            metadata, raw = self.http(plan, remaining)
            need(type(raw) is bytes and len(raw) <= remaining and type(metadata) is dict and
                 metadata.get('body_bytes') == len(raw) and metadata.get('body_sha256') == sha(raw),
                 'mail_public_http_binding')
            self.bytes += len(raw)
            return {'request_sequence':sequence, 'operation':'http', 'transport':metadata}, raw
        except BaseException:
            self.closed = True; raise


def _keeper_root(folder):
    # A sibling of mail-network, so binding the writable epoch cannot recurse
    # into its own root directory.
    return folder.parent.parent/'mail-keeper-roots'/folder.name


def _prepare_keeper_root(folder, release):
    root=_keeper_root(folder)
    root.parent.mkdir(mode=0o700,exist_ok=True)
    root.mkdir(mode=0o700)
    for name in ['usr','lib','lib64','etc','proc','sys/fs/cgroup','dev','tmp',
                 'run/systemd','home','root',str(folder).lstrip('/'),
                 'opt/paw-vm/releases/'+release+'/paw/core']:
        (root/name).mkdir(mode=0o755,parents=True,exist_ok=True)
    (root/'bin').symlink_to('usr/bin')
    root.chmod(0o555)


def service(job, epoch, release, role, keeper_pid=None, serial=0, *, protocol=False):
    """Finite PID1 role profiles, never caller-provided properties or commands."""
    ids = identity(job, epoch, release, serial)
    _, props, _ = kernel.policy.service(job, epoch, release, role,
        keeper_pid if keeper_pid is not None else 2, serial, protocol=protocol)
    folder = Path(ids['directory'])
    config = kernel.private_json(folder/'public.json')
    need(config['mode'] in {'owned-raw', 'owned-browser', 'public'}, 'mail_public_role_mode')
    props.update(BindsTo=ids['parent'], After=ids['parent'])
    if role == 'fixture':
        need(config['mode'] != 'public', 'mail_public_no_public_fixture')
        props.pop('NetworkNamespacePath', None)
        props.update(PrivateNetwork='yes', RootDirectory=str(folder/'fixture-root'),
                     BindReadOnlyPaths='/usr /lib /lib64 '+str(folder/'code')+':/opt/paw-code',
                     IPAddressAllow='93.184.216.34/32 9.9.9.9/32')
    elif role == 'keeper':
        props.update(PrivateNetwork='no', ReadWritePaths=str(folder),
                     RootDirectory=str(_keeper_root(folder)),MountAPIVFS='yes',BindPaths=str(folder),
                     BindReadOnlyPaths='/usr /lib /lib64 /sys/fs/cgroup /run/systemd '+
                         '/opt/paw-vm/releases/'+release+'/paw/core',
                     SystemCallFilter='@system-service', SystemCallArchitectures='native')
        if config['mode'] != 'public':
            need(type(keeper_pid) is int and keeper_pid > 1, 'mail_public_fixture_namespace')
            props['NetworkNamespacePath'] = '/proc/'+str(keeper_pid)+'/ns/net'
        # Keep500ms and10%CPU. A Root-private proof is written only after both
        # tables' sets were successfully flushed in the finalizer. Otherwise
        # retain the exact fixed nft backstop, including abrupt guard loss.
        props.update(ExecStopPost="/bin/sh -c 'printf x > "+str(folder/'stop-hook-entered')+
                     '; test -f '+str(folder/'revoked-complete')+
                     ' || exec /usr/sbin/nft -f '+str(folder/'revoke.nft')+"'")
    else:
        need(type(keeper_pid) is int and keeper_pid > 1, 'mail_public_guard_namespace')
        props.update(RootDirectory=str(folder/'probe-root'),
            BindReadOnlyPaths='/usr /lib /lib64 '+str(folder/'code')+':/opt/paw-code',
            BindsTo=ids['keeper'], After=ids['keeper'], IPAddressAllow='',
            NetworkNamespacePath='/proc/'+str(keeper_pid)+'/ns/net')
    program = ('/opt/paw-vm/releases/'+release+'/paw/core/mail_browser_public.py'
               if role == 'keeper' else '/opt/paw-code/mail_browser_public.py')
    command = ['/usr/bin/python3', '-I', '-S', '-B', program, '--'+role, job, epoch, release]
    if role == 'probe':
        command.append('wire' if protocol else 'raw')
    return ids[role], props, command


class PublicActor(kernel.Managed):
    def _service(self, job, epoch, release, role, keeper_pid, serial, *, protocol):
        return service(job, epoch, release, role, keeper_pid, serial, protocol=protocol)


def root_config(job, epoch, release):
    ids = identity(job, epoch, release)
    need(os.geteuid() == 0 and HERE == Path('/opt/paw-vm/releases')/release/
         'paw/core/mail_browser_public.py', 'mail_public_immutable_root_only')
    config = kernel.private_json(Path(ids['directory'])/'public.json')
    need(set(config) == {'schema', 'job', 'epoch', 'release', 'mode', 'interface', 'source_addresses',
                        'controller_pid', 'controller_identity', 'namespace_inode', 'host_namespace_inode'} and
         config['schema'] == 'paw-mail-network-v1' and
         all(config[k] == ids[k] for k in ['job', 'epoch', 'release']) and
         config['mode'] in {'owned-raw', 'owned-browser', 'public'} and
         type(config['namespace_inode']) is int and config['namespace_inode']>0 and
         type(config['host_namespace_inode']) is int and config['host_namespace_inode']>0,
         'mail_public_protected_config')
    rules(None, config['interface'], config['source_addresses'])
    return ids, config


def guard_identity(binding=None, *, expected=None):
    digest,stale = _guard_identity_once(binding)
    if not stale:return digest
    # The whole first snapshot, including later selectors and other rule
    # fields, must match the established identity before a fresh read is safe.
    # The tentative normalization of a stale name never establishes a pin.
    need(expected is not None,'mail_public_cgroup_path_not_live')
    need(digest==expected,'mail_public_guard_snapshot_changed')
    observed,again = _guard_identity_once(binding)
    need(not again,'mail_public_cgroup_path_not_live')
    need(observed==expected,'mail_public_guard_snapshot_changed')
    return observed


def _guard_identity_once(binding):
    value = json.loads(kernel.nft('-j', 'list', 'ruleset'))
    selectors_seen = [];stale_names = []
    def cgroup_id(right):
        need(binding is not None, 'mail_public_unarmed_cgroup_selector')
        group, inode = binding
        # nft1.1.6 renders the SAME kernel ID as a pathname while its cgroup
        # exists, then as a decimal JSON string after PID1 collects the unit.
        # Pin the live inode at arm time; never discard the selector itself.
        path = Path('/sys/fs/cgroup'+group)
        try: current = path.stat().st_ino
        except FileNotFoundError: current = None
        need(current is None or current == inode, 'mail_public_cgroup_replaced')
        if right == group.lstrip('/'):
            if current is None:stale_names.append(True)
        else:
            need((type(right) is int and right == inode) or
                 (type(right) is str and right == str(inode)), 'mail_public_cgroup_id_changed')
        selectors_seen.append(inode)
        return inode
    def clean(v):
        if type(v) is list:
            return [clean(x) for x in v if not (type(x) is dict and 'metainfo' in x)]
        if type(v) is dict:
            if set(v) == {'match'} and type(v['match']) is dict:
                match = v['match']
                if match.get('left') == {'socket':{'key':'cgroupv2'}}:
                    need(set(match) == {'op','left','right'} and match['op'] == '==',
                         'mail_public_cgroup_expression')
                    return {'match':{**match, 'right':cgroup_id(match['right'])}}
            return {k:clean(x) for k,x in v.items() if k != 'handle' and
                    not (k == 'elem' and v.get('name') in {'tcp4', 'udp4'})}
        return v
    selected = [row for row in value['nftables'] if any(
        type(body) is dict and (body.get('table') in TABLES or
        kind == 'table' and body.get('name') in TABLES) for kind,body in row.items())]
    need(sum(1 for row in selected if 'table' in row) == 2, 'mail_public_guard_missing')
    cleaned = clean(selected)
    need(len(selectors_seen) == (0 if binding is None else 2), 'mail_public_cgroup_selector_count')
    return sha(canonical(cleaned)),bool(stale_names)


def keeper_action(value, epoch, sequence, ids):
    need(type(value) is dict and value.get('epoch') == epoch and
         type(value.get('id')) is int and value['id'] == sequence and 0 <= sequence < 128,
         'mail_public_guard_control')
    op = value.get('op')
    if op == 'lease':
        need(set(value) == {'epoch', 'id', 'op', 'kind', 'address', 'milliseconds'},
             'mail_public_lease_shape')
        return op, lease(value['kind'], value['address'], value['milliseconds'])
    if op == 'arm':
        need(set(value) == {'epoch', 'id', 'op', 'serial'} and type(value['serial']) is int and
             0 <= value['serial'] < 8, 'mail_public_arm_shape')
        group = '/system.slice/'+identity(ids['job'], epoch, ids['release'], value['serial'])['probe']
        return op, group
    need(set(value) == {'epoch', 'id', 'op'} and op in {'revoke', 'stop', 'delete_one'},
         'mail_public_guard_control_shape')
    if op == 'delete_one':
        return op, 'delete table inet '+TABLES[1]+'\n'
    return op, revoke() if op == 'revoke' else None


def revoke_role(job, epoch, release):
    ids, _ = root_config(job, epoch, release)
    marker = Path(ids['directory'])/'guard-created'
    flushed=0
    if marker.exists():
        # Leave default-drop tables in place until the Root coordinator has
        # independently proved every worker stopped. Removing them here would
        # race PID1's asynchronous BindsTo stop of the dependent transport.
        try:
            kernel.nft('-f', '-', text=revoke())
            return True
        except ValueError:
            # A deliberately removed table invalidates the whole transaction.
            # Still revoke any surviving table, without claiming full proof.
            pass
        for table in TABLES:
            present = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', table],
                capture_output=True, timeout=2)
            if present.returncode == 0:
                kernel.nft('-f', '-', text=''.join('flush set inet '+table+' '+name+'\n'
                    for name in ['tcp4','udp4']))
                flushed+=1
    return flushed==2


def keeper(job, epoch, release):
    ids, cfg = root_config(job, epoch, release)
    folder = Path(ids['directory'])
    # The NET_ADMIN-only guard cannot inspect PID1's namespace link. The Root
    # coordinator records its host namespace before joining the private one.
    host_ns = cfg['host_namespace_inode']
    need(os.stat('/proc/self/ns/net').st_ino==cfg['namespace_inode'] and
         (cfg['namespace_inode'] == host_ns) == (cfg['mode'] == 'public'),
         'mail_public_exact_namespace')
    fd = os.open(folder/'guard-created', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    kernel.nft('-f', '-', text=rules(None, cfg['interface'], cfg['source_addresses']))
    expected = guard_identity(); began = time.monotonic_ns(); sequence = 0; armed = None; binding = None
    selected = selectors.DefaultSelector(); selected.register(0, selectors.EVENT_READ)
    stopped = []; signal.signal(signal.SIGTERM, lambda *_: stopped.append('external_stop'))
    kernel.emit({'ready':True, 'role':'keeper', 'witness':kernel.status(), 'filter_sha256':expected})
    reason = 'unknown';check_error = None
    try:
        while time.monotonic_ns()-began < 8*10**9:
            if stopped: reason = stopped[0]; break
            try:observed=guard_identity(binding,expected=expected)
            except ValueError as error:
                code=str(error)
                check_error=code if code in {'mail_public_guard_missing','mail_public_unarmed_cgroup_selector',
                    'mail_public_cgroup_replaced','mail_public_cgroup_path_not_live','mail_public_cgroup_id_changed',
                    'mail_public_cgroup_expression','mail_public_cgroup_selector_count',
                    'mail_public_guard_snapshot_changed'}else 'guard_snapshot_unavailable'
                reason='guard_changed';break
            if observed != expected: reason = 'guard_changed';check_error = 'guard_digest_changed';break
            if not selected.select(.08): continue
            raw = sys.stdin.buffer.readline(4097)
            if not raw: reason = 'controller_lost'; break
            value = kernel.decode(raw)
            op, script = keeper_action(value, epoch, sequence, ids); sequence += 1
            if op == 'arm':
                need(armed is None or kernel.unit_properties(armed.rsplit('/',1)[1])['MainPID'] == '0',
                     'mail_public_guard_previous_worker_live')
                props = kernel.unit_properties(script.rsplit('/', 1)[1])
                need(props['ActiveState'] == 'active' and int(props['MainPID']) > 1 and
                     props['ControlGroup'] == script, 'mail_public_arm_live_cgroup')
                armed = script
                binding = (armed, os.stat('/sys/fs/cgroup'+armed).st_ino)
                script = ''.join('delete table inet '+v+'\n' for v in TABLES)+rules(
                    armed, cfg['interface'], cfg['source_addresses'])
            if op == 'lease': need(armed is not None, 'mail_public_lease_before_arm')
            if script is not None: kernel.nft('-f', '-', text=script)
            if op == 'arm': expected = guard_identity(binding)
            kernel.emit({'accepted':True, 'id':value['id'], 'op':op})
            if op == 'stop': reason = 'requested_stop'; break
        else: reason = 'deadline'
    finally:
        selected.close()
        (folder/'owner-result.json').write_bytes(canonical({'schema':'paw-mail-network-stop-v1',
            'epoch':epoch, 'reason':reason, 'namespace_inode':os.stat('/proc/self/ns/net').st_ino,
            'elapsed_ns':time.monotonic_ns()-began, 'check_error':check_error}))
        if revoke_role(job,epoch,release) is True:
            fd=os.open(folder/'revoked-complete',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            os.close(fd)


def private_role(job, epoch, release, role):
    need(os.geteuid() == 0 and HERE == Path('/opt/paw-code/mail_browser_public.py'),
         'mail_public_private_root_bootstrap')
    ids = identity(job, epoch, release)
    cfg = kernel.private_json(Path('/etc/paw-mail-network.json'))
    need(cfg['job'] == job and cfg['epoch'] == epoch and cfg['release'] == release and
         cfg['mode'] in {'owned-raw', 'owned-browser', 'public'}, 'mail_public_private_binding')
    if role=='probe':
        need(type(cfg.get('namespace_inode')) is int and
             os.stat('/proc/self/ns/net').st_ino==cfg['namespace_inode'],
             'mail_public_transport_namespace_changed')
    return ids, cfg


def fixture_main(job, epoch, release):
    _, cfg = private_role(job, epoch, release, 'fixture')
    need(cfg['mode'] != 'public' and sorted(os.listdir('/sys/class/net')) == ['lo'],
         'mail_public_fixture_private_only')
    # Parent sets the two fixed loopback aliases in this private namespace.
    # No capability or socket work is added to the fixture credential bootstrap.
    kernel.emit({'ready':True, 'phase':'namespace-bootstrap', 'witness':kernel.status()})
    need(kernel.decode(sys.stdin.buffer.readline(4097)) == {'op':'continue'},
         'mail_public_fixture_bootstrap_control')
    if cfg['mode'] == 'owned-raw': kernel.fixture(job, epoch, release)
    else:
        if __package__: from . import browser_owned_protocol as protocol
        else: import browser_owned_protocol as protocol
        protocol.fixture_main(job, epoch, release)


def drop_public():
    """Fixed identity drop for the transport's explicitly host-net namespace."""
    need(os.getresuid() == (0,0,0) and os.getresgid() == (0,0,0), 'mail_public_credential_bootstrap')
    before = kernel.status()
    need(before['nnp'] == '1' and before['seccomp'] == '2' and set(before['groups']) <= {0} and
         int(before['cap_eff'],16) == (1 << 6 | 1 << 7), 'mail_public_bootstrap_confinement')
    os.setgroups([]); os.setresgid(UID, UID, UID); os.setresuid(UID, UID, UID); kernel.capabilities(0)
    witness = kernel.status()
    need(os.getresuid() == (UID,)*3 and os.getresgid() == (UID,)*3 and not os.getgroups() and
         all(int(witness[k],16) == 0 for k in ['cap_eff', 'cap_prm', 'cap_inh', 'cap_amb']),
         'mail_public_irreversible_identity')
    return witness


def dns_bytes(host, ident, deadline_ns):
    need(type(deadline_ns) is int and deadline_ns > time.monotonic_ns(), 'mail_public_dns_deadline')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(min(1, (deadline_ns-time.monotonic_ns())/10**9))
        stream.connect(dns.RESOLVER); stream.send(dns.question(host, ident)); raw = stream.recv(4097)
    need(time.monotonic_ns() < deadline_ns, 'mail_public_dns_expired')
    return raw


def probe_main(job, epoch, release, form):
    _, cfg = private_role(job, epoch, release, 'probe')
    need(form in {'wire','raw'} and (form != 'raw' or cfg['mode'] == 'owned-raw'),
         'mail_public_probe_form')
    if form == 'raw':
        kernel.probe(job, epoch, release); return
    witness = drop_public()
    kernel.emit({'ready':True, 'role':'probe', 'witness':witness})
    session = PublicTransport(epoch, time.monotonic_ns()+8*10**9, dns_bytes, mediator.transport_response)
    decoder = wire.Decoder(epoch, body_budget=0); written = 0
    while not session.closed:
        raw = os.read(0,32768)
        if not raw: decoder.eof(); return
        for header, body in decoder.feed(raw):
            fields, response = session.dispatch(header['nonce'], header['sequence'], header['kind'], header['fields'], body)
            encoded = wire.frame(epoch, header['sequence'], 'reply', fields, response)
            written += len(encoded); need(written <= wire.WIRE_MAX, 'mail_public_wire_budget')
            view = memoryview(encoded)
            while view:
                count = os.write(1,view); need(count > 0,'mail_public_pipe_closed'); view = view[count:]


def prepare_network(job, epoch, release, mode, uplink):
    ids = identity(job, epoch, release); folder = Path(ids['directory'])
    need(mode in {'public','owned-browser','owned-raw'}, 'mail_public_finite_mode')
    folder.parent.mkdir(mode=0o700, exist_ok=True)
    from benign_guest_validation import process_identity
    cfg = {'schema':'paw-mail-network-v1', 'job':job, 'epoch':epoch, 'release':release,
           'mode':mode, 'interface':uplink['interface'] if mode == 'public' else 'lo',
           'source_addresses':[uplink['host_ipv4']] if mode == 'public' else ['9.9.9.9','93.184.216.34'],
           'controller_pid':os.getpid(), 'controller_identity':process_identity(os.getpid())}
    cfg['host_namespace_inode']=os.stat('/proc/self/ns/net').st_ino
    cfg['namespace_inode']=cfg['host_namespace_inode'] if mode=='public' else None
    # Reuse the existing bounded private root/config construction, never bind a
    # workspace file or real email into a privileged process or the guest.
    kernel.prepare_case(folder, job, epoch, release)
    _prepare_keeper_root(folder,release)
    (folder/'public.json').write_bytes(canonical(cfg)); (folder/'public.json').chmod(0o600)
    (folder/'revoke.nft').write_text(revoke());(folder/'revoke.nft').chmod(0o444)
    for name in PROGRAMS:
        source = HERE.with_name(name); info = source.stat()
        need(info.st_uid == 0 and not info.st_mode & 0o222 and stat.S_ISREG(info.st_mode) and
             info.st_size <= 128*1024, 'mail_public_immutable_program')
        target = folder/'code'/name
        if target.exists(): need(target.read_bytes() == source.read_bytes(), 'mail_public_source_changed')
        else: target.write_bytes(source.read_bytes()); target.chmod(0o444)
    for role in ['probe','fixture']:
        target = folder/(role+'-root')/'etc/paw-mail-network.json'
        target.write_bytes(canonical(cfg)); target.chmod(0o444)
    trust = folder/'probe-root/etc/ssl/certs'; trust.mkdir(mode=0o755, parents=True)
    if mode == 'public':
        from .mail_browser_native import protected
        ca = protected(Path(mediator.TRUST_FILE), 2*1024**2, mode=0o644)
    elif mode == 'owned-browser':
        cert=folder/'owned-cert.pem'; key=folder/'owned-key.pem'
        result = subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=paw-owned.invalid','-addext','subjectAltName=DNS:paw-owned.invalid',
            '-keyout',str(key),'-out',str(cert)], capture_output=True, timeout=5)
        need(result.returncode == 0 and len(result.stdout)+len(result.stderr) <= 8192,
             'mail_public_owned_certificate_generation')
        for source,name in [(cert,'paw-owned-cert.pem'),(key,'paw-owned-key.pem')]:
            raw=source.read_bytes(); need(0 < len(raw) <= 16384,'mail_public_owned_certificate_budget')
            target=folder/'fixture-root/etc'/name;target.write_bytes(raw);target.chmod(0o444)
        ca=cert.read_bytes()
    else: ca=b'No TLS in the raw owned kernel matrix\n'
    (trust/'ca-certificates.crt').write_bytes(ca); (trust/'ca-certificates.crt').chmod(0o444)
    return folder, sha(ca)


class NetworkPreparation:
    """Advance only the fixed roles while continuing to poll the same VM."""
    def __init__(self, job, epoch, release, mode, actors, *, protocol=True):
        self.job=job; self.epoch=epoch; self.release=release; self.mode=mode; self.actors=actors
        self.protocol=protocol; self.owner=None; self.server=None; self.worker=None
        self.inode=None; self.server_live=mode == 'public'; self.worker_live=False; self.ready=False
        self.fixture_configured=False
        if mode != 'public':
            self.server=PublicActor(job,epoch,release,'fixture',registry=actors,defer_ready=True)
        else: self._owner(None)
    def _owner(self, fixture_pid):
        need((fixture_pid is None)==(self.mode=='public'), 'mail_public_bootstrap_namespace_source')
        self.owner=PublicActor(self.job,self.epoch,self.release,'keeper',fixture_pid,
                               registry=self.actors,defer_ready=True)
    def _start_owned_worker(self):
        if self.mode=='public' or self.worker is not None:return
        # Popen is not PID1 registration. Wait for the exact Type=exec unit to
        # be active before constructing a dependent worker, without waiting for
        # the guard's later Python/nft readiness. Initial BPF stays deny-all.
        props=kernel.unit_properties(self.owner.unit)
        if props['ActiveState']!='active':return
        ids=identity(self.job,self.epoch,self.release);pid=int(props['MainPID'])
        cfg=kernel.private_json(Path(ids['directory'])/'public.json')
        need(pid>1 and props['ControlGroup']=='/system.slice/'+ids['keeper'] and
             os.stat('/proc/'+str(pid)+'/ns/net').st_ino==cfg['namespace_inode'],
             'mail_public_owned_active_guard_namespace')
        self.worker=PublicActor(self.job,self.epoch,self.release,'probe',pid,
            registry=self.actors,protocol=self.protocol,defer_ready=True)
    def poll(self):
        if self.ready:return True
        if self.server is not None and not self.fixture_configured:
            if not self.server.poll_ready():return False
            need(self.server.ready.get('phase') == 'namespace-bootstrap','mail_public_fixture_bootstrap')
            pid=self.server.pid
            need(kernel.unit_properties(self.server.unit)['MainPID'] == str(pid) and
                 os.stat('/proc/'+str(pid)+'/ns/net').st_ino != os.stat('/proc/self/ns/net').st_ino,
                 'mail_public_owned_namespace')
            namespace=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
            process=None
            try:
                process=os.pidfd_open(pid)
                inode=os.fstat(namespace).st_ino
                need(inode==self.server.ready['witness']['namespace_inode'] and
                     inode!=os.stat('/proc/self/ns/net').st_ino and
                     kernel.unit_properties(self.server.unit)['MainPID']==str(pid),
                     'mail_public_fixture_namespace_pin')
                with selectors.DefaultSelector() as selected:
                    selected.register(process,selectors.EVENT_READ)
                    need(not selected.select(0),'mail_public_fixture_died_before_namespace_setup')
                for args in [['link','set','lo','up'],['address','add','9.9.9.9/32','dev','lo'],
                             ['address','add','93.184.216.34/32','dev','lo']]:
                    subprocess.run(['/usr/bin/nsenter','--net=/proc/self/fd/'+str(namespace),
                        '/usr/sbin/ip',*args],pass_fds=(namespace,),check=True,capture_output=True,timeout=2)
                # Later PID1 namespace-path lookups must match this protected
                # inode, even if a fixture/guardian PID dies or is reused.
                ids=identity(self.job,self.epoch,self.release);folder=Path(ids['directory'])
                cfg=kernel.private_json(folder/'public.json');cfg['namespace_inode']=inode
                (folder/'public.json').write_bytes(canonical(cfg))
                for role in ['probe','fixture']:
                    target=folder/(role+'-root')/'etc/paw-mail-network.json'
                    target.write_bytes(canonical(cfg));target.chmod(0o444)
            finally:
                if process is not None:os.close(process)
                os.close(namespace)
            # Second readiness is emitted only after the original fixture's
            # UID/capability drop and socket construction. Same PID1 lifetime.
            self.server.ready=None; self.server._ready_received_at=None
            self.server._ready_deadline=time.monotonic()+2
            self.server.send({'op':'continue'})
            self.fixture_configured=True; self._owner(pid)
        if self.inode is None:
            self._start_owned_worker()
            if not self.owner.poll_ready():return False
            self.inode=kernel.live_role(self.owner,'keeper')
            need((self.inode == os.stat('/proc/self/ns/net').st_ino) == (self.mode == 'public'),
                 'mail_public_observed_namespace')
            if self.worker is None:
                # Public mode has no private fixture and retains its original
                # guard-ready-then-worker sequence and namespace source.
                self.worker=PublicActor(self.job,self.epoch,self.release,'probe',self.owner.pid,
                    registry=self.actors,protocol=self.protocol,defer_ready=True)
        if not self.server_live and self.server.poll_ready():
            kernel.live_role(self.server,'fixture',self.inode);self.server_live=True
        if not self.worker_live and self.worker.poll_ready():
            kernel.live_role(self.worker,'probe',self.inode);self.worker_live=True
        self.ready=self.server_live and self.worker_live
        return self.ready


class Mediation:
    def __init__(self, owner, worker, nonce, began, seed, budget, slot, out, uplink=None, approval=None):
        from . import browser_owned_broker as existing
        self._existing=existing
        self.owner=owner;self.worker=worker;self.nonce=nonce;self.control_sequence=0;self.sequence=0
        self.ledger=mediator.BrowserRequestLedger(seed,nonce,began,allow_dynamic_public_hosts=True)
        self.budget=budget;self.slot=slot;self.out=out;self.uplink=uplink;self.approval=approval
        self.observations=[];self.bodies=[]
        self.control('arm',serial=0)
    def control(self, op, **fields):
        self._existing.Mediation.control(self,op,**fields)
    def transaction(self, kind, fields):
        return self._existing.Mediation.transaction(self,kind,fields)
    def allow(self, kind, address, milliseconds, *, plan=None):
        if self.approval is not None:
            from . import mail_browser_native as native
            need(native.scope(self.approval['release_sha'],self.approval['batch_id'])==self.approval,
                 'mail_public_lease_scope_changed')
        if self.uplink is not None:
            from prepare_uplink import current_uplink
            need(canonical(current_uplink()) == canonical(self.uplink),'mail_public_uplink_changed')
        # Lists are reset on every operation, not accumulated. Both BPF and
        # duplicate expiring packet guards must admit the exact numeric tuple.
        subprocess.run(['/usr/bin/systemctl','set-property','--runtime',self.worker.unit,
            'IPAddressAllow=', 'IPAddressAllow='+address+'/32'], check=True,capture_output=True,timeout=2)
        if plan is not None:
            # BPF installation has its own bounded latency. Start the existing
            # two-second nft commit reserve only after that operation, so a
            # relative timeout can never extend the absolute Root lease.
            milliseconds=self._existing.kernel_lease_milliseconds(plan,time.monotonic_ns())
        self.control('lease',kind=kind,address=address,milliseconds=milliseconds)
    def resolver(self, host, deadline_ns):
        import secrets
        self.budget.hostname(host)
        issued=time.monotonic_ns();self.allow('dns',dns.RESOLVER[0],1000)
        ident=secrets.randbelow(65536)
        fields,raw=self.transaction('dns',{'host':host,'ident':ident,
            'deadline_ns':min(deadline_ns,time.monotonic_ns()+10**9)})
        need(set(fields) == {'request_sequence','operation','host','ident','received_ns'} and
             fields['host'] == host and type(fields['ident']) is int and fields['ident'] == ident and
             type(fields['received_ns']) is int and issued <= fields['received_ns'] <= time.monotonic_ns() and
             time.monotonic_ns() < deadline_ns, 'mail_public_actual_dns_binding')
        self.control('revoke')
        name='dns-'+str(len(self.observations)).zfill(2)+'.bin'
        self.write(name,raw)
        facts=dns.parse_answer(raw,host,ident)
        self.observations.append({'operation':'dns','host':host,'packet':name,'packet_sha256':sha(raw),**facts})
        return {**facts,'observed_ns':issued}
    def write(self, name, raw):
        fd=os.open(self.out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        self.bodies.append({'name':name,'bytes':len(raw),'sha256':sha(raw)})
    def response(self, request):
        # Burn refused HTTP attempts too. The ledger validates the exact first
        # seed/method/envelope before invoking our trusted resolver callback.
        self.budget.request(self.slot)
        before=len(self.observations); reserved=False
        try:
            plan=self.ledger.admit_resolved(request,self.resolver)
            plan=self.ledger.lease(plan,time.monotonic_ns())
            remaining=self.budget.reserve(self.slot);reserved=True
            ms=self._existing.kernel_lease_milliseconds(plan,time.monotonic_ns())
            self.allow(plan['scheme'],plan['peer_ipv4'],ms,plan=plan)
            fields,body=self.transaction('http',{'plan':plan,'remaining_bytes':remaining})
            need(set(fields) == {'request_sequence','operation','transport'} and
                 type(fields['transport']) is dict,'mail_public_transport_response')
            facts=fields['transport']
            need(set(facts) == {'http_status','headers','peer_ipv4','tls_verified_by_broker','body_bytes','body_sha256'} and
                 type(facts['body_bytes']) is int and facts['body_bytes'] == len(body) and
                 facts['body_sha256'] == sha(body),'mail_public_body_binding')
            self.budget.complete(self.slot,len(body));reserved=False
            metadata=self.ledger.complete(plan,facts['http_status'],facts['headers'],body,
                facts['peer_ipv4'],facts['tls_verified_by_broker'],time.monotonic_ns())
            self.control('revoke')
            name='body-'+str(plan['slot']).zfill(2)+'.bin';self.write(name,body)
            self.observations.append({'operation':'http','request':dict(request),'url_sha256':plan['url_sha256'],
                'status':metadata['http_status'],'body_file':name,'body_bytes':len(body),'body_sha256':sha(body),
                'peer_ipv4':facts['peer_ipv4'],'tls_verified_by_broker':facts['tls_verified_by_broker'],
                'response_headers':metadata['headers'],'tls_fingerprint_source':'broker, not browser'})
            return {k:metadata[k] for k in ['status','slot','http_status','headers','body_bytes','body_sha256']},body
        except (OSError,ValueError,KeyError,TypeError) as error:
            if reserved:self.budget.uncertain(self.slot)
            self.observations.append({'operation':'refused_or_unavailable','request':dict(request),
                'reason':type(error).__name__+':'+str(error)[:256],'after_observation':before})
            # No retry/reconnection or new authority after unknown I/O. A
            # bounded diagnostic may later publish only after independent stop.
            self.ledger.closed=True
            raise
    def stop(self):
        for actor in [self.owner,self.worker]:
            state=kernel.unit_properties(actor.unit)
            need(state['ActiveState']=='active' and state['MainPID']==str(actor.pid),
                 'mail_public_unexpected_network_exit')
        fields,body=self.transaction('stop',{})
        need(fields == {'request_sequence':self.sequence-1,'operation':'stop','stopped':True} and
             body==b'' and self.worker.process.wait(timeout=2)==0,'mail_public_transport_stop')
        self.control('stop');need(self.owner.process.wait(timeout=2)==0,'mail_public_guard_stop')
        self.ledger.close()


def guest_main():
    import tty
    need(os.geteuid() == 0 and HERE == Path('/usr/local/lib/paw-s14/mail_browser_public.py') and
         Path('/etc/paw-mail-browser.json').is_file(), 'mail_public_trusted_guest_only')
    levels=Path('/proc/sys/kernel/printk').read_text().split()
    need(len(levels)==4 and all(v.isdecimal() for v in levels),'mail_public_console_levels')
    Path('/proc/sys/kernel/printk').write_text('0 '+' '.join(levels[1:])+'\n')
    os.chmod('/dev/ttyS0',0o600);tty.setraw(0)
    def emit(value):
        raw=cdp.canonical(value);need(len(raw)<60000,'mail_public_console_budget')
        print('PAW14 '+raw.decode('ascii'),flush=True)
    emit({'ready':True,'network_interfaces':['lo']})
    captured.serve(PublicRuntime(),sys.stdin.buffer,emit)


def require_idle():
    from vm_runtime_revalidation import snapshot
    snapshot(); kernel.vacant_ids()
    ruleset=json.loads(kernel.nft('-j','list','ruleset'))
    need(not any(row.get('table',{}).get('name') in TABLES for row in ruleset['nftables']),
         'mail_public_stale_guard')


def verify_baseline(job, release, current):
    from .mail_browser_native import protected
    from . import browser_owned_broker as existing, browser_bridge
    need(type(job) is str and re.fullmatch('[0-9a-f]{32}',job),'mail_public_baseline_job')
    raw=protected(Path('/var/lib/paw-vm-exports')/('owned-broker-'+job)/'attestation.json',
                  1024**2,mode=0o440)
    value=cdp.strict_json(raw)
    need(value.get('schema')=='paw-owned-brokered-browser-v1' and value.get('result')=='PASS' and
         value.get('release_sha')==release and value.get('job')==job and
         value.get('context_sha256')==sha(browser_bridge.canonical(current['browser'])) and
         value.get('writers_stopped') is True and value.get('host_restored') is True and
         type(value.get('stop_ns')) is int and 0 <= value['stop_ns'] < 12*10**9 and
         value.get('kernel_component',{}).get('result')=='PASS' and
         value.get('guest',{}).get('status')=='completed' and
         all(value.get('guest',{}).get('sandbox',{}).get(k) is True for k in [
            'all_uids_nonroot','renderer_nnp','renderer_seccomp','renderer_pid_namespace','renderer_seen']) and
         value.get('programs')=={n:sha(HERE.with_name(n).read_bytes()) for n in existing.PROGRAMS},
         'mail_public_current_owned_baseline_required')
    return sha(raw)


def remove_tables(job, epoch, release):
    ids,cfg=root_config(job,epoch,release)
    if cfg['mode'] != 'public':return
    need((Path(ids['directory'])/'guard-created').is_file(),'mail_public_guard_owner_marker')
    # No response-capable process may survive removing the UID packet guard.
    kernel.vacant_ids()
    for serial in range(8):
        props=kernel.unit_properties(identity(job,epoch,release,serial)['probe'])
        need(props['MainPID']=='0' and props['ActiveState'] in {'inactive','failed'},
             'mail_public_worker_alive_before_guard_removal')
    for table in TABLES:
        present=subprocess.run(['/usr/sbin/nft','list','table','inet',table],capture_output=True,timeout=2)
        if present.returncode==0:kernel.nft('delete','table','inet',table)


def run_capture(approval, binding, request, budget):
    """One serial VM; no direct host fetch, auxiliary public probe or retry."""
    from . import browser_owned_broker as existing, mail_browser_native as native
    from . import browser_broker_console as console
    import browser_authorization as auth
    from browser_vm import BrowserVM,BROWSER_BASE,LIMITS
    from browser_offline_adapter import input_media,available_memory
    from benign_guest_validation import BASE,digest
    from vm_runtime_revalidation import network_state
    job=binding['job'];epoch=binding['epoch'];release=approval['release_sha'];slot=binding['slot']
    mode='owned-browser' if slot=='owned' else 'public';budget_slot=0 if slot=='owned' else slot
    need(native.scope(release,approval['batch_id'])==approval,'mail_public_live_batch_changed')
    context=auth.capture();auth.validate_context(context)
    need(context==approval['context']['browser'],'mail_public_browser_context_changed')
    need(available_memory()>=2*1024**3,'mail_public_host_memory')
    actors=[];gate=None;vm=None;mediation=None;preparation=None;network_closed=False
    record={'schema':'paw-real-mail-browser-capture-v1','status':'failed','job':job,
        'batch_id':approval['batch_id'],'slot':slot,'release_sha':release,'nonce':epoch,
        'source_sha256':request['source_sha256'],'request_sha256':sha(canonical(request)),
        'scope':'No-NIC main-page browser and filtered broker observations; broker TLS, no browser fingerprint',
        'capture_artifacts':[],'admitted_at':int(time.time()),'mode':mode}
    with auth.fs.execution_lock():
        require_idle()
        folder,ca_sha=prepare_network(job,epoch,release,mode,approval['context']['uplink'])
        if mode=='public':
            need(ca_sha==approval['context']['ca_sha256'],'mail_public_prepared_CA_changed')
        out=Path('/var/lib/paw-s14/control')/('mail-capture-'+epoch)
        media=input_media(b'Only the protected selected URL is seeded; original email is never executed',epoch)
        gate=BrowserVM(argparse.Namespace(output=out),phase='mail_public',media=media,
            seed_config={'kind':'mail-public-browser-v1','nonce':epoch,'url':request['url']})
        gate.canary=out/'host-owned-canary.bin';gate.canary.write_bytes(os.urandom(32));gate.canary.chmod(0o600)
        canary=digest(gate.canary);before=gate.snapshot_host();network=network_state()
        record.update(context_sha256=sha(canonical(context)),image_sha256=context['image_sha256'],
                      chrome_binary_sha256=context['chrome_binary_sha256'],transport_ca_sha256=ca_sha)
        try:
            vm=gate.start('selected-mail-browser');record['vm_uuid']=vm['node']['uuid']
            inspected=vm['channel'].call('inspect',seconds=8)
            need(inspected['network_interfaces']==['lo'] and inspected['chrome_version']==context['chrome_version'] and
                 inspected['chrome_binary_sha256']==context['chrome_binary_sha256'],'mail_public_exact_guest')
            admitted=vm['channel'].call('start',seconds=8)
            need(admitted.get('started') is True,'mail_public_guest_start_ack')
            began=time.monotonic_ns();record['guest_started_ns']=began;end=time.monotonic()+18
            while time.monotonic()<end:
                value=vm['channel'].call('poll',seconds=5);request_frame=value.get('network_request')
                need(not network_closed or request_frame is None,'mail_public_network_after_snapshot')
                if value.get('done') is True:record['guest']=value;break
                if preparation is None and (request_frame is not None or time.monotonic_ns()-began>=7*10**9):
                    preparation=NetworkPreparation(job,epoch,release,mode,actors)
                if preparation is not None and mediation is None and preparation.poll():
                    mediation=Mediation(preparation.owner,preparation.worker,epoch,began,request['url'],
                        budget,budget_slot,out,approval['context']['uplink'] if mode=='public' else None,approval)
                if value.get('network_quiescent') is True and not network_closed:
                    need(mediation is not None and request_frame is None,'mail_public_quiescent_pending')
                    mediation.stop();network_closed=True;record['network_stopped_before_capture']=True
                if mediation is not None and request_frame is not None:
                    metadata,body=mediation.response(request_frame)
                    existing.send_response(vm['channel'],epoch,request_frame['seq'],metadata,body)
                time.sleep(.03)
            else:raise ValueError('mail_public_poll_deadline')
            need(value.get('status')=='completed' and value.get('writers_stopped') is True and
                 value.get('network_interfaces')==['lo'] and network_closed and
                 type(value.get('sandbox')) is dict and set(value['sandbox'])=={
                    'all_uids_nonroot','renderer_nnp','renderer_seccomp','renderer_pid_namespace','renderer_seen'} and
                 all(v is True for v in value['sandbox'].values()),'mail_public_guest_incomplete')
            record['capture_transfer_started']=True
            existing.collect_capture(vm['channel'],epoch,value,out,record['capture_artifacts'])
            if mode=='owned-browser':
                dom=(out/'capture-dom.html').read_bytes()
                need(('PAW-OWNED-'+epoch).encode() in dom and b'data-owned="done"' in dom and
                     len([v for v in mediation.observations if v['operation']=='http'])>=2,
                     'mail_public_owned_JS_or_resource_missing')
            record['status']='completed'
        except Exception as error:
            record['error']=type(error).__name__+':'+str(error)[:512]
        finally:
            failures=[];stopped=time.monotonic_ns()
            try:
                kernel.cleanup_actors(actors);kernel.vacant_ids()
                if mode=='public' and (folder/'guard-created').exists():remove_tables(job,epoch,release)
            except Exception as error:failures.append('network:'+type(error).__name__+':'+str(error)[:256])
            try:
                if vm is not None and not record.get('capture_transfer_started'):
                    try:
                        terminal=record.get('guest')
                        if terminal is None:terminal=vm['channel'].call('cancel',seconds=4)
                        record['guest']=terminal
                        if terminal.get('writers_stopped') is True:
                            record['capture_transfer_started']=True
                            existing.collect_capture(vm['channel'],epoch,terminal,out,record['capture_artifacts'])
                    except Exception as error:record['capture_error']=type(error).__name__+':'+str(error)[:256]
                if gate.active_vm is not None:gate.stop(gate.active_vm)
                need(vm is not None and Path(vm['owner_result_path']).parent==gate.output,'mail_public_owner_result_path')
                with auth.fs.root_directory(gate.output) as fd:
                    owner_result=json.loads(auth.fs.read(fd,Path(vm['owner_result_path']).name,65536))
                need(owner_result.get('reason')=='requested_stop' and owner_result.get('connection_closed') is True and
                     owner_result.get('vm_uuid')==vm['node']['uuid'],'mail_public_external_owner_disposition')
                record['owner_disposition']=owner_result
                record['stop_ns']=time.monotonic_ns()-stopped
                need(0<=record['stop_ns']<12*10**9 and not gate.connection.listAllDomains(0) and
                     before==gate.snapshot_host() and network==network_state() and
                     digest(BASE)==auth.fs.IMAGE_SHA256 and digest(BROWSER_BASE)==context['image_sha256'] and
                     digest(gate.canary)==canary and auth.capture()==context,'mail_public_unknown_stop_or_restore')
                need(native.context(release)==approval['context'],'mail_public_terminal_context_changed')
                record.update(writers_stopped=True,host_restored=True)
            except Exception as error:failures.append('VM:'+type(error).__name__+':'+str(error)[:256])
            gate.connection.close()
            if failures:record.update(status='failed',cleanup_errors=failures)
            record['completed_at']=int(time.time());record['budget']=budget.facts()
            if mediation is not None:
                record['observations']=mediation.observations;record['opaque_resources']=mediation.bodies
                record['ledger']=mediation.ledger.close()
            record['roles']=[v.observation for v in actors if hasattr(v,'observation')]
            record['capture_missing_coverage']=[n for n in ['dom.html','screenshot.png']
                if n not in {v['name'] for v in record['capture_artifacts']}]
            record['qemu_limits']=dict(LIMITS)
            (out/'results.json').write_bytes(canonical(record))
        need(record.get('writers_stopped') is True and record.get('host_restored') is True and
             not record.get('cleanup_errors'),'mail_public_unknown_stop_no_publication')
        return publish_capture(approval,binding,request,record,out)


EXPORT_ROOT=Path('/var/lib/paw-vm-exports')
RECEIPT_MAX=32768


def slot_name(slot):
    need(slot=='owned' or type(slot) is int and 0<=slot<3,'mail_public_source_slot')
    return str(slot)


def artifact_cap(name):
    if name in {'dom.html','screenshot.png'}:return 256*1024
    if name=='network.json':return 1024**2
    if type(name) is str and re.fullmatch(r'dns-[0-9]{2}\.bin',name):return 4096
    if type(name) is str and re.fullmatch(r'body-[0-9]{2}\.bin',name):return CASE_BYTES
    raise ValueError('mail_public_artifact_name')


def validate_receipt(raw, request, batch, slot):
    from . import mail_browser_custody as custody, synthetic_bridge as shared
    slot_name(slot)
    need(type(batch) is str and re.fullmatch('[0-9a-f]{32}',batch),'mail_public_export_batch')
    value=shared._decode(raw,RECEIPT_MAX)
    need(raw==canonical(value) and type(value) is dict and set(value)=={
        'schema','profile','producer_kind','batch_id','slot','job','nonce','request_sha256',
        'source_sha256','snapshot_sha256','case_reference','status','runtime','artifacts'} and
        value['schema']=='paw-real-mail-browser-result-v1' and value['profile']==custody.PROFILE and
        value['producer_kind']=='local-root-native-single-batch' and value['batch_id']==batch and
        type(value['slot']) is type(slot) and value['slot']==slot and
        value['request_sha256']==sha(canonical(request)) and
        value['source_sha256']==request['source_sha256'] and value['snapshot_sha256']==request['snapshot_sha256'] and
        value['case_reference']==request['case_reference'] and value['status'] in {'completed','failed'} and
        all(type(value[k]) is str and re.fullmatch('[0-9a-f]{32}',value[k]) for k in ['job','nonce']),
        'mail_public_receipt_binding')
    r=value['runtime'];hashes={'context_sha256','image_sha256','chrome_binary_sha256','raw_attestation_sha256'}
    need(type(r) is dict and set(r)==hashes|{'release_sha','vm_uuid','admitted_at','completed_at',
        'stop_ns','writers_stopped','host_restored','sandbox','network_stopped_before_capture','mode'} and
        all(type(r[k]) is str and re.fullmatch('[0-9a-f]{64}',r[k]) for k in hashes) and
        type(r['release_sha']) is str and re.fullmatch('[0-9a-f]{40}',r['release_sha']) and
        type(r['vm_uuid']) is str and str(uuid.UUID(r['vm_uuid']))==r['vm_uuid'] and
        type(r['admitted_at']) is int and type(r['completed_at']) is int and
        request['created_at']<=r['admitted_at']<request['expires_at'] and
        r['admitted_at']<=r['completed_at']<=time.time()+5 and
        type(r['stop_ns']) is int and 0<=r['stop_ns']<12*10**9 and
        r['writers_stopped'] is True and r['host_restored'] is True and
        type(r['network_stopped_before_capture']) is bool and
        r['mode']==('owned-browser' if slot=='owned' else 'public') and
        type(r['sandbox']) is dict and set(r['sandbox'])=={
            'all_uids_nonroot','renderer_nnp','renderer_seccomp','renderer_pid_namespace','renderer_seen'} and
        all(type(v) is bool for v in r['sandbox'].values()),'mail_public_receipt_runtime')
    if value['status']=='completed':
        need(all(r['sandbox'].values()) and r['network_stopped_before_capture'] is True,
             'mail_public_completed_runtime')
    need(type(value['artifacts']) is list and len(value['artifacts'])<=2*CASE_REQUESTS+3,
         'mail_public_artifact_count')
    names=set();body_bytes=0;dns_bytes=0
    for item in value['artifacts']:
        need(type(item) is dict and set(item)=={'name','bytes','sha256'} and
             type(item['name']) is str and item['name'] not in names and
             type(item['bytes']) is int and 0<=item['bytes']<=artifact_cap(item['name']) and
             type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}',item['sha256']),
             'mail_public_artifact_inventory')
        names.add(item['name'])
        if item['name'].startswith('body-'):body_bytes+=item['bytes']
        elif item['name'].startswith('dns-'):dns_bytes+=item['bytes']
        else:need(item['bytes']>0,'mail_public_empty_capture')
    need(body_bytes<=CASE_BYTES and dns_bytes<=CASE_REQUESTS*4096,'mail_public_export_resource_budget')
    need('network.json' in names,'mail_public_network_evidence_missing')
    if value['status']=='completed':need({'dom.html','screenshot.png'}<=names,'mail_public_complete_capture_missing')
    return value


def publish_capture(approval, binding, request, record, out):
    from . import mail_browser_native as native
    from reader_export import publish_reader_tree
    need(record.get('writers_stopped') is True and record.get('host_restored') is True and
         not record.get('cleanup_errors'),'mail_public_unknown_stop_no_export')
    bodies={'network.json':canonical(record)}
    for item in record['capture_artifacts']:
        raw=(out/('capture-'+item['name'])).read_bytes()
        need(len(raw)==item['bytes'] and sha(raw)==item['sha256'],'mail_public_capture_changed')
        bodies[item['name']]=raw
    for item in record.get('opaque_resources',[]):
        raw=(out/item['name']).read_bytes()
        need(len(raw)==item['bytes'] and sha(raw)==item['sha256'],'mail_public_resource_changed')
        bodies[item['name']]=raw
    receipt={'schema':'paw-real-mail-browser-result-v1','profile':request['profile'],
        'producer_kind':'local-root-native-single-batch','batch_id':approval['batch_id'],
        'slot':binding['slot'],'job':binding['job'],'nonce':binding['epoch'],
        'request_sha256':sha(canonical(request)),'source_sha256':request['source_sha256'],
        'snapshot_sha256':request['snapshot_sha256'],'case_reference':request['case_reference'],
        'status':record['status'],'runtime':{
            **{k:record[k] for k in ['release_sha','vm_uuid','admitted_at','completed_at','stop_ns',
                'writers_stopped','host_restored','mode','context_sha256','image_sha256','chrome_binary_sha256']},
            'raw_attestation_sha256':sha(bodies['network.json']),
            'network_stopped_before_capture':record.get('network_stopped_before_capture') is True,
            'sandbox':record.get('guest',{}).get('sandbox',{})},
        'artifacts':[{'name':name,'bytes':len(raw),'sha256':sha(raw)} for name,raw in sorted(bodies.items())]}
    receipt_raw=canonical(receipt);validate_receipt(receipt_raw,request,approval['batch_id'],binding['slot'])
    target=EXPORT_ROOT/('mail-public-'+approval['batch_id']+'-'+slot_name(binding['slot']))
    native._mkdir(target)
    for name,raw in {'request.json':canonical(request),'receipt.json':receipt_raw,**bodies}.items():
        # Per-artifact cap has already been checked. No DOM/response parsing by Root.
        fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    publish_reader_tree(target)
    return {'schema':'paw-mail-native-child-result-v1','kind':'capture','status':record['status'],
            'job':binding['job'],'epoch':binding['epoch'],'slot':binding['slot'],'batch_id':approval['batch_id'],
            'release_sha':approval['release_sha'],'receipt_sha256':sha(receipt_raw),'budget':record['budget'],
            'writers_stopped':True,'host_restored':True}


def sidecar_result(request, receipt):
    return canonical({'schema':'paw-real-mail-browser-sidecar-v1','status':'collected',
        'execution_status':receipt['status'],'case_reference':request['case_reference'],
        'request_sha256':sha(canonical(request)),'original_case_modified':False,
        'producer_trust':'local Root-protected native single-batch export; no remote attestation',
        'meaning':'Browser observations and custody only; no score, verdict, authenticity or attribution claim'})


def client_prepare(directory, url_index, output):
    from . import synthetic_bridge as shared
    return shared._offline(_client_prepare)(directory,url_index,output)


def _client_prepare(directory,url_index,output):
    from . import mail_browser_custody as custody, mail_browser_owned as owned, synthetic_bridge as shared
    case,ref=shared._case_reference(directory);dest=shared._destination(output,case)
    raw=custody.prepare(case,url_index)
    with owned._output(dest,case) as (fd,key):
        owned._write(fd,'request.json',raw,key,0o400)
        need(shared._case_reference(case)[1]==ref,'mail_public_parent_changed')
        owned._named_output(dest,fd,key)
    return {'status':'prepared','request':str(dest/'request.json'),'sha256':sha(raw),
            'execution_authorized':False,'scope':'Data only; native protected source/hash approval still required'}


def client_import(directory,batch,slot,output):
    from . import synthetic_bridge as shared
    return shared._offline(_client_import)(directory,batch,slot,output)


def _client_import(directory,batch,slot,output):
    import blake3
    from contextlib import contextmanager
    from . import mail_browser_custody as custody, mail_browser_owned as owned, synthetic_bridge as shared
    shared._linux();slot_name(slot)
    need(type(batch) is str and re.fullmatch('[0-9a-f]{32}',batch),'mail_public_export_batch')
    case,ref=shared._case_reference(directory);dest=shared._destination(output,case)
    path=EXPORT_ROOT/('mail-public-'+batch+'-'+slot_name(slot))
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            info=os.fstat(fd)
            need(info.st_uid==0 and not info.st_mode&0o022,'mail_public_untrusted_export')
        raw=shared._read_regular('request.json',custody.REQUEST_MAX,directory_fd=fd,root_owned=True)
        parsed=shared._decode(raw,custody.REQUEST_MAX)
        request=custody.validate(raw,lambda v:blake3.blake3(v).hexdigest(),now=parsed['created_at'])
        need(request['case_reference']==ref,'mail_public_wrong_parent')
        current=custody.prepare(case,request['url_index'])
        custody.require_selection(json.loads(current),custody.selection(request))
        receipt_raw=shared._read_regular('receipt.json',RECEIPT_MAX,directory_fd=fd,root_owned=True)
        receipt=validate_receipt(receipt_raw,request,batch,slot)
        need(set(os.listdir(fd))=={'request.json','receipt.json'}|{a['name'] for a in receipt['artifacts']},
             'mail_public_export_inventory')
        artifacts={}
        for item in receipt['artifacts']:
            body=shared._read_regular(item['name'],artifact_cap(item['name']),directory_fd=fd,root_owned=True)
            need(len(body)==item['bytes'] and sha(body)==item['sha256'],'mail_public_export_hash')
            artifacts[item['name']]=body
        need(sha(artifacts['network.json'])==receipt['runtime']['raw_attestation_sha256'],
             'mail_public_network_attestation_binding')
    finally:os.close(fd)
    contents={'request.json':raw,'receipt.json':receipt_raw,'result.json':sidecar_result(request,receipt),**artifacts}
    with owned._output(dest,case) as (fd,key):
        pending=owned._new_directory(fd,'pending',key)
        try:
            for name,body in contents.items():owned._write(pending,name,body,key)
            owned._seal_fd(pending,contents,key)
            need(shared._case_reference(case)[1]==ref,'mail_public_original_changed')
            owned._named_output(dest,fd,key);owned._publish(fd,pending);owned._named_output(dest,fd,key)
        finally:os.close(pending)
    return {'status':'collected','execution_status':receipt['status'],'result':str(dest/'result'),
            'batch_id':batch,'slot':slot,'case_unchanged':True,'scope':'Separate sealed observations; original score unchanged'}


@contextmanager
def _owned_preparation_budget(job):
    """Match the native coordinator inside the enrolled aggregate ceiling."""
    parent='paw-vm-owned-'+job+'.service';before=kernel.unit_properties(parent)
    expected={'ActiveState':'active','MainPID':str(os.getpid()),'MemoryMax':str(512*1024**2),
              'MemorySwapMax':'0','TasksMax':'64','CPUQuotaPerSecUSec':'1s'}
    need(all(before.get(k)==v for k,v in expected.items()),'mail_public_owned_parent_budget')
    def limit(memory,tasks,cpu):
        subprocess.run(['/usr/bin/systemctl','set-property','--runtime',parent,
            'MemoryMax='+memory,'TasksMax='+tasks,'CPUQuota='+cpu],check=True,capture_output=True,timeout=2)
    try:
        limit('192M','24','35%')
        yield
    finally:
        limit('512M','64','100%')
        after=kernel.unit_properties(parent)
        need(all(after.get(k)==v for k,v in expected.items()),'mail_public_owned_parent_not_restored')


def _cleanup_progress(folder):
    """Stopped diagnostic telemetry only; never an acceptance or authority gate."""
    result={}
    for name,size in [('revoked-complete',0),('stop-hook-entered',1)]:
        try:info=(folder/name).lstat()
        except FileNotFoundError:result[name]=False;continue
        result[name]=(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and
                      info.st_nlink==1 and not info.st_mode&0o077 and info.st_size==size)
    return result


def owned_preparation(job, release):
    """Fixed no-VM preparation probe, called only by the enrolled owned recipe.

    No native/public authority is constructed or consumed here. This probe
    always uses loopback aliases in a private namespace, with unchanged roles,
    observer deadlines and PID1 budgets; it opens no public tuple or browser.
    """
    need(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/mail_browser_public.py',
         'mail_public_owned_preparation_snapshot')
    epoch=uuid.uuid4().hex;identity(job,epoch,release)
    from vm_runtime_revalidation import snapshot,network_state
    import one_use_authorization as fs
    from reader_export import publish_reader_tree
    actors=[];prep=None;began=time.monotonic_ns()
    record={'schema':'paw-mail-owned-preparation-v1','result':'FAIL','job':job,'release_sha':release,
        'epoch':epoch,'vm_started':False,'real_samples_executed':0,'real_connections':0,
        'production_grants_enabled':False,'i08_installed':False,
        'scope':'Fixed private loopback preparation and two default-denied packets; no browser or public readiness',
        'programs':{name:sha(HERE.with_name(name).read_bytes()) for name in PROGRAMS}}
    with _owned_preparation_budget(job),fs.execution_lock():
        require_idle();before=snapshot();network=network_state()
        try:
            prepare_network(job,epoch,release,'owned-raw',{})
            prep=NetworkPreparation(job,epoch,release,'owned-raw',actors,protocol=False)
            until=time.monotonic()+5
            while not prep.poll():
                need(time.monotonic()<until,'mail_public_raw_preparation');time.sleep(.02)
            record['closed_packets'] = []
            record['closed_packets'] = closed_packets(job, epoch, release, prep, actors,
                                                     observations=record['closed_packets'])
            record['result']='PASS'
        except Exception as error:
            record['error']=type(error).__name__+':'+str(error)[:512]
        finally:
            # Diagnostic publication never substitutes a failing launcher for
            # independent stopped-role/host readback, even on a failed probe.
            kernel.cleanup_actors(actors);kernel.vacant_ids()
            need(snapshot()==before and network_state()==network,'mail_public_owned_preparation_restore')
            record.update(writers_stopped=True,host_restored=True,elapsed_ns=time.monotonic_ns()-began)
            record.update(root_partition_mib=[192,64,128,64],root_partition_tasks=[24,8,16,8],
                          root_partition_cpu_percent=[35,10,25,15])
            record['preparation']={} if prep is None else {
                name:getattr(prep,name) for name in ['fixture_configured','server_live','worker_live','ready']}
            stop = Path(identity(job,epoch,release)['directory'])/'owner-result.json'
            if stop.exists():
                # Fixed protected path, bounded metadata, read only after the
                # independent role stop/host restore checks above succeeded.
                stopped = kernel.private_json(stop)
                need(set(stopped)=={'schema','epoch','reason','namespace_inode','elapsed_ns','check_error'} and
                     stopped['schema']=='paw-mail-network-stop-v1' and stopped['epoch']==epoch and
                     stopped['reason'] in {'unknown','guard_changed','controller_lost','external_stop',
                                          'requested_stop','deadline'} and
                     stopped['check_error'] in {None,'mail_public_guard_missing','mail_public_unarmed_cgroup_selector',
                        'mail_public_cgroup_replaced','mail_public_cgroup_path_not_live','mail_public_cgroup_id_changed',
                        'mail_public_cgroup_expression','mail_public_cgroup_selector_count',
                        'mail_public_guard_snapshot_changed','guard_snapshot_unavailable','guard_digest_changed'} and
                     all(type(stopped[k]) is int and stopped[k]>=0 for k in ['namespace_inode','elapsed_ns']),
                     'mail_public_owned_stop_metadata')
                record['guard_stop'] = stopped
            record['guard_cleanup_progress']=_cleanup_progress(stop.parent)
            record['roles']=[{'unit':actor.unit,'launcher_returncode':actor.process.poll(),
                'stderr_bytes':len(actor.errors),'stderr_sha256':sha(bytes(actor.errors)),
                'stderr':bytes(actor.errors[:4096]).decode('utf-8','replace'),
                'stderr_truncated':len(actor.errors)>4096,
                'witness':getattr(actor,'observation',None)} for actor in actors]
    raw=canonical(record);need(len(raw)<=32768,'mail_public_owned_diagnostic_budget')
    target=EXPORT_ROOT/('owned-mail-preparation-'+job)
    target.mkdir(mode=0o700)
    fd=os.open(target/'attestation.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    publish_reader_tree(target)
    return {'result':record['result'],'vm_started':False,'real_samples_executed':0,'real_connections':0,
            'production_grants_enabled':False,'i08_installed':False,'writers_stopped':True,'host_restored':True,
            'attestation_sha256':sha(raw),'export':str(target),'scope':record['scope']}


def closed_packets(job, epoch, release, prep, roles, *, observations=None):
    """The same fixed denied UDP→collected worker→denied TCP path in both gates.

    Only the loopback-only owned namespace is admissible. No lease is issued.
    This is also callable by the existing no-VM owned diagnostic, so startup
    and cgroup rearm failures do not require another real-source approval.
    """
    need(prep.mode=='owned-raw' and prep.ready, 'mail_public_closed_owned_only')
    owner=prep.owner; worker=prep.worker
    if observations is None:observations=[]
    need(type(observations) is list and not observations,'mail_public_closed_observation_sink')
    for serial, op in enumerate(['udp','tcp']):
        if serial:
            worker=PublicActor(job,epoch,release,'probe',owner.pid,registry=roles,serial=serial)
            kernel.live_role(worker,'probe',prep.inode)
        subprocess.run(['/usr/bin/systemctl','set-property','--runtime',worker.unit,
            'IPAddressAllow=', 'IPAddressAllow=93.184.216.34/32 9.9.9.9/32'],
            check=True,capture_output=True,timeout=2)
        owner.send({'op':'arm','epoch':epoch,'id':serial,'serial':serial})
        ack=owner.receive()
        need(ack.get('accepted') is True and type(ack.get('id')) is int and ack['id']==serial,
             'mail_public_raw_guard_ack')
        worker.send({'op':op});value=worker.receive()
        need(value.get('done') is True,'mail_public_raw_not_done')
        worker.process.wait(timeout=2);observations.append(value)
    need(not observations[0]['matched'] and not observations[1]['connected'],
         'mail_public_actual_default_drop')
    owner.send({'op':'stop','epoch':epoch,'id':2});ack=owner.receive()
    need(ack.get('accepted') is True and type(ack.get('id')) is int and ack['id']==2,
         'mail_public_raw_guard_ack')
    need(owner.process.wait(timeout=2)==0,'mail_public_raw_guard_exit')
    return observations


def run_raw(approval,binding):
    """Actual packets use only aliases on a loopback-only private namespace."""
    from . import mail_browser_native as native
    from vm_runtime_revalidation import snapshot,network_state
    import one_use_authorization as fs
    job=binding['job'];epoch=binding['epoch'];release=approval['release_sha'];case=binding['case']
    need(case in native.OWNED_CASES[:5],'mail_public_raw_case')
    roles=[];before=snapshot();network=network_state();result={'case':case,'result':'FAIL',
        'scope':'Actual private namespace TCP/UDP; no public network or VM', 'observations':[]}
    with fs.execution_lock():
        folder,_=prepare_network(job,epoch,release,'owned-raw',approval['context']['uplink'])
        try:
            prep=NetworkPreparation(job,epoch,release,'owned-raw',roles,protocol=False)
            until=time.monotonic()+5
            while not prep.poll():need(time.monotonic()<until,'mail_public_raw_preparation');time.sleep(.02)
            owner=prep.owner;server=prep.server;worker=prep.worker;serial=0;sequence=0
            def control(op,**fields):
                nonlocal sequence
                owner.send({'op':op,'epoch':epoch,'id':sequence,**fields});ack=owner.receive()
                need(ack.get('accepted') is True and type(ack.get('id')) is int and ack['id']==sequence,
                     'mail_public_raw_guard_ack');sequence+=1
            def arm(child,number):
                subprocess.run(['/usr/bin/systemctl','set-property','--runtime',child.unit,
                    'IPAddressAllow=', 'IPAddressAllow=93.184.216.34/32 9.9.9.9/32'],
                    check=True,capture_output=True,timeout=2)
                control('arm',serial=number)
            def packet(op,lease_kind=None,expired=False,bpf_closed=False):
                nonlocal worker,serial
                if serial:
                    worker=PublicActor(job,epoch,release,'probe',owner.pid,registry=roles,serial=serial)
                    kernel.live_role(worker,'probe',prep.inode)
                arm(worker,serial);serial+=1
                if bpf_closed:
                    subprocess.run(['/usr/bin/systemctl','set-property','--runtime',worker.unit,
                        'IPAddressAllow='],check=True,capture_output=True,timeout=2)
                if lease_kind:
                    control('lease',kind=lease_kind,address='9.9.9.9' if lease_kind=='dns' else '93.184.216.34',
                            milliseconds=1000)
                    if expired:time.sleep(1.1)
                worker.send({'op':op});value=worker.receive()
                need(value.get('done') is True,'mail_public_raw_not_done');worker.process.wait(timeout=2)
                result['observations'].append(value);return value
            if case=='closed':
                result['observations']=closed_packets(job,epoch,release,prep,roles)
            elif case=='dns-only':
                need(packet('udp','dns')['matched'] and not packet('tcp','dns')['connected'],
                     'mail_public_actual_dns_only')
                need(not packet('udp','dns',bpf_closed=True)['matched'],
                     'mail_public_BPF_deny_not_effective')
                server.send({'op':'counts'});counts=server.receive()
                need(counts.get('counts',{}).get('udp')==1,'mail_public_BPF_packet_reached_fixture')
            elif case=='http-expiry':
                arm(worker,0);control('lease',kind='http',address='93.184.216.34',milliseconds=1000)
                worker.send({'op':'stream'});progress=[]
                while True:
                    value=worker.receive(4)
                    if value.get('done') is True:break
                    need(value.get('progress') is True and value.get('matched') is True,'mail_public_stream_witness')
                    progress.append(value)
                need(progress and value['bytes']>0 and progress[-1]['last_byte_ns']-progress[0]['last_byte_ns']<
                     1300*10**6,'mail_public_established_reply_expiry')
                worker.process.wait(timeout=2);result['observations']=progress+[value]
            else:
                arm(worker,0);control('lease',kind='http',address='93.184.216.34',milliseconds=3000)
                worker.send({'op':'stream'});value=worker.receive()
                need(value.get('progress') is True and value.get('matched') is True,'mail_public_fault_live_stream')
                result['observations'].append(value)
                if case=='owner-loss':
                    # Master expects no normal child result. Its independent
                    # PID1 ExecStopPost reader must prove every role/VM stopped.
                    from benign_guest_validation import process_identity
                    native.atomic(native.private_batch(approval['batch_id'])/'children'/(job+'-crash.json'),
                        canonical({'schema':'paw-mail-native-controller-kill-armed-v1','job':job,'epoch':epoch,
                            'batch_id':approval['batch_id'],'release_sha':release,'controller_pid':os.getpid(),
                            'controller_identity':process_identity(os.getpid()),'established_stream':value}),
                        exclusive=True)
                    os.kill(os.getpid(),signal.SIGKILL)
                control('delete_one')
                owner.process.wait(timeout=3);worker.process.wait(timeout=3)
                stopped=kernel.private_json(folder/'owner-result.json')
                need(stopped['reason']=='guard_changed','mail_public_guard_loss_disposition')
            if case not in {'closed','owner-loss','guard-loss'}:
                control('stop');owner.process.wait(timeout=2)
            result['result']='PASS'
        finally:
            kernel.cleanup_actors(roles);kernel.vacant_ids()
            need(snapshot()==before and network_state()==network,'mail_public_owned_raw_restore')
            result['roles']=[v.observation for v in roles if hasattr(v,'observation')]
    return {'schema':'paw-mail-native-child-result-v1','kind':'kernel','job':job,'epoch':epoch,
            'batch_id':approval['batch_id'],'release_sha':release,'case':case,'result':result,
            'writers_stopped':True,'host_restored':True}


def run_contract(case):
    """Compiled inert packet/ledger tests, explicitly not network observations."""
    from . import browser_owned_protocol as protocol
    nonce='0'*32;began=time.monotonic_ns();seed='https://paw-owned.invalid/'
    def frame(sequence,url=seed):return {'nonce':nonce,'seq':sequence,'url':url,'method':'GET','resource':'Document'}
    refusal=None
    try:
        if case=='private-dns':
            dns.parse_answer(protocol.dns_response(dns.question('paw-owned.invalid',1),'private'),'paw-owned.invalid',1)
        elif case=='rebind':
            ledger=mediator.BrowserRequestLedger(seed,nonce,began)
            plan=ledger.admit(frame(0),['93.184.216.34'],0,10**10,began)
            ledger.complete(plan,200,[],b'','93.184.216.34',True,began+1)
            ledger.admit(frame(1),['93.184.216.35'],0,10**10,began+2)
        elif case=='redirect':
            ledger=mediator.BrowserRequestLedger(seed,nonce,began)
            for seq in range(6):
                plan=ledger.admit(frame(seq),['93.184.216.34'],0,10**10,began+seq*2)
                ledger.complete(plan,302,[['Location','/loop']],b'','93.184.216.34',True,began+seq*2+1)
        elif case=='protocol-loss':
            decoder=wire.Decoder(nonce,body_budget=0)
            decoder.feed(wire.frame(nonce,0,'stop',{})[:-1]);decoder.eof()
        elif case=='counter-budget':
            budget=BatchBudget([seed,seed,seed]);budget.reserve(0);budget.uncertain(0);budget.reserve(0)
        else:raise ValueError('mail_public_unknown_contract_case')
    except ValueError as error:refusal=str(error)
    expected={'private-dns':'broker_dns_special','rebind':'broker_dns_rebinding',
              'redirect':'broker_redirect_budget_or_location','protocol-loss':'wire_truncated',
              'counter-budget':'mail_public_case_byte_budget'}
    need(case in expected and refusal==expected[case],'mail_public_owned_contract_did_not_refuse:'+str(refusal))
    return {'case':case,'result':'PASS','scope':'Inert compiled packet/ledger refusal; no network/VM',
            'expected_refusal':refusal}


def child_binding(release,batch,job):
    from . import mail_browser_native as native
    need(type(job) is str and re.fullmatch('[0-9a-f]{32}',job),'mail_public_child_job')
    value=native.decode(native.protected(native.private_batch(batch)/'children'/(job+'.json'),65536),65536)
    need(type(value) is dict and set(value)=={'schema','release_sha','batch_id','job','epoch','kind','case','slot','budget'} and
         value['schema']=='paw-mail-native-child-binding-v1' and value['release_sha']==release and
         value['batch_id']==batch and value['job']==job and
         type(value['epoch']) is str and re.fullmatch('[0-9a-f]{32}',value['epoch']) and
         value['kind'] in {'kernel','capture'} and value['case'] in native.OWNED_CASES and
         (value['kind']=='capture')==(value['case']=='browser'),'mail_public_child_binding')
    slot_name(value['slot'])
    need(value['kind']=='capture' or value['slot']=='owned','mail_public_kernel_owned_only')
    return value


def cleanup_child(release,batch,job):
    """Fixed PID1 stop hook can only terminate this protected batch's children.

    It works after master death/revocation and never starts a guest, makes a
    grant, promotes a release or imports executable user data.
    """
    from . import mail_browser_native as native
    binding=child_binding(release,batch,job);epoch=binding['epoch'];ids=identity(job,epoch,release)
    need(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/mail_browser_public.py',
         'mail_public_cleanup_immutable_root')
    began=time.monotonic_ns();failures=[]
    raw_exit=subprocess.check_output(['/usr/bin/systemctl','show','paw-vm-owned-'+job+'.service',
        '--property=ExecMainPID,ExecMainCode,ExecMainStatus,Result'],text=True,timeout=2)
    exit_state=dict(row.split('=',1) for row in raw_exit.splitlines())
    units=[identity(job,epoch,release,n)['probe'] for n in range(8)]+[ids['keeper'],ids['fixture']]
    for unit in units:
        state=kernel.unit_properties(unit)
        if state['MainPID']!='0' or state['ActiveState'] not in {'inactive','failed'}:
            stopped=subprocess.run(['/usr/bin/systemctl','stop',unit],capture_output=True,timeout=3)
            if stopped.returncode!=0:failures.append('stop:'+unit)
    for unit in units:
        state=kernel.unit_properties(unit)
        if state['MainPID']!='0' or state['ActiveState'] not in {'inactive','failed'}:
            failures.append('residual:'+unit)
    try:
        kernel.vacant_ids()
        folder=Path(ids['directory'])
        if (folder/'guard-created').exists():remove_tables(job,epoch,release)
        from vm_runtime_revalidation import snapshot,network_state
        from .mail_browser_native import protected
        before=native.decode(protected(native.private_batch(batch)/'baseline.json',65536),65536)
        need(snapshot()==before['snapshot'] and network_state()==before['network'],
             'mail_public_child_terminal_host_changed')
    except Exception as error:failures.append(type(error).__name__+':'+str(error)[:256])
    result={'schema':'paw-mail-native-child-cleanup-v1','job':job,'batch_id':batch,'release_sha':release,
            'epoch':epoch,'writers_stopped':not failures,'host_restored':not failures,
            'elapsed_ns':time.monotonic_ns()-began,'failures':failures,'exit_state':exit_state}
    destination=native.private_batch(batch)/'children'/(job+'-cleanup.json')
    if destination.exists():destination=native.private_batch(batch)/'children'/(job+'-cleanup-latest.json')
    native.atomic(destination,canonical(result))
    need(not failures and result['elapsed_ns']<12*10**9,'mail_public_child_cleanup_failed')
    return result


def child(release,batch,job):
    from . import mail_browser_native as native
    native.root(release);approval=native.scope(release,batch);binding=child_binding(release,batch,job)
    props=kernel.unit_properties('paw-vm-owned-'+job+'.service')
    need(props['MainPID']==str(os.getpid()) and props['MemoryMax']==str(192*1024**2) and
         props['MemorySwapMax']=='0' and props['TasksMax']=='24' and
         props['CPUQuotaPerSecUSec']=='350ms','mail_public_child_budget')
    need(native.context(release)==approval['context'],'mail_public_child_context_changed')
    need(not (native.private_batch(batch)/'children'/(job+'-used')).exists(),'mail_public_child_replay')
    native.atomic(native.private_batch(batch)/'children'/(job+'-used'),b'used',exclusive=True)
    if binding['kind']=='kernel':result=run_raw(approval,binding)
    else:
        if binding['slot']!='owned':
            need(native.protected(native.private_batch(batch)/'real-batch-consumed',128)==b'consumed',
                 'mail_public_actual_before_owned_gates')
        request=native.materialize(approval,binding['slot'])
        seeds=([request['url']]*3 if binding['slot']=='owned' else [v['url'] for v in approval['selections']])
        budget=BatchBudget(seeds,binding['budget'])
        result=run_capture(approval,binding,request,budget)
    native.atomic(native.private_batch(batch)/'children'/(job+'-result.json'),canonical(result),exclusive=True)
    return result


def launch_child(approval,kind,case,slot='owned',previous=None):
    from . import mail_browser_native as native
    release=approval['release_sha'];batch=approval['batch_id'];job=uuid.uuid4().hex;epoch=uuid.uuid4().hex
    native.need(native.scope(release,batch)==approval,'mail_public_master_live_binding')
    native._mkdir(Path('/var/lib/paw-vm/jobs')/job)
    binding={'schema':'paw-mail-native-child-binding-v1','release_sha':release,'batch_id':batch,
        'job':job,'epoch':epoch,'kind':kind,'case':case,'slot':slot,'budget':previous}
    native.atomic(native.private_batch(batch)/'children'/(job+'.json'),canonical(binding),exclusive=True)
    program='/opt/paw-vm/releases/'+release+'/paw/core/mail_browser_public.py'
    props={'Type':'exec','Restart':'no','MemoryMax':'192M','MemorySwapMax':'0','TasksMax':'24',
        'CPUQuota':'35%','RuntimeMaxSec':'360','RuntimeRandomizedExtraSec':'0','KillMode':'control-group',
        'TimeoutStopSec':'12','LimitCORE':'0','LimitFSIZE':'67108864','UMask':'0077',
        'NoNewPrivileges':'yes','RestrictAddressFamilies':'AF_UNIX AF_NETLINK','IPAddressDeny':'any',
        'BindsTo':'paw-mail-batch-'+batch+'.service','After':'paw-mail-batch-'+batch+'.service',
        'ExecStopPost':'/usr/bin/python3 -I -S -B '+program+' --cleanup-child '+job+' '+batch+' '+release}
    argv=['/usr/bin/systemd-run','--quiet','--wait','--collect','--unit=paw-vm-owned-'+job+'.service',
        *['--property='+k+'='+v for k,v in props.items()],
        '/usr/bin/python3','-I','-S','-B',program,'--child',job,batch,release]
    outcome=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           timeout=375,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
    need(len(outcome.stdout)+len(outcome.stderr)<=16384,'mail_public_child_launcher_output')
    props=kernel.unit_properties('paw-vm-owned-'+job+'.service')
    need(props['MainPID']=='0' and props['ActiveState'] in {'inactive','failed'},'mail_public_child_residual')
    cleanup=native.decode(native.protected(native.private_batch(batch)/'children'/(job+'-cleanup.json'),
                                         65536),65536)
    need(cleanup.get('job')==job and cleanup.get('batch_id')==batch and cleanup.get('release_sha')==release and
         cleanup.get('epoch')==epoch and cleanup.get('writers_stopped') is True and
         cleanup.get('host_restored') is True and not cleanup.get('failures') and
         type(cleanup.get('elapsed_ns')) is int and 0<=cleanup['elapsed_ns']<12*10**9,
         'mail_public_child_unknown_stop')
    if kind=='kernel' and case=='owner-loss':
        armed=native.decode(native.protected(native.private_batch(batch)/'children'/(job+'-crash.json'),65536),65536)
        need(armed.get('schema')=='paw-mail-native-controller-kill-armed-v1' and
             all(armed.get(k)==v for k,v in {'job':job,'epoch':epoch,'batch_id':batch,'release_sha':release}.items()) and
             type(armed.get('controller_pid')) is int and armed['controller_pid']>1 and
             type(armed.get('controller_identity')) is str and armed['controller_identity'].isdigit() and
             armed.get('established_stream',{}).get('progress') is True and
             armed.get('established_stream',{}).get('matched') is True and
             cleanup.get('exit_state')=={'ExecMainPID':str(armed['controller_pid']),
                'ExecMainCode':'2','ExecMainStatus':'9','Result':'signal'} and outcome.returncode!=0,
             'mail_public_controller_kill_not_observed')
        return {'case':'owner-loss','result':'PASS','scope':'Actual coordinator SIGKILL with private established stream',
                'cleanup':cleanup}
    need(outcome.returncode==0,'mail_public_child_failed:'+outcome.stderr[:1024].decode('utf-8','replace'))
    result=native.decode(native.protected(native.private_batch(batch)/'children'/(job+'-result.json'),
                                        65536),65536)
    need(result.get('job')==job and result.get('epoch')==epoch and result.get('batch_id')==batch and
         result.get('release_sha')==release and result.get('writers_stopped') is True and
         result.get('host_restored') is True,'mail_public_child_result_binding')
    if kind=='kernel':need(result['result']['result']=='PASS','mail_public_raw_matrix_failed')
    return result


def native_sequence(approval):
    from . import mail_browser_native as native
    from vm_runtime_revalidation import snapshot,network_state
    batch=approval['batch_id'];directory=native.private_batch(batch)
    baseline={'snapshot':snapshot(),'network':network_state()}
    native.atomic(directory/'baseline.json',canonical(baseline),exclusive=True)
    publish_status(approval,'owned-packet-gates')
    rows=[]
    for case in native.OWNED_CASES[:5]:rows.append(launch_child(approval,'kernel',case))
    for case in native.OWNED_CASES[5:-1]:rows.append(run_contract(case))
    own=launch_child(approval,'capture','browser')
    need(own['status']=='completed','mail_public_owned_browser_not_accepted')
    rows.append(own)
    native.atomic(directory/'owned-gates.json',canonical(rows),exclusive=True)
    publish_status(approval,'waiting-installed-owned-custody',owned_capture=own)
    # No real navigation yet. Installed PAW must import/verify/export the new
    # protected owned capture, and Root independently validates those exact bytes.
    acknowledgement=receive_owned_ack(approval)
    native.atomic(directory/'owned-custody.json',canonical(acknowledgement),exclusive=True)
    native.atomic(directory/'real-batch-consumed',b'consumed',exclusive=True)
    results=[];previous=None
    for slot in range(3):
        publish_status(approval,'real-capture',slot=slot)
        result=launch_child(approval,'capture','browser',slot,previous)
        current=BatchBudget([v['url'] for v in approval['selections']],result['budget']).facts()
        if previous is not None:
            need(set(previous['hostname_slots'])<=set(current['hostname_slots']) and
                 all(b>=a for a,b in zip(previous['request_slots'],current['request_slots'])) and
                 all(b>=a for a,b in zip(previous['response_bytes_or_unrecoverable_reservations'],
                                        current['response_bytes_or_unrecoverable_reservations'])),
                 'mail_public_batch_accounting_regressed')
        results.append(result);previous=current
    need(snapshot()==baseline['snapshot'] and network_state()==baseline['network'],'mail_public_batch_restore')
    result={'schema':'paw-mail-native-batch-result-v1','status':'collected','batch_id':batch,
            'release_sha':approval['release_sha'],'results':results,'budget':previous,
            'scope':'Three actual controlled main-page attempts; individual coverage/status may be partial'}
    native.atomic(directory/'result.json',canonical(result),exclusive=True)
    publish_status(approval,'collected',result=result)
    return result


def cleanup_batch(release,batch):
    from . import mail_browser_native as native
    need(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/mail_browser_public.py',
         'mail_public_cleanup_immutable_root')
    directory=native.private_batch(batch);children=directory/'children';failures=[]
    fd=native.root_directory(children)
    try:names=os.listdir(fd)
    finally:os.close(fd)
    need(len(names)<=128,'mail_public_batch_children_budget')
    jobs=sorted(name[:-5] for name in names if re.fullmatch(r'[0-9a-f]{32}\.json',name))
    for job in jobs:
        try:
            subprocess.run(['/usr/bin/systemctl','stop','paw-vm-owned-'+job+'.service'],capture_output=True,timeout=14)
            cleanup_child(release,batch,job)
        except Exception as error:failures.append(type(error).__name__+':'+str(error)[:256])
    native.atomic(directory/'closed.json',canonical({'schema':'paw-mail-native-batch-closed-v1',
        'batch_id':batch,'release_sha':release,'at':int(time.time()),'failures':failures}))
    need(not failures,'mail_public_batch_cleanup_failed')
    return {'status':'closed','batch_id':batch}


ACK_MAX=2*1024**2


def validate_ack(raw,batch,expected,hasher):
    """Independent actual sidecar and ZIP bytes, never a UID passed:true claim."""
    import io
    import zipfile
    from . import mail_browser_custody as custody, synthetic_bridge as shared
    value=shared._decode(raw,ACK_MAX)
    need(type(value) is dict and set(value)=={'schema','batch_id','sidecar_b64','zip_b64'} and
         raw==canonical(value) and value['schema']=='paw-mail-native-owned-custody-ack-v1' and
         value['batch_id']==batch and type(value['sidecar_b64']) is dict,
         'mail_public_owned_ack_shape')
    need(set(value['sidecar_b64'])==set(expected)|{'evidence/inventory_scope.json',
        'evidence/merkle_index.json','evidence/merkle_root.bin'},'mail_public_owned_sidecar_inventory')
    files={}
    for name,encoded in value['sidecar_b64'].items():
        cap=max(len(expected[name]),1) if name in expected else 16384
        files[name]=custody.decode64(encoded,cap)
        if name in expected:need(files[name]==expected[name],'mail_public_owned_sidecar_changed')
    scope=shared._decode(files['evidence/inventory_scope.json'],4096)
    from .evidence import EXCLUDED
    need(scope=={'policy':'all_case_files_v1','excluded':sorted(EXCLUDED),
        'limitation':'Content integrity; no independent signature, origin or Rekor proof is established'},
         'mail_public_owned_scope')
    index=shared._decode(files['evidence/merkle_index.json'],16384)
    hashes={n:hasher(v) for n,v in sorted(files.items()) if n not in {
        'evidence/merkle_index.json','evidence/merkle_root.bin'}}
    need(index==hashes and list(index)==sorted(hashes) and
         files['evidence/merkle_root.bin']==hasher(''.join(hashes.values()).encode()).encode(),
         'mail_public_owned_seal')
    zipped=custody.decode64(value['zip_b64'],1024**2)
    with zipfile.ZipFile(io.BytesIO(zipped)) as archive:
        entries=archive.infolist()
        need(len(entries)==len(files) and len({v.filename for v in entries})==len(files) and
             {v.filename for v in entries}=={'result/'+n for n in files},'mail_public_owned_zip_inventory')
        for entry in entries:
            data=files[entry.filename.removeprefix('result/')]
            need(not entry.is_dir() and not entry.flag_bits&1 and entry.file_size==len(data) and
                 entry.compress_type in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED},'mail_public_owned_zip_entry')
            with archive.open(entry) as stream:
                need(stream.read(len(data)+1)==data and stream.read(1)==b'', 'mail_public_owned_zip_bytes')
    return {'schema':'paw-mail-native-owned-custody-verified-v1','batch_id':batch,
            'sidecar_files':len(files),'merkle_root_blake3':files['evidence/merkle_root.bin'].decode(),
            'zip_bytes':len(zipped),'zip_sha256':sha(zipped),'ack_sha256':sha(raw)}


def ack_descriptor(fd):
    import fcntl
    before=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    need(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1 and
         stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=ACK_MAX and
         flags&os.O_ACCMODE==os.O_RDONLY and not flags&getattr(os,'O_PATH',0),'mail_public_ack_descriptor')
    raw=os.pread(fd,ACK_MAX+1,0);after=os.fstat(fd)
    keys=['st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_nlink']
    need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in keys),
         'mail_public_ack_descriptor_changed')
    return raw


def receive_owned_ack(approval):
    import array
    from . import mail_browser_native as native, mail_browser_custody as custody
    from . import synthetic_bridge as shared
    batch=approval['batch_id'];release=approval['release_sha']
    target=EXPORT_ROOT/('mail-public-'+batch+'-owned')
    fd=native.root_directory(target);os.close(fd)
    raw=native.protected(target/'request.json',custody.REQUEST_MAX,mode=0o440)
    parsed=shared._decode(raw,custody.REQUEST_MAX)
    request=custody.validate(raw,native.load_hasher(),now=parsed['created_at'])
    custody.require_selection(request,approval['owned_selection'])
    receipt_raw=native.protected(target/'receipt.json',RECEIPT_MAX,mode=0o440)
    receipt=validate_receipt(receipt_raw,request,batch,'owned')
    need(receipt['status']=='completed','mail_public_owned_ack_partial_capture')
    expected={'request.json':raw,'receipt.json':receipt_raw,'result.json':sidecar_result(request,receipt)}
    for item in receipt['artifacts']:
        data=native.protected(target/item['name'],artifact_cap(item['name']),mode=0o440,allow_empty=True)
        need(len(data)==item['bytes'] and sha(data)==item['sha256'],'mail_public_owned_export_changed')
        expected[item['name']]=data
    folder=EXPORT_ROOT/('mail-native-ack-'+batch);native._mkdir(folder)
    listener=None;peer=None;fds=[]
    try:
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);listener.settimeout(180)
        listener.bind(str(folder/'ack.sock'));os.chown(folder/'ack.sock',0,1000);os.chmod(folder/'ack.sock',0o660)
        listener.listen(1);os.chown(folder,0,1000);os.chmod(folder,0o750)
        peer,_=listener.accept();peer.settimeout(3)
        pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(pid>1 and uid==gid==1000,'mail_public_owned_ack_peer')
        raw,ancillary,flags,_=peer.recvmsg(4097,socket.CMSG_SPACE(array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
        unknown=False
        for level,kind,body in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                values=array.array('i');values.frombytes(body[:len(body)-len(body)%values.itemsize]);fds.extend(values)
            else:unknown=True
        need(not unknown and not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) and len(fds)==1 and
             raw==canonical({'kind':'paw-mail-owned-ack-fd-v1','batch_id':batch}),
             'mail_public_owned_ack_envelope')
        need(native.scope(release,batch)==approval,'mail_public_owned_ack_scope_expired')
        result=validate_ack(ack_descriptor(fds[0]),batch,expected,native.load_hasher())
        answer=canonical({'accepted':True,'batch_id':batch,'ack_sha256':result['ack_sha256']})
        need(peer.send(answer)==len(answer),'mail_public_owned_ack_short_reply')
        return result
    finally:
        for fd in fds:os.close(fd)
        if peer is not None:peer.close()
        if listener is not None:listener.close()
        try:(folder/'ack.sock').unlink()
        except FileNotFoundError:pass
        folder.rmdir()


def client_ack(batch,result,archive,output):
    from . import synthetic_bridge as shared
    return shared._offline(_client_ack)(batch,Path(result),Path(archive),Path(output))


def _client_ack(batch,result,archive,output):
    import blake3
    from . import mail_browser_owned as owned, synthetic_bridge as shared
    need(type(batch) is str and re.fullmatch('[0-9a-f]{32}',batch),'mail_public_ack_batch')
    need(result.name=='result','mail_public_ack_result_directory')
    fd=owned._walk(result)
    try:
        names=os.listdir(fd);need('evidence' in names and len(names)<=27,'mail_public_ack_file_count')
        expected={name:shared._read_regular(name,2*1024**2,directory_fd=fd) for name in names if name!='evidence'}
        files=dict(expected)
        evidence=os.open('evidence',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            need(set(os.listdir(evidence))=={'inventory_scope.json','merkle_index.json','merkle_root.bin'},
                 'mail_public_ack_evidence_inventory')
            for name in os.listdir(evidence):
                files['evidence/'+name]=shared._read_regular(name,16384,directory_fd=evidence)
        finally:os.close(evidence)
    finally:os.close(fd)
    # Local checks aid usability; only Root's independently reconstructed bytes
    # may authorize real work. This routine cannot create that authority.
    receipt=shared._decode(expected['receipt.json'],RECEIPT_MAX)
    need(receipt.get('batch_id')==batch and receipt.get('slot')=='owned','mail_public_ack_owned_only')
    zipped=shared._read_regular(archive,1024**2)
    raw=canonical({'schema':'paw-mail-native-owned-custody-ack-v1','batch_id':batch,
        'sidecar_b64':{n:base64.b64encode(v).decode('ascii') for n,v in sorted(files.items())},
        'zip_b64':base64.b64encode(zipped).decode('ascii')})
    validate_ack(raw,batch,expected,lambda v:blake3.blake3(v).hexdigest())
    # Output uses the same no-follow, outside-evidence descriptor publication.
    dest=shared._destination(output,result)
    with owned._output(dest,result) as (fd,key):
        owned._write(fd,'ack.json',raw,key,0o400);owned._named_output(dest,fd,key)
    return {'status':'prepared','ack':str(dest/'ack.json'),'sha256':sha(raw),'execution_authorized':False}


def client_submit_ack(batch,path):
    import array
    from . import owned_mail_channel as channel
    need(os.getuid()==os.geteuid()==1000 and type(batch) is str and re.fullmatch('[0-9a-f]{32}',batch),
         'mail_public_ack_submit_owner')
    folder=EXPORT_ROOT/('mail-native-ack-'+batch)
    with channel.protected_directory(folder) as parent:
        info=os.stat('ack.sock',dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid==1000 and
             stat.S_IMODE(info.st_mode)==0o660,'mail_public_ack_protected_socket')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            raw=ack_descriptor(fd)
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(5);peer.connect(str(folder/'ack.sock'))
                pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                need(pid>1 and uid==gid==0,'mail_public_ack_root_peer')
                envelope=canonical({'kind':'paw-mail-owned-ack-fd-v1','batch_id':batch})
                need(peer.sendmsg([envelope],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])==len(envelope),
                     'mail_public_ack_short_send')
                reply,ancillary,flags,_=peer.recvmsg(4097,0)
                need(not ancillary and not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) and
                     reply==canonical({'accepted':True,'batch_id':batch,'ack_sha256':sha(raw)}),
                     'mail_public_ack_root_refused')
        finally:os.close(fd)
    return {'status':'accepted','batch_id':batch,'ack_sha256':sha(raw),
            'scope':'Root independently verified owned custody; finite native batch may proceed'}



def publish_status(approval,phase,**facts):
    """Reader-visible progress only; never an execution or readiness authority."""
    from . import mail_browser_native as native
    directory=EXPORT_ROOT/('mail-native-status-'+approval['batch_id'])
    fresh=not directory.exists()
    if fresh:native._mkdir(directory)
    raw=canonical({'schema':'paw-mail-native-status-v1','batch_id':approval['batch_id'],
        'release_sha':approval['release_sha'],'at':int(time.time()),'phase':phase,
        'advisory_only':True,**facts})
    need(len(raw)<=65536,'mail_public_status_budget')
    native.atomic(directory/'status.json',raw,mode=0o440)
    if fresh:
        from reader_export import publish_reader_tree
        publish_reader_tree(directory)
    else:os.chown(directory/'status.json',0,1000)

def main():
    if len(sys.argv)==2 and sys.argv[1]=='--guest':guest_main();return
    need(len(sys.argv) in {5,6} and sys.argv[1] in {
        '--keeper','--fixture','--probe','--child','--cleanup-child','--cleanup-batch'},
         'mail_public_fixed_entry')
    operation=sys.argv[1]
    if operation in {'--child','--cleanup-child'}:
        need(len(sys.argv)==5,'mail_public_child_argv')
        job,batch,release=sys.argv[2:]
        need(type(release) is str and re.fullmatch('[0-9a-f]{40}',release) and
             HERE==Path('/opt/paw-vm/releases')/release/'paw/core/mail_browser_public.py',
             'mail_public_installed_child_entry')
        sys.path[:0]=[str(HERE.parents[2]),str(HERE.parents[2]/'lab/s14')]
        global __package__
        __package__='paw.core'
        result=child(release,batch,job) if operation=='--child' else cleanup_child(release,batch,job)
        print(canonical(result).decode('ascii'),flush=True);return
    if operation=='--cleanup-batch':
        need(len(sys.argv)==5 and sys.argv[2]=='fixed','mail_public_batch_cleanup_argv')
        batch,release=sys.argv[3:]
        sys.path[:0]=[str(HERE.parents[2]),str(HERE.parents[2]/'lab/s14')];__package__='paw.core'
        print(canonical(cleanup_batch(release,batch)).decode('ascii'),flush=True);return
    job,epoch,release=sys.argv[2:5]
    if operation=='--probe':
        need(len(sys.argv)==6,'mail_public_probe_argv');probe_main(job,epoch,release,sys.argv[5])
    else:
        need(len(sys.argv)==5,'mail_public_role_argv')
        {'--keeper':keeper,'--fixture':fixture_main}[operation](job,epoch,release)


if __name__=='__main__':main()
