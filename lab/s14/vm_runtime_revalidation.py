"""Finite no-guest runtime restart from an immutable root snapshot."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
UNITS = ('machine-paws14.slice', 'libvirtd.service')
SLICE = {'MemoryMax': '2147483648', 'MemorySwapMax': '0', 'TasksMax': '128'}
MAINTENANCE_PREVIOUS = '4ab64d87b191dd6ea2879fae0f9e5f12eb255a8fe83062d34f577c2d8d7b1e44'
INVENTORY_PREVIOUS = '4c4a2167cfbd316bd7923426ef249b25f459dc7181df5fbe55624bb4ffeaed80'
INVENTORY_BROTLI = 'e214bcd487744333146303190396743973b1ad9755112c182b0bf7aa255c2ef3'
BROTLI_PACKAGES = {b'libbrotli1:amd64', b'python3-brotli'}


def require(value, reason):
    if not value: raise ValueError(reason)


def properties(unit, names):
    require(unit in {*UNITS, 'paw-s14-guard.service', 'libvirtd-tcp.socket', 'libvirtd-tls.socket'}, 'runtime_fixed_unit')
    value = subprocess.check_output(['/usr/bin/systemctl', 'show', unit, '--property='+','.join(names)],
                                    text=True, timeout=15)
    return dict(row.split('=', 1) for row in value.splitlines())


def process_inventory():
    found = []; count = 0
    binary = Path('/usr/bin/qemu-system-x86_64').stat()
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal(): continue
        count += 1; require(count <= 65536, 'runtime_process_scan_budget')
        try: name = (path/'comm').read_text().strip()
        except (FileNotFoundError, ProcessLookupError): continue
        try:
            target = (path/'exe').stat()
            same_binary = (target.st_dev, target.st_ino) == (binary.st_dev, binary.st_ino)
            executable = (path/'exe').readlink().name
        except (FileNotFoundError, ProcessLookupError): same_binary = False; executable = ''
        if same_binary or name.startswith(('qemu-system', 'qemu-kvm')) or executable.startswith(('qemu-system', 'qemu-kvm')):
            found.append(int(path.name))
    require(len(found) <= 4096, 'runtime_process_inventory_budget')
    return sorted(found)


def validate_snapshot(value):
    require(type(value) is dict and set(value) == {'guard', 'guard_service', 'slice_properties',
            'qemu_pids', 'namespaces', 'tcp_sockets', 'domain_definitions', 'autostart', 'hooks',
            'daemon_config_sha256'}, 'runtime_snapshot_shape')
    require(type(value['guard']) is str and len(value['guard']) == 64 and
            all(v in '0123456789abcdef' for v in value['guard']) and
            value['guard_service'] == {'LoadState': 'loaded', 'ActiveState': 'active'}, 'runtime_effective_guard')
    require(value['slice_properties'] == {'LoadState': 'loaded', **SLICE}, 'runtime_slice_budget')
    require(value['qemu_pids'] == [] and value['namespaces'] == [] and
            value['domain_definitions'] == [] and value['hooks'] == [] and value['autostart'] == [], 'runtime_foreign_work_or_autostart')
    require(value['tcp_sockets'] == {'libvirtd-tcp.socket': 'inactive', 'libvirtd-tls.socket': 'inactive'}, 'runtime_remote_libvirt')
    require(type(value['daemon_config_sha256']) is str and len(value['daemon_config_sha256']) == 64 and
            all(v in '0123456789abcdef' for v in value['daemon_config_sha256']), 'runtime_daemon_configuration')
    return value


def protected_names(path, *, optional=False):
    # Root path and every existing ancestor must be protected, including an
    # optional directory's parent. No user-chosen path enters this function.
    import one_use_authorization as fs
    try: path.lstat(); absent = False
    except FileNotFoundError: absent = True
    parent = path.parent if optional and absent else path
    with fs.root_directory(parent) as fd:
        if parent != path: return []
        names = os.listdir(fd); require(len(names) <= 256, 'runtime_directory_budget')
        for name in names:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == 0 and not info.st_mode & 0o022 and
                    (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), 'runtime_protected_config')
        return sorted(names)


def daemon_configuration():
    import one_use_authorization as fs
    config = properties('libvirtd.service', ['ExecStart', 'Environment', 'EnvironmentFiles', 'FragmentPath', 'DropInPaths'])
    require(config['Environment'] == '"LIBVIRTD_ARGS=--timeout 120"' and
            config['EnvironmentFiles'] == '/etc/default/libvirtd (ignore_errors=yes)' and
            config['FragmentPath'] == '/usr/lib/systemd/system/libvirtd.service' and
            config['DropInPaths'] == '/etc/systemd/system/libvirtd.service.d/paw-s14-guard.conf' and
            config['ExecStart'].count('{') == 1 and config['ExecStart'].startswith(
                '{ path=/usr/sbin/libvirtd ; argv[]=/usr/sbin/libvirtd $LIBVIRTD_ARGS ; ignore_errors=no ;'),
            'runtime_unreviewed_daemon_command')
    files = {}
    for path in [Path(config['FragmentPath']), Path(config['DropInPaths']), Path('/etc/default/libvirtd')]:
        with fs.root_directory(path.parent) as fd: raw = fs.read(fd, path.name, 65536)
        files[str(path)] = hashlib.sha256(raw).hexdigest()
        if path.name == 'libvirtd':
            lines = [line.strip() for line in raw.decode('utf-8', 'strict').splitlines()
                     if line.strip() and not line.lstrip().startswith('#')]
            require(lines in [[], ['LIBVIRTD_ARGS="--timeout 120"']], 'runtime_daemon_environment_override')
        if path.name == 'paw-s14-guard.conf':
            require(raw == (HERE/'libvirtd-guard.conf').read_bytes(), 'runtime_guard_dependency_changed')
    # Dynamic ExecStart timestamps/PIDs are not a configuration identity.
    config.pop('ExecStart')
    return fs.digest(json.dumps({'properties': config, 'files': files}, sort_keys=True).encode())


def snapshot():
    from benign_guest_validation import guard_fingerprint
    qemu = Path('/etc/libvirt/qemu'); hooks = Path('/etc/libvirt/hooks')
    names = protected_names(qemu)
    require(set(names) <= {'networks', 'autostart'}, 'runtime_domain_config_requires_review')
    auto = []
    for path in [qemu/'autostart', qemu/'networks/autostart']:
        auto.extend(str(path/name) for name in protected_names(path, optional=True))
    # Any hook, including a directory of hooks, needs a separate review. Do not
    # run a daemon with uninspected startup actions.
    hook_names = protected_names(hooks, optional=True)
    namespaces = subprocess.check_output(['/usr/sbin/ip', 'netns', 'list'], text=True, timeout=10).splitlines()
    return validate_snapshot({'guard': guard_fingerprint(),
        'guard_service': properties('paw-s14-guard.service', ['LoadState', 'ActiveState']),
        'slice_properties': properties('machine-paws14.slice', ['LoadState', *SLICE]),
        'qemu_pids': process_inventory(), 'namespaces': namespaces,
        'tcp_sockets': {unit: properties(unit, ['ActiveState'])['ActiveState']
                        for unit in ['libvirtd-tcp.socket', 'libvirtd-tls.socket']},
        'domain_definitions': [name for name in names if name.endswith('.xml')],
        'autostart': auto, 'hooks': hook_names, 'daemon_config_sha256': daemon_configuration()})


def network_state():
    # Read-only observation; no Wi-Fi, forwarding, bridge, route or filter write.
    # This observation covers the whole ruleset, including scalar set elements
    # and map/range lists. Reuse the established whole-ruleset normalizer.
    from gw_validation import canonical
    rules = json.loads(subprocess.check_output(['/usr/sbin/nft', '-j', 'list', 'ruleset'], timeout=10))
    interfaces = sorted(path.name for path in Path('/sys/class/net').iterdir())
    routes = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'route'], timeout=10))
    return {'nft_sha256': hashlib.sha256(json.dumps(canonical(rules), sort_keys=True).encode()).hexdigest(),
            'interfaces': interfaces, 'routes': routes}


def revalidate():
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined',
            'runtime_root_PID1_only')
    import one_use_authorization as fs
    import hash_authorization as platform
    import browser_authorization as browser
    # The operator's deployment lock is also held by the caller. This global
    # execution lock excludes another PAW guest while checking/starting units.
    with fs.execution_lock():
        before = snapshot(); network_before = network_state(); began = time.monotonic()
        old = {unit: properties(unit, ['LoadState', 'ActiveState']) for unit in UNITS}
        require(all(item['LoadState'] == 'loaded' and item['ActiveState'] in {'active', 'inactive'}
                    for item in old.values()), 'runtime_unit_state')
        started = []
        for unit in UNITS:
            # Reobserve immediate guard/autostart/busy predicates before every
            # fixed action, not just at initial admission.
            require(snapshot() == before and network_state() == network_before, 'runtime_prestart_changed')
            if old[unit]['ActiveState'] == 'inactive':
                subprocess.run(['/usr/bin/systemctl', 'start', unit], check=True, timeout=45)
                started.append(unit)
        after = snapshot(); network_after = network_state()
        require(after == before and network_after == network_before, 'runtime_host_network_changed')
        import libvirt
        libvirt.registerErrorHandler(lambda *_: None, None)
        connection = libvirt.open('qemu:///system')
        try:
            require(not connection.listAllDomains(0), 'runtime_existing_domain')
            networks = connection.listAllNetworks(0)
            require(all(not network.isActive() and not network.autostart() for network in networks),
                    'runtime_network_started_or_autostart')
            inventory = sorted(network.name() for network in networks)
        finally: connection.close()
        host = platform.capture(); platform.validate_context(host)
        html = browser.capture(); browser.validate_context(html)
        require(snapshot() == before and network_state() == network_before, 'runtime_final_state_changed')
        require(all(properties(unit, ['ActiveState']) == {'ActiveState': 'active'} for unit in UNITS),
                'runtime_fixed_unit_not_active')
        return {'result': 'PASS', 'scope': 'runtime restart and image/context readback only; no guest or I08',
                'before': before, 'after': after, 'network_before': network_before, 'network_after': network_after,
                'units_before': old, 'started_units': started, 'inactive_defined_networks': inventory,
                'platform_context_sha256': fs.digest(browser.canonical(host)),
                'browser_context_sha256': fs.digest(browser.canonical(html)),
                'elapsed_milliseconds': int((time.monotonic()-began)*1000),
                'vm_started': False, 'real_samples_executed': 0,
                'production_grants_enabled': False, 'i08_installed': False}


def maintenance_transition(previous, context, inventory):
    """One reviewed inventory delta, never a generic maintenance reattestation."""
    import hash_authorization as platform
    require(platform.digest(previous) == MAINTENANCE_PREVIOUS, 'runtime_previous_maintenance_digest')
    require(type(inventory) is bytes and len(inventory) <= 2*1024**2, 'runtime_inventory_budget')
    rows = inventory.splitlines()
    require(0 < len(rows) <= 65536 and all(row.count(b'\t') == 1 for row in rows), 'runtime_inventory_shape')
    names = [row.split(b'\t', 1)[0] for row in rows]
    require(len(set(names)) == len(names), 'runtime_inventory_duplicates')
    current = platform.digest(b'\n'.join(sorted(rows))+b'\n')
    require(current == context['dpkg_inventory_sha256'] and current in {INVENTORY_PREVIOUS, INVENTORY_BROTLI},
            'runtime_unreviewed_inventory')
    old_context = dict(context, dpkg_inventory_sha256=INVENTORY_PREVIOUS)
    # The old protected receipt must still match every non-inventory platform,
    # host, image and vendor field through the unchanged real validator.
    record = platform.validate_maintenance(previous, old_context)
    if current == INVENTORY_PREVIOUS: return previous
    changed = set(); restored = []
    for row in rows:
        name, version = row.split(b'\t')
        if name in BROTLI_PACKAGES:
            require(version == b'1.2.0-3ubuntu0.1', 'runtime_brotli_version')
            changed.add(name); row = name+b'\t1.2.0-3build1'
        restored.append(row)
    require(changed == BROTLI_PACKAGES and platform.digest(b'\n'.join(sorted(restored))+b'\n') == INVENTORY_PREVIOUS,
            'runtime_inventory_delta')
    record['dpkg_inventory_sha256'] = current
    record['review_notes'] = ('Exact reviewed Brotli-only inventory transition; prior protected maintenance and '
        'unchanged hypervisor/image/host bindings retained. No I08, grant or real specimen authorization.')
    raw = platform.canonical(record); platform.validate_maintenance(raw, context)
    return raw


def refresh_maintenance():
    """Fixed no-guest recipe only: append one exact reviewed maintenance record."""
    require(os.geteuid() == 0, 'runtime_root_maintenance_required')
    import hash_authorization as platform
    fs = platform.fs
    with fs.execution_lock():
        before = snapshot(); network_before = network_state()
        require(not Path('/var/run/reboot-required').exists(), 'runtime_maintenance_reboot_required')
        require(subprocess.check_output(['/usr/bin/dpkg', '--audit'], timeout=15) == b'', 'runtime_package_audit')
        context = platform.capture(); platform.validate_context(context)
        with platform.store() as fd:
            previous = fs.read(fd, 'maintenance-'+MAINTENANCE_PREVIOUS+'.json', 65536)
        inventory = subprocess.check_output(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n'], timeout=15)
        raw = maintenance_transition(previous, context, inventory)
        require(platform.canonical(platform.capture()) == platform.canonical(context) and
                snapshot() == before and network_state() == network_before and
                not Path('/var/run/reboot-required').exists(), 'runtime_maintenance_context_changed')
        name = 'maintenance-'+platform.digest(raw)+'.json'
        with platform.store() as fd:
            try: fs.exclusive(fd, name, raw)
            except FileExistsError: require(fs.read(fd, name, 65536) == raw, 'runtime_existing_maintenance_changed')
        # No policy, grant, readiness or old record is rewritten. Future callers
        # still validate this receipt against their independently captured context.
        return {'result': 'PASS', 'previous_sha256': platform.digest(previous), 'maintenance_sha256': platform.digest(raw),
                'inventory_sha256': context['dpkg_inventory_sha256'], 'changed': raw != previous,
                'i08_installed': False, 'production_grants_enabled': False, 'vm_started': False}


def run_owned(job, release):
    """Fixed recipe entry; root job directory was created by the enrolled helper."""
    require(os.geteuid() == 0 and type(job) is str and re.fullmatch('[0-9a-f]{32}', job) and
            type(release) is str and re.fullmatch('[0-9a-f]{40}', release) and
            HERE.parents[1] == Path('/opt/paw-vm/releases')/release, 'runtime_owned_snapshot_and_job')
    import one_use_authorization as fs
    from reader_export import publish_reader_tree
    from vm_operator_host import write_state
    folder = Path('/var/lib/paw-vm/jobs')/job
    with fs.root_directory(folder): pass
    record = {'result': 'FAIL', 'job': job, 'recipe': 'vm-acceptance-v1', 'release_sha': release,
              'real_samples_executed': 0, 'vm_started': False, 'scope': 'finite runtime restart only, not VM/I08 acceptance'}
    try:
        record['runtime'] = revalidate()
        require(record['runtime']['result'] == 'PASS' and record['runtime']['vm_started'] is False and
                type(record['runtime']['real_samples_executed']) is int and record['runtime']['real_samples_executed'] == 0 and
                record['runtime']['production_grants_enabled'] is False and record['runtime']['i08_installed'] is False,
                'runtime_owned_scope')
        record['runtime']['maintenance'] = refresh_maintenance()
        target = Path('/var/lib/paw-vm-exports')/job
        with fs.root_directory(target.parent): pass
        target.mkdir(mode=0o700)
        with fs.root_directory(target) as fd:
            fs.exclusive(fd, 'runtime.json', json.dumps(record['runtime'], sort_keys=True).encode()+b'\n')
        publish_reader_tree(target)
        record.update(result='PASS', export=str(target))
    except Exception as error: record.update(error=type(error).__name__+':'+str(error))
    with fs.root_directory(folder) as fd: write_state(fd, 'result.json', record)
    print(json.dumps({'result': record['result'], 'job': job, 'recipe': record['recipe'],
                      'real_samples_executed': 0, 'error': record.get('error'), 'export': record.get('export')}), flush=True)
    require(record['result'] == 'PASS', 'runtime_owned_recipe_failed')
