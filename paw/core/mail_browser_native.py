"""Native-authenticated one-batch controller, not a new passwordless command.

A digest-approved data bundle selects exactly three sealed-source/URL subjects.
The existing operator, static modules and polkit rules remain unchanged. One
authenticated PID1 controller runs owned gates, waits for verified installed
custody, then serial real captures; no public authority survives its lifetime.
"""
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve()
STATE = Path('/var/lib/paw-vm')
NATIVE = STATE/'mail-batches'
DEB = '2e13134c19b913b531c5050e34a625184c371707dffbcf6b46c59bbdae8149c9'
DEPENDENCY = STATE/'mail-dependencies'/DEB
ASSETS = {
    'COPYRIGHT': (1349, '75d6f0b04c912205ff4a6f7d924e910511991192bbb577506ded8e08d1f54416'),
    'blake3/__init__.py': (107, '8b919729adf98380edfe138af0e98214663eeb10edce64c01a57a9485bffd27b'),
    'blake3/blake3.cpython-314-x86_64-linux-gnu.so':
        (652312, '5c2fbbc1215f7d98f5ce6c2675a1f09db5818d69fb6d962174c6f88f42bf5373')}
POLICY = {'allow_dynamic_public_hosts': True, 'public_hosts_batch': 8,
          'http_requests_batch': 32, 'response_bytes_batch': 4*1024**2,
          'redirects_per_navigation': 5, 'browser_seconds': 15, 'external_stop_seconds': 12}
OWNED_CASES = ('closed', 'dns-only', 'http-expiry', 'owner-loss', 'guard-loss',
               'private-dns', 'rebind', 'redirect', 'protocol-loss', 'counter-budget', 'browser')
BUNDLE_MAX = 2*1024**2


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_value(value, size):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def decode(raw, cap):
    # The existing strict bounded decoder rejects duplicate/nonfinite values.
    from .synthetic_bridge import _decode
    value = _decode(raw, cap)
    need(raw == canonical(value), 'mail_native_canonical_data')
    return value


def root_directory(path):
    need(path.is_absolute() and '..' not in path.parts, 'mail_native_fixed_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in [None, *path.parts[1:]]:
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            info = os.fstat(fd)
            need(info.st_uid == 0 and not info.st_mode & 0o022, 'mail_native_protected_directory')
        return fd
    except BaseException:
        os.close(fd); raise


def protected(path, cap, *, mode=0o600, allow_empty=False):
    directory = root_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
             stat.S_IMODE(before.st_mode) == mode and
             (0 <= before.st_size if allow_empty else 0 < before.st_size) and before.st_size <= cap,
             'mail_native_protected_file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap+1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'mail_native_file_changed')
        return raw
    finally:
        os.close(fd)


def root(release):
    need(os.getuid() == os.geteuid() == 0 and hex_value(release, 40) and
         HERE == Path('/opt/paw-vm/releases')/release/'paw/core/mail_browser_native.py',
         'mail_native_immutable_root_only')
    protected(HERE, 128*1024, mode=0o444)
    active = json.loads(protected(STATE/'active.json', 16384))
    need(active.get('release_sha') == release and hex_value(active.get('manifest_sha256'), 64),
         'mail_native_active_release_required')
    return HERE.parents[2]


def atomic(path, raw, *, exclusive=False, mode=0o600):
    """Internal fixed protected destination, never an ordinary caller RPC."""
    need(type(raw) is bytes and len(raw) <= BUNDLE_MAX, 'mail_native_write_budget')
    fd = root_directory(path.parent)
    name = path.name if exclusive else '.mail-'+uuid.uuid4().hex
    try:
        child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(child, 'wb', closefd=False) as stream:
                stream.write(raw); stream.flush(); os.fsync(child)
            os.fchmod(child, mode)
        finally:
            os.close(child)
        if not exclusive:
            os.replace(name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        if not exclusive:
            try: os.unlink(name, dir_fd=fd)
            except FileNotFoundError: pass
        os.close(fd)


def validate_bundle(raw, digest, *, now=None):
    """Pure native data check. A matching digest is not native authorization."""
    need(type(raw) is bytes and 0 < len(raw) <= BUNDLE_MAX and hex_value(digest, 64) and
         sha(raw) == digest, 'mail_native_approved_bundle_digest')
    value = decode(raw, BUNDLE_MAX)
    need(type(value) is dict and set(value) == {
        'schema', 'state', 'release_sha', 'created_at', 'expires_at', 'owner_uid',
        'batch_id', 'batch_expires_at', 'policy', 'requests_b64', 'assets_b64', 'uplink',
        'owned_request_b64', 'baseline_job'
    } and value['schema'] == 'paw-mail-native-bundle-v1' and
        value['state'] == 'NATIVE_CONDITIONAL_APPROVAL_REQUESTED' and
        type(value['owner_uid']) is int and value['owner_uid'] == 1000 and
        hex_value(value['release_sha'], 40) and hex_value(value['batch_id'], 32) and
        hex_value(value['baseline_job'], 32),
        'mail_native_bundle_shape')
    now = time.time() if now is None else now
    need(type(value['created_at']) is int and type(value['expires_at']) is int and
         type(value['batch_expires_at']) is int and
         value['created_at'] <= now < value['expires_at'] <= value['created_at']+3600 and
         now < value['batch_expires_at'] <= value['created_at']+86400, 'mail_native_bundle_expired')
    need(canonical(value['policy']) == canonical(POLICY), 'mail_native_fixed_batch_policy')
    need(type(value['requests_b64']) is list and len(value['requests_b64']) == 3 and
         type(value['assets_b64']) is dict and set(value['assets_b64']) == set(ASSETS),
         'mail_native_finite_bundle_inventory')
    from .mail_browser_custody import decode64
    assets = {}
    for name, (size, expected) in ASSETS.items():
        data = decode64(value['assets_b64'][name], size)
        need(len(data) == size and sha(data) == expected, 'mail_native_dependency_digest')
        assets[name] = data
    requests = [decode64(v, 128*1024) for v in value['requests_b64']]
    decode64(value['owned_request_b64'], 128*1024)
    need(type(value['uplink']) is dict and set(value['uplink']) == {
        'interface', 'mac', 'host_ipv4', 'next_hop', 'connection_uuid', 'bssid'
    }, 'mail_native_uplink_shape')
    return value, assets, requests


def load_hasher():
    """Load only the exact protected Ubuntu ABI, never a user site package."""
    need(os.geteuid() == 0 and sys.version_info[:2] == (3, 14), 'mail_native_hash_root_ABI')
    import sysconfig
    need(sysconfig.get_config_var('SOABI') == 'cpython-314-x86_64-linux-gnu', 'mail_native_hash_ABI')
    fd = root_directory(DEPENDENCY)
    try:
        need(set(os.listdir(fd)) == {'COPYRIGHT', 'blake3'}, 'mail_native_dependency_inventory')
    finally:
        os.close(fd)
    fd = root_directory(DEPENDENCY/'blake3')
    try:
        need(set(os.listdir(fd)) == {'__init__.py', 'blake3.cpython-314-x86_64-linux-gnu.so'},
             'mail_native_hash_package_inventory')
    finally:
        os.close(fd)
    for name, (size, digest) in ASSETS.items():
        raw = protected(DEPENDENCY/name, size, mode=0o444)
        need(len(raw) == size and sha(raw) == digest, 'mail_native_dependency_changed')
    if 'blake3' not in sys.modules:
        sys.path.insert(0, str(DEPENDENCY)); sys.dont_write_bytecode = True
        importlib.import_module('blake3')
    package = sys.modules['blake3']; extension = sys.modules.get('blake3.blake3')
    need(Path(package.__file__).resolve() == DEPENDENCY/'blake3/__init__.py' and extension is not None and
         Path(extension.__file__).resolve() == DEPENDENCY/'blake3/blake3.cpython-314-x86_64-linux-gnu.so',
         'mail_native_hash_module_origin')
    need(package.blake3(b'').hexdigest() == 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262' and
         package.blake3(b'abc').hexdigest() == '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
         'mail_native_hash_vectors')
    return lambda raw: package.blake3(raw).hexdigest()


def context(release):
    repo = root(release)
    sys.path.insert(0, str(repo/'lab/s14'))
    import browser_authorization as auth
    from prepare_uplink import current_uplink
    facts = auth.capture(); auth.validate_context(facts)
    trust = protected(Path('/etc/ssl/certs/ca-certificates.crt'), 2*1024**2, mode=0o644)
    return {'browser': facts, 'uplink': current_uplink(), 'dependency': DEB, 'ca_sha256': sha(trust)}


def private_batch(batch):
    need(hex_value(batch, 32), 'mail_native_batch_identity')
    return NATIVE/batch


def installed_host():
    """Authenticate the existing static boundary without replacing any byte."""
    bootstrap = json.loads(protected(STATE/'bootstrap.json', 16384))
    static = Path('/usr/local/lib/paw-vm')
    names = {'vm_release_contract.py', 'vm_release_storage.py', 'vm_release_github.py',
             'vm_release_archive.py', 'vm_operator_host.py'}
    need(set(bootstrap.get('modules', {})) == names and bootstrap.get('owner_uid') == 1000,
         'mail_native_installed_bootstrap')
    need(sha(protected(Path('/usr/local/libexec/paw-vm-operator'), 1024**2, mode=0o755)) ==
         bootstrap.get('entry_sha256'), 'mail_native_installed_entry_digest')
    for name, expected_module in bootstrap['modules'].items():
        need(sha(protected(static/name, 1024**2, mode=0o444)) == expected_module,
             'mail_native_installed_static_digest')
    sys.path.insert(0,str(static))
    host=importlib.import_module('vm_operator_host')
    for name in names:
        module=sys.modules.get(name[:-3])
        if module is not None:
            need(Path(module.__file__).resolve()==static/name,'mail_native_static_module_origin')
    return host


def scope(release, batch):
    root(release)
    value = decode(protected(private_batch(batch)/'approval.json', BUNDLE_MAX), BUNDLE_MAX)
    need(type(value) is dict and value.get('schema') == 'paw-mail-native-single-batch-v1' and
         value.get('batch_id') == batch and value.get('release_sha') == release and
         canonical(value.get('policy')) == canonical(POLICY) and
         type(value.get('expires_at')) is int and time.time() < value['expires_at'] and
         type(value.get('controller_pid')) is int and value['controller_pid'] > 1,
         'mail_native_live_scope')
    sys.path.insert(0, str(HERE.parents[2]/'lab/s14'))
    from benign_guest_validation import process_identity
    props = dict(line.split('=', 1) for line in subprocess.check_output([
        '/usr/bin/systemctl', 'show', 'paw-mail-batch-'+batch+'.service',
        '--property=MainPID,ActiveState'], text=True, timeout=5).splitlines())
    need(props == {'MainPID':str(value['controller_pid']), 'ActiveState':'active'} and
         process_identity(value['controller_pid']) == value.get('controller_identity'),
         'mail_native_controller_dead_or_revoked')
    host=installed_host()
    with host.trusted_directory(STATE) as fd:
        installed=host.private_json(fd,'policy.json');host.contract.policy(installed)
        need(host.enrollment_complete(installed) and not host.revoked(fd),
             'mail_native_operator_dead_or_revoked')
    return value


def materialize(approval, index):
    from . import mail_browser_custody as custody
    need(index == 'owned' or type(index) is int and 0 <= index < 3, 'mail_native_source_slot')
    raw = approval['owned_request_b64'] if index == 'owned' else approval['requests_b64'][index]
    selected = approval['owned_selection'] if index == 'owned' else approval['selections'][index]
    value = decode(custody.decode64(raw, custody.REQUEST_MAX), custody.REQUEST_MAX)
    created = int(time.time())
    value.update(request_id=uuid.uuid4().hex, created_at=created, expires_at=created+900)
    value = custody.validate(canonical(value), load_hasher())
    custody.require_selection(value, selected)
    return value


def _mkdir(path, mode=0o700):
    fd = root_directory(path.parent)
    try:
        os.mkdir(path.name, mode, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def _install_hash_assets(assets):
    for directory in [DEPENDENCY.parent]:
        if not directory.exists():
            _mkdir(directory, 0o755)
        fd = root_directory(directory); os.close(fd)
    if not DEPENDENCY.exists():
        _mkdir(DEPENDENCY, 0o755); _mkdir(DEPENDENCY/'blake3', 0o755)
        for name, raw in assets.items():
            atomic(DEPENDENCY/name, raw, exclusive=True, mode=0o444)
    return load_hasher()


def _owner_bundle(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1000 and before.st_nlink == 1 and
             stat.S_IMODE(before.st_mode) == 0o400 and 0 < before.st_size <= BUNDLE_MAX,
             'mail_native_owner_data_file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(BUNDLE_MAX+1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             'mail_native_bundle_changed')
    finally:
        os.close(fd)
    return validate_bundle(raw, expected)


MASTER_PROPERTIES = {'ActiveState':'active','Type':'exec','Restart':'no','KillMode':'control-group',
    'MemoryMax':str(64*1024**2),'MemorySwapMax':'0','TasksMax':'8','CPUQuotaPerSecUSec':'150ms',
    'RuntimeMaxUSec':'20min','RuntimeRandomizedExtraUSec':'0','TimeoutStopUSec':'12s',
    'NoNewPrivileges':'yes','RestrictAddressFamilies':'AF_NETLINK AF_UNIX'}


def validate_master_unit(properties, pid):
    need(type(pid) is int and pid>1 and properties=={'MainPID':str(pid),**MASTER_PROPERTIES},
         'mail_native_master_budget_or_confinement')


def master(path, expected, release, batch):
    """Single native-authenticated PID1 invocation; never a passwordless RPC."""
    repo = root(release)
    need(os.environ.get('PKEXEC_UID') == '1000' and hex_value(batch, 32),
         'mail_native_authenticated_owner_required')
    value, assets, requests = _owner_bundle(path, expected)
    need(value['batch_id'] == batch and value['release_sha'] == release, 'mail_native_bundle_binding')
    need(Path('/proc/self/attr/current').read_text().strip() == 'unconfined', 'mail_native_PID1_unconfined')
    props = dict(line.split('=', 1) for line in subprocess.check_output([
        '/usr/bin/systemctl', 'show', 'paw-mail-batch-'+batch+'.service',
        '--property=MainPID,'+','.join(MASTER_PROPERTIES)], text=True, timeout=5).splitlines())
    validate_master_unit(props,os.getpid())
    host=installed_host()
    import vm_release_storage as storage
    from benign_guest_validation import process_identity
    from . import mail_browser_custody as custody, mail_browser_owned as owned
    from . import mail_browser_public as public
    with host.trusted_directory(STATE) as state_fd, host.operation_lock(state_fd):
        active = host.active(host.private_json(state_fd, 'active.json'))
        installed = host.private_json(state_fd, 'policy.json'); host.contract.policy(installed)
        need(active['release_sha'] == release and host.enrollment_complete(installed) and
             not host.revoked(state_fd), 'mail_native_completed_operator_required')
        with host.trusted_directory(host.RELEASES) as releases_fd:
            storage.verify(releases_fd, release, active['manifest_sha256'])
        public.require_idle()
        hasher = _install_hash_assets(assets)
        selected = [custody.validate(raw, hasher) for raw in requests]
        own = custody.validate(custody.decode64(value['owned_request_b64'], custody.REQUEST_MAX), hasher)
        need(custody.decode64(own['source_b64'], custody.SOURCE_MAX) == owned.SOURCE and own['url'] == owned.SEED,
             'mail_native_compiled_owned_parent_required')
        need(len({v['source_sha256'] for v in selected}) == 3, 'mail_native_duplicate_email')
        current = context(release)
        need(canonical(current['uplink']) == canonical(value['uplink']), 'mail_native_uplink_changed')
        public.verify_baseline(value['baseline_job'], release, current)
        if not NATIVE.exists():
            _mkdir(NATIVE)
        _mkdir(private_batch(batch)); _mkdir(private_batch(batch)/'children')
        approved = {'schema':'paw-mail-native-single-batch-v1', 'batch_id':batch, 'release_sha':release,
            'controller_pid':os.getpid(), 'controller_identity':process_identity(os.getpid()),
            'approved_at':int(time.time()), 'expires_at':min(value['expires_at'],value['batch_expires_at'],int(time.time())+1200),
            'native_bundle_sha256':expected, 'policy':POLICY, 'context':current,
            'requests_b64':value['requests_b64'], 'selections':[custody.selection(v) for v in selected],
            'owned_request_b64':value['owned_request_b64'], 'owned_selection':custody.selection(own)}
        atomic(private_batch(batch)/'approval.json', canonical(approved), exclusive=True)
        try:
            return public.native_sequence(approved)
        except Exception as error:
            public.publish_status(approved,'failed',error=type(error).__name__+':'+str(error)[:512])
            raise
        finally:
            # Normal exceptions also clean up before releasing the deployment
            # lock. PID1's fixed ExecStopPost repeats this on SIGKILL/timeout.
            public.cleanup_batch(release,batch)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', action='store_true', required=True)
    parser.add_argument('--bundle', type=Path, required=True); parser.add_argument('--sha256', required=True)
    parser.add_argument('--release', required=True); parser.add_argument('--batch', required=True)
    args = parser.parse_args()
    print(json.dumps(master(args.bundle, args.sha256, args.release, args.batch)), flush=True)


if __name__ == '__main__':
    need(os.geteuid() == 0 and hex_value(HERE.parents[2].name, 40) and
         HERE == Path('/opt/paw-vm/releases')/HERE.parents[2].name/'paw/core/mail_browser_native.py',
         'mail_native_installed_snapshot_entry_required')
    sys.path[:0] = [str(HERE.parents[2]), str(HERE.parents[2]/'lab/s14')]
    __package__ = 'paw.core'
    main()
