"""Root-owned synthetic-only I08 freeze and global, durable one-use grants.

No sample is evaluated here. Possession of an unprivileged JSON frame is not
execution authority. Production paths are fixed and walked without symlinks.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import re

from offline_candidate import canonical, decode, inspect_candidate, require
from owned_grant_fixtures import SOURCES

ROOT = Path('/var/lib/paw-s14/authorization-v1')
OWNER_UID = 0
IMAGE_SHA256 = 'b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658'
SCOPE = 'owned-synthetic-offline-python-only'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted(info, directory=False):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
            info.st_uid == OWNER_UID and not info.st_mode & 0o022, 'untrusted_authority_storage')


@contextlib.contextmanager
def root_directory(path=ROOT):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        trusted(os.fstat(fd), True)
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: trusted(os.fstat(child), True)
            except BaseException: os.close(child); raise
            os.close(fd); fd = child
        yield fd
    finally:
        os.close(fd)


def read(fd, name, limit=65536):
    require(Path(name).name == name and name not in {'.', '..'}, 'authority_name')
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(child); trusted(before)
        require(before.st_size <= limit, 'authority_file_budget')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(child, min(8192, limit + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        after = os.fstat(child)
        require(len(data) <= limit and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'authority_changed_or_budget')
        return bytes(data)
    finally:
        os.close(child)


def exclusive(fd, name, raw):
    require(Path(name).name == name and name not in {'.', '..'}, 'authority_name')
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=fd)
    with os.fdopen(child, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.fsync(fd)


@contextlib.contextmanager
def subdirectory(fd, name):
    try: os.mkdir(name, mode=0o700, dir_fd=fd); os.fsync(fd)
    except FileExistsError: pass
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        trusted(os.fstat(child), True)
        yield child
    finally:
        os.close(child)


def validate_policy(policy, context, now=None):
    now = time.time() if now is None else now
    require(type(policy) is dict and set(policy) == {'schema', 'scope', 'context', 'created_at', 'expires_at',
            'maintenance_disposition', 'hostile_code_authorized'}, 'policy_shape')
    require(policy['schema'] == 'paw-s14-i08-freeze-v1' and policy['scope'] == SCOPE and
            policy['hostile_code_authorized'] is False, 'policy_scope')
    require(type(policy['created_at']) is int and type(policy['expires_at']) is int and
            policy['created_at'] <= now < policy['expires_at'] <= policy['created_at'] + 86400, 'policy_clock')
    require(policy['maintenance_disposition'] == 'synthetic-validation-only-no-hostile-acceptance', 'maintenance_scope')
    require(type(context) is dict and set(context) == {'kernel', 'packages', 'image_sha256', 'guard_fingerprint',
            'source_hashes', 'smt_active', 'apparmor_enabled', 'slice', 'mitigations', 'mitigation_cmdline'}, 'context_shape')
    require(type(context['kernel']) is str and 0 < len(context['kernel']) <= 128 and
            type(context['packages']) is dict and set(context['packages']) ==
            {'qemu-system-x86', 'libvirt-daemon-system', 'intel-microcode'} and
            all(type(v) is str and 0 < len(v) <= 128 for v in context['packages'].values()), 'context_versions')
    manifest = context['source_hashes']
    require(type(manifest) is dict and 63 <= len(manifest) <= 128 and
            {'one_use_authorization.py', 'granted_offline_adapter.py', 'i08_context.py', 'owned_grant_fixtures.py'} <= manifest.keys() and
            all(type(k) is str and Path(k).name == k and k not in {'.', '..'} and type(v) is str and
                re.fullmatch('[0-9a-f]{64}', v) for k, v in manifest.items()), 'context_sources')
    states = context['mitigations']
    require(type(states) is dict and {'gather_data_sampling', 'l1tf', 'mds', 'spectre_v1', 'spectre_v2', 'meltdown'} <= states.keys() and
            all(type(k) is str and type(v) is str and v.startswith(('Mitigation:', 'Not affected', 'KVM: Mitigation:'))
                for k, v in states.items()), 'unmitigated_host_state')
    command = context['mitigation_cmdline']
    require(type(command) is list and all(type(v) is str for v in command) and
            not {'mitigations=off', 'gather_data_sampling=off', 'l1tf=off'}.intersection(command), 'unsafe_mitigation_cmdline')
    if states['gather_data_sampling'] == 'Mitigation: AVX disabled, no microcode':
        require('gather_data_sampling=force' in command or 'clearcpuid=avx' in command, 'gds_fallback_policy')
    require(policy['context'] == context, 'effective_context_changed')
    require(context['image_sha256'] == IMAGE_SHA256 and context['smt_active'] == '0' and
            context['apparmor_enabled'] == 'Y' and type(context['guard_fingerprint']) is str and
            re.fullmatch('[0-9a-f]{64}',context['guard_fingerprint']) and
            context['slice'] == {'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128'}, 'platform_admission')
    return policy


def make_policy(context, now=None):
    now = int(time.time()) if now is None else now
    value = {'schema': 'paw-s14-i08-freeze-v1', 'scope': SCOPE, 'context': context,
             'created_at': now, 'expires_at': now + 86400,
             'maintenance_disposition': 'synthetic-validation-only-no-hostile-acceptance', 'hostile_code_authorized': False}
    validate_policy(value, context, now=now)
    return value


def validate_binding(raw, grant, policy_raw, context, now=None):
    summary = inspect_candidate(raw, now=now); value = decode(raw)
    policy = validate_policy(json.loads(policy_raw), context, now=now)
    require(type(grant) is dict and set(grant) == {'schema', 'scope', 'request_id', 'frame_sha256', 'candidate_sha256',
            'source_sha256', 'case_reference_sha256', 'policy_sha256', 'created_at', 'expires_at'}, 'grant_shape')
    require(grant['schema'] == 'paw-s14-one-use-grant-v1' and grant['scope'] == SCOPE, 'grant_scope')
    for key in ['request_id', 'frame_sha256', 'candidate_sha256', 'source_sha256', 'case_reference_sha256']:
        require(grant[key] == summary[key], 'grant_binding:' + key)
    require(grant['policy_sha256'] == digest(policy_raw), 'grant_policy_binding')
    now = time.time() if now is None else now
    require(type(grant['created_at']) is int and type(grant['expires_at']) is int and
            value['created_at'] <= grant['created_at'] <= now < grant['expires_at'] <=
            min(value['expires_at'], policy['expires_at'], grant['created_at'] + 900), 'grant_clock')
    source = bytes.fromhex(value['source']['data_hex'])
    require(source in SOURCES.values(), 'owned_synthetic_sources_only')
    return summary, value, source


def policy_name(raw):
    return 'policy-' + digest(raw) + '.json'


def issue(raw, policy_raw, context, now=None):
    require(os.geteuid() == 0, 'root_operator_required')
    now = int(time.time()) if now is None else now
    summary = inspect_candidate(raw, now=now); value = decode(raw); policy = validate_policy(json.loads(policy_raw), context, now=now)
    grant = {'schema': 'paw-s14-one-use-grant-v1', 'scope': SCOPE,
             **{key: summary[key] for key in ['request_id', 'frame_sha256', 'candidate_sha256', 'source_sha256', 'case_reference_sha256']},
             'policy_sha256': digest(policy_raw), 'created_at': now, 'expires_at': min(now + 900, value['expires_at'], policy['expires_at'])}
    validate_binding(raw, grant, policy_raw, context, now=now)
    with root_directory() as fd:
        require(read(fd, policy_name(policy_raw)) == policy_raw, 'policy_not_installed')
        with subdirectory(fd, 'grants') as grants:
            exclusive(grants, summary['request_id'] + '.json', canonical(grant))
    return grant


def load_bound(raw, policy_raw, context, now=None):
    summary = inspect_candidate(raw, now=now)
    with root_directory() as fd:
        require(read(fd, policy_name(policy_raw)) == policy_raw, 'policy_changed')
        with subdirectory(fd, 'grants') as grants:
            grant_raw = read(grants, summary['request_id'] + '.json', 4096)
    grant = json.loads(grant_raw)
    summary, value, source = validate_binding(raw, grant, policy_raw, context, now=now)
    return grant_raw, summary, value, source


def consume(raw, policy_raw, context, now=None):
    require(os.geteuid() == 0, 'root_operator_required')
    grant_raw, summary, value, source = load_bound(raw, policy_raw, context, now=now)
    ledger = {'schema': 'paw-s14-consumed-grant-v1', 'request_id': summary['request_id'],
              'grant_sha256': digest(grant_raw), 'frame_sha256': digest(raw),
              'policy_sha256': digest(policy_raw), 'consumed_at': int(time.time()) if now is None else now,
              'meaning': 'consumed before VM creation, including any subsequent failure'}
    with root_directory() as fd:
        with subdirectory(fd, 'consumed') as consumed:
            exclusive(consumed, summary['request_id'] + '.json', canonical(ledger))
    return ledger, grant_raw, summary, value, source


def confirm_consumed(ledger):
    with root_directory() as fd:
        with subdirectory(fd, 'consumed') as consumed:
            require(read(consumed, ledger['request_id'] + '.json', 4096) == canonical(ledger), 'consumption_ledger_changed')


@contextlib.contextmanager
def execution_lock():
    import fcntl
    with root_directory() as fd:
        child = os.open('execution.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        try:
            trusted(os.fstat(child))
            fcntl.flock(child, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(child)
