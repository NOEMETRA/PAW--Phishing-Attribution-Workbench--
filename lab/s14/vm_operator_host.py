"""Installed root-only dispatcher: fixed state, verified snapshots, owned recipes.

This module is installed into a protected static directory, never imported from
the caller's workspace by the passwordless entrypoint. No arbitrary input paths,
commands, systemd options, real samples or grant issuance are accepted.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import uuid

import vm_release_contract as contract
import vm_release_storage as storage
import vm_release_archive as archive
from vm_release_github import GitHubClient, collect

STATE = Path('/var/lib/paw-vm')
RELEASES = Path('/opt/paw-vm/releases')
ENTRY = Path('/usr/local/libexec/paw-vm-operator')
STATIC = Path('/usr/local/lib/paw-vm')
ROOT_UID = 0
WORKER = 'lab/s14/vm_operator_worker.py'
require = contract.require


@contextmanager
def trusted_directory(path):
    """Open/check every fixed absolute ancestor without following symlinks."""
    require(isinstance(path, Path) and path.is_absolute() and '..' not in path.parts, 'operator_fixed_absolute_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        storage.directory(fd)
        for part in path.parts[1:]:
            child = storage.open_dir(fd, part); os.close(fd); fd = child
        yield fd
    finally: os.close(fd)


def private_json(fd, name):
    require(name in {'policy.json', 'active.json', 'result.json', 'enrollment-test.json'}, 'operator_state_name')
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(handle)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= contract.MAX_PROOF, 'operator_protected_state')
        with os.fdopen(handle, 'rb', closefd=False) as stream: raw = stream.read(contract.MAX_PROOF+1)
        require(len(raw) == info.st_size, 'operator_state_changed')
        value = contract.decode(raw); require(raw == storage.canonical(value), 'operator_canonical_state'); return value
    finally: os.close(handle)


def write_state(fd, name, value):
    require(name in {'active.json', 'result.json'}, 'operator_state_name')
    raw = storage.canonical(value); require(len(raw) <= contract.MAX_PROOF, 'operator_state_budget')
    temporary = '.state-'+uuid.uuid4().hex
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, 'wb', closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(handle)
    finally: os.close(handle)
    try: os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
    finally:
        try: os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError: pass


def revoked(fd):
    try: info = os.stat('revoked', dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError: return False
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'operator_revoke_marker')
    return True


def revoke(fd):
    try: handle = os.open('revoked', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    except FileExistsError: require(revoked(fd), 'operator_revoke_marker'); return
    try: os.write(handle, b'Operator revoked; new work refused.\n'); os.fsync(handle)
    finally: os.close(handle)
    os.fsync(fd)


@contextmanager
def operation_lock(fd):
    handle = os.open('operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
    try:
        info = os.fstat(handle)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'operator_lock_protection')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally: os.close(handle)


def active(value):
    contract.shape(value, {'schema', 'release_sha', 'manifest_sha256', 'pull_request'}, 'operator_active_shape')
    require(value['schema'] == 'paw-vm-active-v1' and contract.sha(value['release_sha']) and
            storage.hex64(value['manifest_sha256']) and contract.positive(value['pull_request']), 'operator_active_identity')
    return value


def credential():
    """One bounded atomic pipe frame; no TTY, file, argv, logging or persistence."""
    require(not os.isatty(0) and select.select([0], [], [], 5)[0], 'operator_api_credential_pipe_required')
    raw = os.read(0, 513)
    require(len(raw) <= 257 and raw.endswith(b'\n') and b'\n' not in raw[:-1], 'operator_api_credential_frame')
    try: token = raw[:-1].decode('ascii')
    except UnicodeError: raise ValueError('operator_api_credential_frame') from None
    return token


def enrollment_complete(installed):
    """Absence/failure is durable denial, independent of installer survival."""
    try:
        with trusted_directory(STATE/'enrollment-acceptance') as fd: value = private_json(fd, 'result.json')
    except FileNotFoundError: return False
    return (value.get('schema') == 'paw-vm-native-acceptance-v1' and value.get('result') == 'PASS' and
            value.get('release_sha') == installed['anchor_sha'] and
            value.get('completed_phases') == ['probe', 'run', 'revoke', 'restored'] and
            type(value.get('cases')) is int and value['cases'] == 9 and
            type(value.get('real_samples_executed')) is int and value['real_samples_executed'] == 0 and
            storage.hex64(value.get('protected_job_sha256')))


def enrollment_test_consumed(fd):
    try: value = os.stat('enrollment-test-consumed', dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError: return False
    require(stat.S_ISREG(value.st_mode) and value.st_uid == ROOT_UID and value.st_nlink == 1 and
            stat.S_IMODE(value.st_mode) == 0o600, 'operator_native_test_consumption_protection')
    return True


def native_test_live(grant):
    require(grant['created_at'] <= time.time() < grant['expires_at'] <= grant['created_at']+60,
            'operator_native_test_identity_or_lease')
    proc = Path('/proc')/str(grant['owner_pid'])
    try:
        fields = (proc/'stat').read_text().rsplit(')', 1)[1].split()
        alive = proc.stat().st_uid == ROOT_UID and fields[0] not in {'Z', 'X'} and fields[19] == grant['owner_start']
    except (OSError, IndexError): alive = False
    require(alive, 'operator_native_test_owner_lost')


def consume_enrollment_test(fd, current, recipe):
    """Native-armable one-use browser test, never ordinary delegated authority.

    A secret pipe frame alone is insufficient: root-private grant, live native
    owner identity, one-minute admission lease, fixed recipe/release and durable
    consumption must all agree. Owner loss after admission retains job bounds.
    """
    require(recipe == 'browser-owned-v1', 'operator_enrollment_incomplete')
    require(not enrollment_test_consumed(fd), 'operator_native_test_consumed')
    try: grant = private_json(fd, 'enrollment-test.json')
    except FileNotFoundError: raise ValueError('operator_enrollment_incomplete') from None
    contract.shape(grant, {'schema', 'release_sha', 'recipe', 'token_sha256', 'owner_pid', 'owner_start',
                           'created_at', 'expires_at'}, 'operator_native_test_shape')
    require(grant['schema'] == 'paw-vm-native-test-v1' and grant['release_sha'] == current['release_sha'] and
            grant['recipe'] == recipe and storage.hex64(grant['token_sha256']) and
            contract.positive(grant['owner_pid']) and grant['owner_pid'] > 1 and
            type(grant['owner_start']) is str and grant['owner_start'].isdigit() and
            type(grant['created_at']) is int and type(grant['expires_at']) is int,
            'operator_native_test_identity_or_lease')
    native_test_live(grant)
    require(not os.isatty(0) and select.select([0], [], [], 5)[0], 'operator_native_test_pipe_required')
    raw = os.read(0, 66)
    require(len(raw) == 65 and raw[-1:] == b'\n' and re.fullmatch(b'[0-9a-f]{64}', raw[:-1]) and
            hashlib.sha256(raw[:-1]).hexdigest() == grant['token_sha256'], 'operator_native_test_authorization_required')
    # Waiting for a pipe frame is not admission: observe owner/lease again
    # immediately before, and after, durable one-use consumption.
    native_test_live(grant)
    require(not revoked(fd), 'operator_revoked_before_native_test')
    marker = os.open('enrollment-test-consumed', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try: os.write(marker, b'Native browser acceptance test consumed.\n'); os.fsync(marker)
    finally: os.close(marker)
    os.fsync(fd)
    native_test_live(grant)


def promote(fd, installed, current, number):
    # Authority comes from fixed HTTPS queries, never caller-supplied proof JSON.
    enrolled = dict(installed, anchor_sha=current['release_sha'])
    client = GitHubClient(credential()); proof = collect(client, number, enrolled)
    files = archive.sources(archive.fetch(proof['merge_sha']), proof['merge_sha'])
    tree_sha = archive.verify_git_tree(client, proof, files)
    require(WORKER in files, 'operator_reviewed_worker_missing')
    fresh = collect(client, number, enrolled)
    require(fresh == proof and not revoked(fd), 'operator_release_proof_changed_or_revoked')
    with trusted_directory(RELEASES) as parent:
        digest = archive.stage(parent, proof, files)
        storage.verify(parent, proof['merge_sha'], digest)
    require(not revoked(fd), 'operator_revoked_before_activation')
    value = {'schema': 'paw-vm-active-v1', 'release_sha': proof['merge_sha'],
             'manifest_sha256': digest, 'pull_request': number}
    write_state(fd, 'active.json', value)
    return {'status': 'promoted', **value, 'git_tree': tree_sha}


def worker_command(release_sha, recipe, job):
    require(contract.sha(release_sha) and type(recipe) is str and recipe in contract.RECIPES and
            type(job) is str and len(job) == 32 and all(v in '0123456789abcdef' for v in job), 'operator_fixed_worker_arguments')
    return ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=paw-vm-owned-'+job,
            '--property=Type=exec', '--property=RuntimeMaxSec=1800', '--property=MemoryMax=512M',
            '--property=MemorySwapMax=0', '--property=TasksMax=64', '--property=TimeoutStopSec=20',
            '--property=CPUQuota=100%',
            '--property=LimitCORE=0', '--property=IPAddressDeny=any', '--property=WorkingDirectory=/var/lib/paw-vm',
            '/usr/bin/python3', '-I', '-B', str(RELEASES/release_sha/WORKER), '--recipe', recipe, '--job', job]


def run_owned(fd, current, recipe):
    with trusted_directory(RELEASES) as parent:
        value, proof = storage.verify(parent, current['release_sha'], current['manifest_sha256'])
    require(WORKER in value['files'], 'operator_reviewed_worker_missing')
    job = uuid.uuid4().hex; jobs = STATE/'jobs'
    with trusted_directory(jobs) as parent: os.mkdir(job, mode=0o700, dir_fd=parent)
    require(not revoked(fd), 'operator_revoked_before_run')
    # Stream bounded worker progress instead of buffering an entire journal.
    completed = subprocess.run(worker_command(current['release_sha'], recipe, job), timeout=1840, check=False)
    with trusted_directory(jobs/job) as result_fd: result = private_json(result_fd, 'result.json')
    require(completed.returncode == 0 and result.get('result') == 'PASS' and
            result.get('job') == job and result.get('recipe') == recipe and
            result.get('release_sha') == current['release_sha'] and
            type(result.get('real_samples_executed')) is int and result['real_samples_executed'] == 0,
            'operator_owned_job_failed')
    with trusted_directory(RELEASES) as parent: storage.verify(parent, current['release_sha'], current['manifest_sha256'])
    return {'status': 'completed', 'job': job, 'recipe': recipe, 'result': 'PASS', 'real_samples_executed': 0}


def main(argv, caller_uid):
    require(os.geteuid() == 0, 'root_operator_required'); verb, parameter = contract.command(argv)
    with trusted_directory(STATE) as fd:
        installed = private_json(fd, 'policy.json')
        # Expiry does not prevent status or permission-reducing revocation.
        contract.policy(installed, now=installed.get('created_at'))
        require(type(caller_uid) is int and caller_uid == installed['owner_uid'], 'operator_wrong_caller')
        if verb == 'revoke': revoke(fd); return {'status': 'revoked', 'accepted_jobs_remain_bounded': True}
        current = active(private_json(fd, 'active.json'))
        if verb == 'status':
            complete = enrollment_complete(installed)
            return {'status': 'revoked' if revoked(fd) else ('enrolled' if complete else 'enrollment_incomplete'),
                    'enrollment_complete': complete, 'expires_at': installed['expires_at'],
                    'lease_valid': installed['created_at'] <= time.time() < installed['expires_at'], **current}
        contract.policy(installed); require(not revoked(fd), 'operator_revoked')
        with operation_lock(fd):
            current = active(private_json(fd, 'active.json'))
            require(not revoked(fd), 'operator_revoked')
            if not enrollment_complete(installed):
                require(verb == 'run', 'operator_enrollment_incomplete')
                consume_enrollment_test(fd, current, parameter)
            if verb == 'promote': return promote(fd, installed, current, parameter)
            require(verb == 'run', 'operator_unknown_command'); return run_owned(fd, current, parameter)
