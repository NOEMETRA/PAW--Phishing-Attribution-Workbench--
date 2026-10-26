"""Native-admin-only initial enrollment from a digest-approved source bundle.

No imports from the workspace: approved bootstrap modules are copied into a
root-private temporary directory before import. The passwordless entrypoint
does not expose this installer. No login/API credential is stored in the bundle.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

REPOSITORY = 'NOEMETRA/PAW--Phishing-Attribution-Workbench--'
MODULES = frozenset({'vm_release_contract.py', 'vm_release_storage.py', 'vm_release_github.py',
                     'vm_release_archive.py', 'vm_operator_host.py'})
ENTRY_SOURCE = 'lab/s14/vm_operator_entry.py'
WORKER_SOURCE = 'lab/s14/vm_operator_worker.py'
INSTALLER_SOURCE = 'lab/s14/vm_operator_install.py'
EXPORTS = Path('/var/lib/paw-vm-exports')
MAX_TOTAL = 32 * 1024**2
MAX_BUNDLE = 2*MAX_TOTAL + 2*1024**2
ACTION_ID = 'org.noemetra.paw.vm.operator'
POLICY_FILE = Path('/usr/share/polkit-1/actions/'+ACTION_ID+'.policy')
RULE_FILE = Path('/etc/polkit-1/rules.d/49-paw-vm-operator.rules')
ROOT_UID = 0

# Executed by fixed system Python as the enrolled *unprivileged* account. No
# arguments select commands/paths/code; phases are native enrollment tests only.
CLIENT = r'''
import json,os,subprocess,sys
ENTRY='/usr/local/libexec/paw-vm-operator'
def need(value, reason):
    if not value: raise ValueError(reason)
def call(argv, expected=0, reason=None):
    p=subprocess.run(['/usr/bin/pkexec','--disable-internal-agent',ENTRY,*argv],capture_output=True,text=True,timeout=20)
    need(p.returncode==expected,'enrollment_client_returncode:'+str(argv))
    need(len(p.stdout)+len(p.stderr)<=65536,'enrollment_client_output_budget')
    if reason: need(reason in p.stderr,'enrollment_client_refusal_reason')
    return json.loads(p.stdout) if expected==0 else None
need(os.getuid()==os.geteuid()==1000,'enrollment_client_not_unprivileged')
phase=sys.argv[1]
if phase=='probe':
    need(call(['status'])['status']=='enrollment_incomplete','enrollment_initial_status')
    call(['unknown-command'],expected=1,reason='operator_unknown_command')
    call(['run','/tmp/untrusted.py'],expected=1,reason='operator_unknown_recipe')
    call(['run','browser-owned-v1'],expected=1,reason='operator_enrollment_incomplete')
    for path in [ENTRY,'/usr/local/lib/paw-vm','/var/lib/paw-vm','/opt/paw-vm/releases']:
        need(not os.access(path,os.W_OK),'enrollment_user_writable_privileged_path')
    need(not os.access('/var/lib/paw-vm',os.R_OK),'enrollment_user_readable_private_state')
elif phase=='run':
    nonce=sys.stdin.buffer.read(66)
    need(len(nonce)==65 and nonce[-1:]==b'\n','enrollment_one_use_pipe_frame')
    # Stream to the root-owned bounded log, not an unbounded memory buffer.
    p=subprocess.run(['/usr/bin/pkexec','--disable-internal-agent',ENTRY,'run','browser-owned-v1'],input=nonce,timeout=1860)
    need(p.returncode==0,'enrollment_owned_job_failed')
    call(['run','browser-owned-v1'],expected=1,reason='operator_native_test_consumed')
elif phase=='revoke':
    need(call(['revoke'])['status']=='revoked','enrollment_revoke_failed')
    need(call(['status'])['status']=='revoked','enrollment_revoked_status')
    call(['run','browser-owned-v1'],expected=1,reason='operator_revoked')
elif phase=='restored':
    need(call(['status'])['status']=='enrollment_incomplete','enrollment_native_restore_failed')
elif phase=='accepted':
    need(call(['status'])['status']=='enrolled','enrollment_completed_status_failed')
else: raise ValueError('enrollment_unknown_phase')
print(json.dumps({'phase':phase,'result':'PASS','uid':os.getuid()}),flush=True)
'''


def require(value, reason):
    if not value: raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def path_parts(name):
    require(type(name) is str and 0 < len(name) <= 240 and '\\' not in name, 'native_source_path')
    value = PurePosixPath(name)
    require(not value.is_absolute() and value.as_posix() == name and '..' not in value.parts and
            (re.fullmatch(r'paw/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.py', name) or
             re.fullmatch(r'lab/s14/[A-Za-z0-9_.-]+\.(?:py|nft|xml|service|conf|slice)', name)), 'native_source_path')
    return value.parts


def bundle(raw, expected_sha256, now=None):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BUNDLE and
            re.fullmatch('[0-9a-f]{64}', expected_sha256 or '') and
            hashlib.sha256(raw).hexdigest() == expected_sha256, 'native_approved_bundle_digest')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'native_bundle_duplicate'); result[key] = value
        return result
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, RecursionError, json.JSONDecodeError): raise ValueError('native_bundle_json') from None
    base_fields = {'schema', 'repository', 'owner_uid', 'head_sha', 'pull_request',
                   'created_at', 'expires_at', 'policy', 'files'}
    require(type(value) is dict and
            ((value.get('schema') == 'paw-vm-native-bundle-v1' and set(value) == base_fields) or
             (value.get('schema') == 'paw-vm-native-bundle-v2' and set(value) == base_fields | {'repair_from'})) and
            value['repository'] == REPOSITORY and type(value['owner_uid']) is int and value['owner_uid'] == 1000 and
            type(value['head_sha']) is str and re.fullmatch('[0-9a-f]{40}', value['head_sha']) and
            type(value['pull_request']) is int and 0 < value['pull_request'] <= 999999999, 'native_bundle_identity')
    now = time.time() if now is None else now
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at']+3600,
            'native_bundle_lease')
    if value.get('repair_from') is not None:
        previous = value['repair_from']
        require(type(previous) is dict and set(previous) == {'release_sha', 'manifest_sha256'} and
                type(previous['release_sha']) is str and re.fullmatch('[0-9a-f]{40}', previous['release_sha']) and
                type(previous['manifest_sha256']) is str and re.fullmatch('[0-9a-f]{64}', previous['manifest_sha256']) and
                previous['release_sha'] != value['head_sha'], 'native_repair_previous_identity')
    require(type(value['policy']) is dict and type(value['files']) is dict and 1 <= len(value['files']) <= 2048,
            'native_bundle_inventory')
    files = {}; total = 0
    for name, item in value['files'].items():
        path_parts(name)
        require(type(item) is dict and set(item) == {'bytes', 'sha256', 'data_hex'} and
                type(item['bytes']) is int and 0 <= item['bytes'] <= 1024**2 and
                type(item['data_hex']) is str and len(item['data_hex']) == 2*item['bytes'] and
                re.fullmatch('[0-9a-f]*', item['data_hex']) and type(item['sha256']) is str,
                'native_bundle_source_shape')
        total += item['bytes']; require(total <= MAX_TOTAL, 'native_bundle_source_budget')
        data = bytes.fromhex(item['data_hex'])
        require(hashlib.sha256(data).hexdigest() == item['sha256'], 'native_bundle_source_digest'); files[name] = data
    required = {ENTRY_SOURCE, WORKER_SOURCE, INSTALLER_SOURCE, *{'lab/s14/'+name for name in MODULES}}
    require(required <= set(files) and raw == canonical(value), 'native_bundle_required_sources_or_canonical')
    return {k: v for k, v in value.items() if k != 'files'}, files


def approved_file(path, expected):
    # Reading this data path is native-admin authorized, never a passwordless RPC.
    require(isinstance(path, Path) and not str(path).startswith('//'), 'native_local_bundle_required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BUNDLE, 'native_bundle_regular_budget')
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(MAX_BUNDLE+1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and before.st_size == after.st_size and
                before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns, 'native_bundle_changed')
        return bundle(raw, expected)
    finally: os.close(fd)


def polkit_configuration(username, entry):
    require(type(username) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', username), 'native_enrolled_username')
    require(entry == Path('/usr/local/libexec/paw-vm-operator'), 'native_fixed_entrypoint')
    policy = ('<?xml version="1.0" encoding="UTF-8"?>\n<policyconfig>\n'
              '<action id="'+ACTION_ID+'"><description>Run reviewed finite PAW VM operations</description>'
              '<message>Authorize the bounded PAW VM operator</message>'
              '<defaults><allow_any>auth_admin</allow_any><allow_inactive>auth_admin</allow_inactive>'
              '<allow_active>auth_admin</allow_active></defaults>'
              '<annotate key="org.freedesktop.policykit.exec.path">'+str(entry)+'</annotate></action>\n</policyconfig>\n')
    rule = ('polkit.addRule(function(action, subject) {\n'
            '  if (action.id === '+json.dumps(ACTION_ID)+' && action.lookup("program") === '+json.dumps(str(entry))+
            ' && action.lookup("user") === "root" && subject.user === '+json.dumps(username)+') {\n'
            '    return polkit.Result.YES;\n  }\n});\n')
    return policy.encode(), rule.encode()


def install_layout(host, storage, archive, meta, files, proof):
    """Native-only transaction; constants are installed paths, never caller roots."""
    require(os.geteuid() == 0, 'native_root_installer_required')
    forbidden = [host.ENTRY, host.STATIC, POLICY_FILE, RULE_FILE, host.STATE/'bootstrap.json',
                 host.STATE/'policy.json', host.STATE/'active.json']
    require(all(not path.exists() and not path.is_symlink() for path in forbidden), 'native_existing_operator_refused')
    created_dirs = []; created_files = []; release_created = False
    def ensure(path, mode=0o755):
        try:
            with host.trusted_directory(path) as fd:
                require(mode != 0o700 or stat.S_IMODE(os.fstat(fd).st_mode) == mode, 'native_existing_private_directory_mode')
        except FileNotFoundError:
            ensure(path.parent)
            with host.trusted_directory(path.parent) as fd: os.mkdir(path.name, mode=mode, dir_fd=fd)
            created_dirs.append(path)
    def write(path, data, mode):
        with host.trusted_directory(path.parent) as parent:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            created_files.append(path)
            try:
                with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(data); stream.flush(); os.fsync(fd)
                os.fchmod(fd, mode)
            finally: os.close(fd)
            os.fsync(parent)
    release_path = host.RELEASES/meta['head_sha']
    try:
        for path, mode in [(host.STATE, 0o700), (host.STATE/'jobs', 0o700),
                           (EXPORTS, 0o755), (host.RELEASES, 0o755),
                           (host.ENTRY.parent, 0o755), (host.STATIC, 0o755),
                           (POLICY_FILE.parent, 0o755), (RULE_FILE.parent, 0o755)]: ensure(path, mode)
        require(not release_path.exists() and not release_path.is_symlink(), 'native_existing_initial_snapshot_refused')
        # Record responsibility before stage(), which can fail after its rename.
        release_created = True
        with host.trusted_directory(host.RELEASES) as parent:
            digest = archive.stage(parent, proof, files)
            storage.verify(parent, meta['head_sha'], digest)
        for name in MODULES: write(host.STATIC/name, files['lab/s14/'+name], 0o444)
        write(host.ENTRY, files[ENTRY_SOURCE], 0o755)
        bootstrap = {'schema': 'paw-vm-bootstrap-v1', 'owner_uid': meta['owner_uid'],
                     'entry_sha256': hashlib.sha256(files[ENTRY_SOURCE]).hexdigest(),
                     'modules': {name: hashlib.sha256(files['lab/s14/'+name]).hexdigest() for name in MODULES}}
        active = {'schema': 'paw-vm-active-v1', 'release_sha': meta['head_sha'], 'manifest_sha256': digest,
                  'pull_request': meta['pull_request']}
        for name, value in [('bootstrap.json', bootstrap), ('policy.json', meta['policy']), ('active.json', active)]:
            write(host.STATE/name, canonical(value), 0o600)
        # Self-check before adding any no-prompt authorization.
        result = subprocess.run([str(host.ENTRY), 'status'], capture_output=True, text=True, timeout=20,
            env={'PKEXEC_UID': str(meta['owner_uid']), 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'})
        require(result.returncode == 0 and json.loads(result.stdout)['status'] == 'enrollment_incomplete', 'native_installed_selfcheck_failed')
        username = pwd.getpwuid(meta['owner_uid']).pw_name
        policy_data, rule_data = polkit_configuration(username, host.ENTRY)
        write(POLICY_FILE, policy_data, 0o644); write(RULE_FILE, rule_data, 0o644)
        return {'result': 'INSTALLED_NOT_RUNTIME_ACCEPTED', 'release_sha': meta['head_sha'],
                'manifest_sha256': digest, 'owner_uid': meta['owner_uid'], 'rule': str(RULE_FILE)}
    except BaseException:
        # Permission is removed first; delete only artifacts made by this transaction.
        for path in [RULE_FILE, POLICY_FILE, *reversed(created_files)]:
            if path in created_files:
                try: path.unlink()
                except FileNotFoundError: pass
        if release_created and release_path.exists(): shutil.rmtree(release_path)
        for path in reversed(created_dirs):
            try: path.rmdir()
            except OSError: pass
        raise


def protected_file(host, path, mode, maximum=1024**2):
    with host.trusted_directory(path.parent) as fd:
        handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(handle)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == ROOT_UID and before.st_nlink == 1 and
                stat.S_IMODE(before.st_mode) == mode and before.st_size <= maximum, 'native_repair_protected_file')
        with os.fdopen(handle, 'rb', closefd=False) as stream: raw = stream.read(maximum+1)
        after = os.fstat(handle)
        require(len(raw) == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns and
                before.st_ctime_ns == after.st_ctime_ns, 'native_repair_protected_file_changed')
        return raw
    finally: os.close(handle)


def root_create(host, path, raw, mode=0o600):
    with host.trusted_directory(path.parent) as fd:
        handle = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(handle, 'wb', closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(handle)
            os.fchmod(handle, mode); os.fsync(handle)
        finally: os.close(handle)
        os.fsync(fd)


def native_replace(host, path, value):
    require(path.parent == host.STATE and path.name in {'policy.json', 'active.json'}, 'native_repair_fixed_state')
    temporary = path.with_name('.native-state-'+os.urandom(16).hex())
    root_create(host, temporary, canonical(value))
    with host.trusted_directory(host.STATE) as fd:
        try: os.replace(temporary.name, path.name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
        finally:
            try: os.unlink(temporary.name, dir_fd=fd)
            except FileNotFoundError: pass


def require_idle(current_unit):
    require(type(current_unit) is str and re.fullmatch('paw-vm-enroll-[0-9a-f]{12}\\.service', current_unit),
            'native_repair_fixed_unit')
    main = subprocess.check_output(['/usr/bin/systemctl', 'show', current_unit, '--property=MainPID', '--value'], text=True, timeout=10)
    require(main.strip() == str(os.getpid()), 'native_repair_PID1_main_process_required')
    qemu = subprocess.run(['/usr/bin/pgrep', '-f', '^/usr/bin/qemu-system'], capture_output=True, timeout=10)
    domains = subprocess.check_output(['/usr/bin/virsh', '--readonly', '-c', 'qemu:///system', 'list', '--all', '--name'], text=True, timeout=15)
    namespaces = subprocess.check_output(['/usr/sbin/ip', 'netns', 'list'], text=True, timeout=10)
    units = subprocess.check_output(['/usr/bin/systemctl', 'list-units', '--type=service', '--state=activating,active,deactivating',
                                     '--no-legend', '--no-pager', '--plain', 'paw-vm-owned-*', 'paw-vm-enroll-*'], text=True, timeout=10)
    other = [line.split()[0] for line in units.splitlines() if line.strip() and line.split()[0] != current_unit]
    require(qemu.returncode == 1 and not domains.strip() and not namespaces.strip() and not other,
            'native_repair_live_job_or_residual')


def repair_layout(host, storage, archive, contract, meta, files, proof):
    """Native-only recovery of failed/incomplete enrollment, not self-promotion.

    Static boundary upgrades are deliberately excluded: installed entry/modules
    must exactly match this newly reviewed bundle. Preserve old snapshots and
    all authority/log files; ordinary authority remains incomplete throughout.
    """
    require(os.geteuid() == 0 and meta.get('repair_from') is not None, 'native_explicit_repair_required')
    previous = meta['repair_from']; current_unit = 'paw-vm-enroll-'+meta['head_sha'][:12]+'.service'; require_idle(current_unit)
    expected_bootstrap = {'schema': 'paw-vm-bootstrap-v1', 'owner_uid': meta['owner_uid'],
        'entry_sha256': hashlib.sha256(files[ENTRY_SOURCE]).hexdigest(),
        'modules': {name: hashlib.sha256(files['lab/s14/'+name]).hexdigest() for name in MODULES}}
    require(protected_file(host, host.STATE/'bootstrap.json', 0o600, 16384) == canonical(expected_bootstrap),
            'native_repair_static_upgrade_requires_separate_enrollment')
    require(hashlib.sha256(protected_file(host, host.ENTRY, 0o755)).hexdigest() == expected_bootstrap['entry_sha256'],
            'native_repair_entry_changed')
    with host.trusted_directory(host.STATIC) as fd: require(set(os.listdir(fd)) == MODULES, 'native_repair_static_inventory')
    for name in MODULES:
        require(hashlib.sha256(protected_file(host, host.STATIC/name, 0o444)).hexdigest() == expected_bootstrap['modules'][name],
                'native_repair_static_module_changed')
    username = pwd.getpwuid(meta['owner_uid']).pw_name
    policy_data, rule_data = polkit_configuration(username, host.ENTRY)
    require(protected_file(host, POLICY_FILE, 0o644) == policy_data, 'native_repair_action_changed')
    with host.trusted_directory(host.STATE) as fd, host.operation_lock(fd):
        current = host.active(host.private_json(fd, 'active.json')); old_policy = host.private_json(fd, 'policy.json')
        contract.policy(old_policy, now=old_policy.get('created_at'))
        require(current['release_sha'] == previous['release_sha'] and current['manifest_sha256'] == previous['manifest_sha256'] and
                current['pull_request'] == meta['pull_request'] and old_policy['anchor_sha'] == previous['release_sha'] and
                all(old_policy[k] == meta['policy'][k] for k in ['repository', 'owner_uid', 'reviewer_login', 'reviewer_id', 'workflows']),
                'native_repair_protected_previous_identity')
        try:
            with host.trusted_directory(host.STATE/'enrollment-acceptance') as accepted:
                prior = host.private_json(accepted, 'result.json')
        except FileNotFoundError: prior = None
        require(prior is None or (prior.get('schema') == 'paw-vm-native-acceptance-v1' and prior.get('result') == 'FAIL' and
                prior.get('release_sha') == previous['release_sha'] and type(prior.get('real_samples_executed')) is int and
                prior['real_samples_executed'] == 0), 'native_repair_only_failed_or_incomplete_enrollment')
        try: old_grant = host.private_json(fd, 'enrollment-test.json')
        except FileNotFoundError: old_grant = None
        if old_grant is not None:
            pid = old_grant.get('owner_pid'); start = old_grant.get('owner_start')
            require(type(pid) is int and pid > 1 and type(start) is str and start.isdigit(), 'native_repair_prior_owner_shape')
            proc = Path('/proc')/str(pid)
            try:
                fields = (proc/'stat').read_text().rsplit(')', 1)[1].split()
                alive = proc.stat().st_uid == ROOT_UID and fields[0] not in {'Z', 'X'} and fields[19] == start
            except (OSError, IndexError): alive = False
            require(not alive, 'native_repair_previous_owner_active')
        with host.trusted_directory(host.RELEASES) as releases:
            storage.verify(releases, previous['release_sha'], previous['manifest_sha256'])
        # Remove delegated permission first. Repaired ordinary authority cannot
        # exist until the new protected acceptance receipt has been written.
        if RULE_FILE.exists() or RULE_FILE.is_symlink():
            require(protected_file(host, RULE_FILE, 0o644) == rule_data, 'native_repair_rule_changed')
            with host.trusted_directory(RULE_FILE.parent) as rules: os.unlink(RULE_FILE.name, dir_fd=rules); os.fsync(rules)
        host.revoke(fd)
        try:
            history_root = host.STATE/'enrollment-history'
            try: os.mkdir(history_root.name, mode=0o700, dir_fd=fd)
            except FileExistsError: pass
            with host.trusted_directory(history_root) as histories:
                name = 'repair-'+os.urandom(16).hex(); os.mkdir(name, mode=0o700, dir_fd=histories)
            history = history_root/name
            for name, raw in [('policy.json', canonical(old_policy)), ('active.json', canonical(current)),
                              ('bootstrap.json', canonical(expected_bootstrap))]: root_create(host, history/name, raw)
            with host.trusted_directory(history) as saved:
                for name in ['enrollment-acceptance', 'enrollment-test.json', 'enrollment-test-consumed']:
                    try: info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError: continue
                    require(info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0 and
                            ((name == 'enrollment-acceptance' and stat.S_ISDIR(info.st_mode)) or
                             (name != 'enrollment-acceptance' and stat.S_ISREG(info.st_mode) and info.st_nlink == 1)),
                            'native_repair_history_artifact')
                    os.rename(name, name, src_dir_fd=fd, dst_dir_fd=saved)
                os.fsync(saved); os.fsync(fd)
            require_idle(current_unit)
            with host.trusted_directory(host.RELEASES) as releases:
                digest = archive.stage(releases, proof, files); storage.verify(releases, meta['head_sha'], digest)
            active = {'schema': 'paw-vm-active-v1', 'release_sha': meta['head_sha'], 'manifest_sha256': digest,
                      'pull_request': meta['pull_request']}
            native_replace(host, host.STATE/'policy.json', meta['policy']); host.write_state(fd, 'active.json', active)
            result = subprocess.run([str(host.ENTRY), 'status'], capture_output=True, text=True, timeout=20,
                env={'PKEXEC_UID': str(meta['owner_uid']), 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'})
            require(result.returncode == 0 and json.loads(result.stdout)['status'] == 'revoked' and
                    json.loads(result.stdout)['enrollment_complete'] is False, 'native_repair_incomplete_selfcheck')
            require(host.revoked(fd), 'native_repair_revoke_marker')
            # Only this native batch may restore the incomplete test context.
            with host.trusted_directory(history) as saved:
                os.rename('revoked', 'revoked', src_dir_fd=fd, dst_dir_fd=saved); os.fsync(saved); os.fsync(fd)
            root_create(host, RULE_FILE, rule_data, 0o644)
            return {'result': 'REPAIRED_NOT_RUNTIME_ACCEPTED', 'release_sha': meta['head_sha'],
                    'manifest_sha256': digest, 'owner_uid': meta['owner_uid'], 'history': str(history)}
        except BaseException:
            with host.trusted_directory(RULE_FILE.parent) as rules:
                try: os.unlink(RULE_FILE.name, dir_fd=rules); os.fsync(rules)
                except FileNotFoundError: pass
            host.revoke(fd)
            raise


def acceptance_phase(host, meta, folder, phase, nonce=None):
    require(phase in {'probe', 'run', 'revoke', 'restored', 'accepted'}, 'native_acceptance_fixed_phase')
    require((phase == 'run' and type(nonce) is bytes and re.fullmatch(b'[0-9a-f]{64}', nonce)) or
            (phase != 'run' and nonce is None), 'native_acceptance_pipe_authority')
    user = pwd.getpwuid(meta['owner_uid'])
    with host.trusted_directory(folder) as fd:
        log = os.open(phase+'.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', CLIENT, phase],
            **({'input': nonce+b'\n'} if phase == 'run' else {'stdin': subprocess.DEVNULL}),
            stdout=log, stderr=log, cwd='/', user=user.pw_uid, group=user.pw_gid,
            extra_groups=os.getgrouplist(user.pw_name, user.pw_gid),
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': user.pw_dir, 'LANG': 'C.UTF-8'},
            timeout=1880 if phase == 'run' else 80, check=False)
        os.fsync(log); require(result.returncode == 0, 'native_acceptance_phase_failed:'+phase)
    finally: os.close(log)


def authorization_probe(host, meta):
    """Root queries polkit for an actual UID1000 subject, without interaction.

    Recent polkit rejects untrusted callers supplying action details, so a
    failing unprivileged pkcheck is not evidence of denied generic execution.
    The native administrator supplies fixed details for a live dropped-UID
    process; the subsequent entrypoint calls themselves are unprivileged.
    """
    require(os.geteuid() == 0, 'native_authorization_probe_root_required')
    user = pwd.getpwuid(meta['owner_uid'])
    child = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', 'import time; time.sleep(45)'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd='/',
        user=user.pw_uid, group=user.pw_gid, extra_groups=os.getgrouplist(user.pw_name, user.pw_gid),
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': user.pw_dir, 'LANG': 'C.UTF-8'})
    try:
        proc = Path('/proc')/str(child.pid)
        require(proc.stat().st_uid == user.pw_uid and child.poll() is None, 'native_probe_unprivileged_subject')
        start = (proc/'stat').read_text().rsplit(')', 1)[1].split()[19]
        subject = str(child.pid)+','+start+','+str(user.pw_uid)
        def check(action, program):
            require(child.poll() is None, 'native_probe_subject_exited')
            result = subprocess.run(['/usr/bin/pkcheck', '--action-id', action, '--process', subject,
                '--detail', 'program', program, '--detail', 'user', 'root'],
                capture_output=True, timeout=10, check=False)
            require(len(result.stdout)+len(result.stderr) <= 65536 and child.poll() is None, 'native_probe_result_or_subject')
            return result.returncode
        deadline = time.monotonic()+15
        while check(ACTION_ID, str(host.ENTRY)) != 0:
            require(time.monotonic() < deadline, 'native_custom_action_not_authorized'); time.sleep(0.25)
        denied = {program: check('org.freedesktop.policykit.exec', program) for program in ['/bin/sh', '/usr/bin/python3']}
        require(all(code in {1, 2} for code in denied.values()), 'native_generic_execution_authorized_or_check_failed')
        return {'custom_authorized': True, 'generic_denial_codes': denied, 'subject_uid': user.pw_uid,
                'noninteractive': True, 'query_caller_uid': os.geteuid()}
    finally:
        if child.poll() is None: child.terminate()
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)


def accept_installation(host, storage, meta, installed):
    """Same native batch: no-prompt tests, nine owned jobs, revoke/native restore.

    A failed acceptance revokes new work and removes the new passwordless rule,
    retaining immutable code/results for diagnosis. It never deletes a release
    from under a possibly running bounded job or infers a known VM stop.
    """
    require(os.geteuid() == 0, 'native_acceptance_root_required')
    folder = host.STATE/'enrollment-acceptance'; created = False
    record = {'schema': 'paw-vm-native-acceptance-v1', 'result': 'FAIL', 'release_sha': meta['head_sha'],
              'real_samples_executed': 0, 'completed_phases': [], 'native_restore_only': True}
    try:
        with host.trusted_directory(host.STATE) as fd: os.mkdir(folder.name, mode=0o700, dir_fd=fd)
        created = True
        with host.trusted_directory(host.STATE/'jobs') as fd: before = set(os.listdir(fd))
        record['authorization'] = authorization_probe(host, meta)
        acceptance_phase(host, meta, folder, 'probe'); record['completed_phases'].append('probe')
        nonce = os.urandom(32).hex().encode(); now = int(time.time())
        grant = {'schema': 'paw-vm-native-test-v1', 'release_sha': meta['head_sha'], 'recipe': 'browser-owned-v1',
                 'token_sha256': hashlib.sha256(nonce).hexdigest(), 'owner_pid': os.getpid(),
                 'owner_start': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                 'created_at': now, 'expires_at': now+60}
        with host.trusted_directory(host.STATE) as fd:
            handle = os.open('enrollment-test.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(handle, 'wb', closefd=False) as stream: stream.write(canonical(grant)); stream.flush(); os.fsync(handle)
            finally: os.close(handle)
            os.fsync(fd)
        acceptance_phase(host, meta, folder, 'run', nonce); record['completed_phases'].append('run')
        with host.trusted_directory(host.STATE) as fd:
            require(host.enrollment_test_consumed(fd), 'native_acceptance_test_not_consumed')
        with host.trusted_directory(host.STATE/'jobs') as fd: after = set(os.listdir(fd))
        new = after-before
        require(len(new) == 1, 'native_acceptance_one_owned_job_required')
        job = next(iter(new)); require(re.fullmatch('[0-9a-f]{32}', job), 'native_acceptance_job_identifier')
        with host.trusted_directory(host.STATE/'jobs'/job) as fd: outcome = host.private_json(fd, 'result.json')
        require(outcome.get('result') == 'PASS' and outcome.get('job') == job and
                outcome.get('recipe') == 'browser-owned-v1' and outcome.get('release_sha') == meta['head_sha'] and
                type(outcome.get('real_samples_executed')) is int and outcome['real_samples_executed'] == 0 and
                type(outcome.get('cases')) is int and outcome['cases'] == 9 and
                outcome.get('cleanup_failed') is not True, 'native_acceptance_protected_job_failed')
        record.update(job=job, cases=9, protected_job_sha256=hashlib.sha256(canonical(outcome)).hexdigest())
        acceptance_phase(host, meta, folder, 'revoke'); record['completed_phases'].append('revoke')
        with host.trusted_directory(host.STATE/'jobs') as fd:
            require(set(os.listdir(fd)) == after, 'native_acceptance_revocation_started_job')
        with host.trusted_directory(host.RELEASES) as fd:
            storage.verify(fd, installed['release_sha'], installed['manifest_sha256'])
        with host.trusted_directory(host.STATE) as fd:
            require(host.revoked(fd), 'native_acceptance_missing_revoke_marker')
            # Explicit native enrollment authority, never an unprivileged command.
            os.unlink('revoked', dir_fd=fd); os.fsync(fd)
        acceptance_phase(host, meta, folder, 'restored'); record['completed_phases'].append('restored')
        record['result'] = 'PASS'
        # A success that cannot be durably recorded is failed acceptance too.
        with host.trusted_directory(folder) as fd: host.write_state(fd, 'result.json', record)
        acceptance_phase(host, meta, folder, 'accepted')
        record['post_acceptance_status_checked'] = True
        with host.trusted_directory(folder) as fd: host.write_state(fd, 'result.json', record)
    except BaseException as error:
        # Disable no-prompt authority even if acceptance storage/revocation
        # creation fails. Never overwrite a previous acceptance directory.
        with host.trusted_directory(RULE_FILE.parent) as fd:
            try: os.unlink(RULE_FILE.name, dir_fd=fd); os.fsync(fd)
            except FileNotFoundError: pass
        with host.trusted_directory(host.STATE) as fd: host.revoke(fd)
        record.update(result='FAIL', error=type(error).__name__+':'+str(error), passwordless_rule_removed=True,
                      accepted_jobs_remain_bounded=True)
        if created:
            try:
                with host.trusted_directory(folder) as fd: host.write_state(fd, 'result.json', record)
            except Exception as storage_error:
                record['failure_record_error'] = type(storage_error).__name__
        raise
    finally:
        print(json.dumps({'enrollment_acceptance': record['result'], 'completed_phases': record['completed_phases'],
                          'real_samples_executed': 0}), flush=True)
    return record


def main():
    require(os.geteuid() == 0, 'native_root_installer_required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True); parser.add_argument('--sha256', required=True)
    args = parser.parse_args(); meta, files = approved_file(args.bundle, args.sha256)
    sys.dont_write_bytecode = True
    # Only digest-approved modules are ever imported; the temp root is not a workspace.
    with tempfile.TemporaryDirectory(prefix='paw-vm-bootstrap-', dir='/var/lib') as temporary:
        root = Path(temporary); root.chmod(0o700)
        for name in MODULES:
            path = root/name; path.write_bytes(files['lab/s14/'+name]); path.chmod(0o444)
        require(not any(name[:-3] in sys.modules for name in MODULES), 'native_bootstrap_preloaded_module')
        sys.path.insert(0, str(root))
        host = importlib.import_module('vm_operator_host'); storage = importlib.import_module('vm_release_storage')
        archive = importlib.import_module('vm_release_archive'); remote = importlib.import_module('vm_release_github')
        contract = importlib.import_module('vm_release_contract')
        require(all(Path(sys.modules[name[:-3]].__file__).parent == root for name in MODULES), 'native_bootstrap_module_origin')
        contract.policy(meta['policy']); require(meta['policy']['owner_uid'] == meta['owner_uid'], 'native_policy_owner')
        client = remote.GitHubClient(host.credential())
        proof = remote.collect_candidate(client, meta['pull_request'], meta['policy'], meta['head_sha'])
        archive.verify_git_tree(client, proof, files)
        fresh = remote.collect_candidate(client, meta['pull_request'], meta['policy'], meta['head_sha'])
        require(fresh == proof, 'native_candidate_changed_before_installation')
        if meta.get('repair_from') is None: result = install_layout(host, storage, archive, meta, files, proof)
        else: result = repair_layout(host, storage, archive, contract, meta, files, proof)
        print(json.dumps(result, sort_keys=True), flush=True)
        accept_installation(host, storage, meta, result)


if __name__ == '__main__': main()
