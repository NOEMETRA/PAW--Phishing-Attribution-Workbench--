"""Separate Root authority for explicit forensic requests; no launcher.

The ordinary operator may use only immutable-owned fixture recipes. These Root
functions do not delegate real-source issuance or enable readiness by themselves.
"""
import contextlib
import json
import os
from pathlib import Path
import re
import time

from paw.core import representation_bridge as contract
import hash_authorization as python_backend
import browser_authorization as html_backend
import vm_release_storage as storage

fs = python_backend.fs
canonical, digest, require = contract.canonical, contract.digest, contract.require
ROOT = Path('/var/lib/paw-s14/representation-authorization-v1')
HERE = Path(__file__).resolve().parent
SCOPE = 'explicit-forensic-selection-no-nic-v1'
PROFILES = {contract.PROFILES[key][0] for key in ['python', 'html']}


def decode(raw, maximum=256*1024): return contract._decode(raw, maximum)


def _backend(profile):
    require(type(profile) is str and profile in PROFILES, 'representation_authority_profile')
    return python_backend if profile == contract.PROFILES['python'][0] else html_backend


def validate_context(value):
    require(type(value) is dict and set(value) == {'profile', 'backend', 'contract_sha256',
            'runtime_sources_sha256', 'maintenance_sha256'}, 'representation_context_shape')
    _backend(value['profile']).validate_context(value['backend'])
    require(value['contract_sha256'] == contract.contract_hash() and
            all(contract.shared._hex(value[key]) for key in ['runtime_sources_sha256', 'maintenance_sha256']),
            'representation_context_code_or_maintenance')
    return value


def capture(profile):
    backend = _backend(profile); context = backend.capture(); backend.validate_context(context)
    platform = context if backend is python_backend else context['platform']
    with python_backend.store() as fd:
        names = os.listdir(fd); require(len(names) <= 4096, 'representation_maintenance_inventory')
        records = []
        for name in sorted(names):
            if not re.fullmatch('maintenance-[0-9a-f]{64}\\.json', name): continue
            raw = fs.read(fd, name, 65536)
            require(name == 'maintenance-'+digest(raw)+'.json', 'representation_maintenance_digest')
            try: python_backend.validate_maintenance(raw, platform)
            except ValueError: continue
            records.append(digest(raw))
    require(records, 'representation_current_protected_maintenance_required')
    release = HERE.parents[1]
    with fs.root_directory(Path('/var/lib/paw-vm')) as fd: active = decode(fs.read(fd, 'active.json'))
    require(type(active) is dict and type(active.get('release_sha')) is str and
            re.fullmatch('[0-9a-f]{40}', active['release_sha']) and
            release == Path('/opt/paw-vm/releases')/active['release_sha'], 'representation_immutable_active_release')
    with fs.root_directory(release.parent) as fd:
        manifest, _ = storage.verify(fd, active['release_sha'], active['manifest_sha256'])
    value = {'profile': profile, 'backend': context, 'contract_sha256': contract.contract_hash(),
             'runtime_sources_sha256': digest(storage.canonical(manifest['files'])), 'maintenance_sha256': min(records)}
    return validate_context(value)


def inspect(raw, now=None):
    request = contract.validate_request(raw, now); frame = request['candidate']
    return {'request_id': frame['request_id'], 'profile': frame['profile'], 'request_sha256': digest(raw),
            'candidate_sha256': digest(canonical(frame)), 'selection_binding_sha256': frame['selection_binding_sha256'],
            'source_sha256': frame['source']['sha256'], 'original_source_sha256': request['binding']['original_source']['sha256'],
            'graph_sha256': request['binding']['graph_sha256'], 'selected_node': request['binding']['derivation']['selected']}


def validate_readiness(raw, context, now=None):
    validate_context(context); value = decode(raw); now = time.time() if now is None else now
    require(raw == canonical(value) and type(value) is dict and set(value) == {'schema', 'scope', 'decision',
            'context_sha256', 'matrix_sha256', 'reviewed_head', 'review_url', 'ci_runs', 'ci_successful_jobs',
            'created_at', 'expires_at'}, 'representation_readiness_shape')
    require(value['schema'] == 'paw-s14-representation-i08-v1' and value['scope'] == SCOPE and
            value['decision'] == 'ready-for-explicit-single-representation-no-nic' and
            value['context_sha256'] == digest(canonical(context)) and contract.shared._hex(value['matrix_sha256']),
            'representation_readiness_binding')
    require(type(value['reviewed_head']) is str and re.fullmatch('[0-9a-f]{40}', value['reviewed_head']) and
            type(value['review_url']) is str and re.fullmatch(r'https://github\.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/[1-9][0-9]*#issuecomment-[1-9][0-9]*', value['review_url']),
            'representation_readiness_review')
    require(type(value['ci_runs']) is list and len(value['ci_runs']) == 2 and
            all(type(v) is int and v > 0 for v in value['ci_runs']) and len(set(value['ci_runs'])) == 2 and
            type(value['ci_successful_jobs']) is int and value['ci_successful_jobs'] == 7, 'representation_readiness_ci')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at']+86400, 'representation_readiness_clock')
    return value


def validate_policy(raw, context, ready=None, now=None):
    validate_context(context); value = decode(raw); now = time.time() if now is None else now
    require(raw == canonical(value) and type(value) is dict and set(value) == {'schema', 'scope', 'context',
            'context_sha256', 'mode', 'approved_requests', 'readiness_sha256', 'owned_manifest_sha256', 'created_at', 'expires_at'},
            'representation_policy_shape')
    require(value['schema'] == 'paw-s14-representation-policy-v1' and value['scope'] == SCOPE and
            canonical(value['context']) == canonical(context) and value['context_sha256'] == digest(canonical(context)),
            'representation_policy_context')
    approvals = value['approved_requests']
    require(type(approvals) is list and 1 <= len(approvals) <= 32, 'representation_approval_budget')
    hashes = []
    for item in approvals:
        require(type(item) is dict and set(item) == {'request_sha256', 'source_sha256'} and
                all(contract.shared._hex(v) for v in item.values()), 'representation_exact_request_approval')
        hashes.append(item['request_sha256'])
    require(len(set(hashes)) == len(hashes), 'representation_duplicate_approval')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at']+86400, 'representation_policy_clock')
    if value['mode'] == 'owned-validation':
        require(value['readiness_sha256'] is None and contract.shared._hex(value['owned_manifest_sha256']),
                'representation_owned_validation_scope')
    elif value['mode'] == 'explicit-source-analysis':
        require(len(approvals) == 1 and value['owned_manifest_sha256'] is None and ready is not None,
                'representation_single_request_readiness_required')
        receipt = validate_readiness(ready, context, now)
        require(value['readiness_sha256'] == digest(ready) and value['expires_at'] <= receipt['expires_at'],
                'representation_policy_readiness')
    else: raise ValueError('representation_policy_mode')
    return value


def make_policy(context, requests, *, mode='owned-validation', owned_manifest_sha256=None, ready=None):
    require(type(requests) is list and 1 <= len(requests) <= 32, 'representation_request_list_budget')
    now = int(time.time()); expiry = now+86400
    if ready is not None: expiry = min(expiry, decode(ready)['expires_at'])
    approvals = []
    for raw in requests:
        summary = inspect(raw)
        require(summary['profile'] == context['profile'], 'representation_policy_profile')
        approvals.append({key: summary[key] for key in ['request_sha256', 'source_sha256']})
    raw = canonical({'schema': 'paw-s14-representation-policy-v1', 'scope': SCOPE, 'context': context,
        'context_sha256': digest(canonical(context)), 'mode': mode, 'approved_requests': approvals,
        'readiness_sha256': digest(ready) if ready is not None else None,
        'owned_manifest_sha256': owned_manifest_sha256, 'created_at': now, 'expires_at': expiry})
    validate_policy(raw, context, ready); return raw


@contextlib.contextmanager
def store():
    with fs.root_directory(ROOT) as fd: yield fd


def initialize():
    require(os.geteuid() == 0, 'root_representation_authority_required')
    with fs.root_directory(ROOT.parent):
        try: ROOT.mkdir(mode=0o700)
        except FileExistsError: pass
    with store() as fd: require(os.fstat(fd).st_mode & 0o777 == 0o700, 'representation_private_authority')


def install_readiness(raw, context):
    require(os.geteuid() == 0, 'root_representation_authority_required')
    validate_readiness(raw, context)
    require(canonical(capture(context['profile'])) == canonical(context), 'representation_actual_context_changed')
    with store() as fd: fs.exclusive(fd, 'readiness-'+digest(raw)+'.json', raw)


def installed(raw, context, now=None):
    value = decode(raw)
    with store() as fd:
        require(fs.read(fd, 'policy-'+digest(raw)+'.json', 256*1024) == raw, 'representation_policy_not_installed')
        ready = fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] is not None else None
    return validate_policy(raw, context, ready, now), ready


def install_policy(raw, context):
    require(os.geteuid() == 0, 'root_representation_authority_required'); value = decode(raw)
    with store() as fd:
        ready = fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] is not None else None
        validate_policy(raw, context, ready)
        require(canonical(capture(context['profile'])) == canonical(context), 'representation_actual_context_changed')
        fs.exclusive(fd, 'policy-'+digest(raw)+'.json', raw)


def validate_binding(raw, grant, policy_raw, context, ready=None, now=None):
    summary = inspect(raw, now); request = contract.validate_request(raw, now); frame = request['candidate']
    policy = validate_policy(policy_raw, context, ready, now); now = time.time() if now is None else now
    require(summary['profile'] == context['profile'] and type(grant) is dict and set(grant) == set(summary) | {
            'schema', 'scope', 'policy_sha256', 'context_sha256', 'execution_purpose', 'created_at', 'expires_at'},
            'representation_grant_shape')
    require(grant['schema'] == 'paw-s14-representation-grant-v1' and grant['scope'] == SCOPE and
            all(grant[key] == value for key, value in summary.items()) and
            grant['policy_sha256'] == digest(policy_raw) and grant['context_sha256'] == digest(canonical(context)) and
            grant['execution_purpose'] == policy['mode'], 'representation_grant_binding')
    require({'request_sha256': summary['request_sha256'], 'source_sha256': summary['source_sha256']} in policy['approved_requests'],
            'representation_request_not_explicitly_approved')
    require(type(grant['created_at']) is int and type(grant['expires_at']) is int and
            frame['created_at'] <= grant['created_at'] <= now < grant['expires_at'] <=
            min(frame['expires_at'], policy['expires_at'], grant['created_at']+900), 'representation_grant_clock')
    return summary, request, bytes.fromhex(frame['source']['data_hex'])


def issue(raw, policy_raw, context):
    require(os.geteuid() == 0, 'root_representation_authority_required')
    policy, ready = installed(policy_raw, context); summary = inspect(raw); frame = contract.validate_request(raw)['candidate']
    require(canonical(capture(context['profile'])) == canonical(context), 'representation_actual_context_changed')
    now = int(time.time()); grant = {'schema': 'paw-s14-representation-grant-v1', 'scope': SCOPE, **summary,
        'policy_sha256': digest(policy_raw), 'context_sha256': digest(canonical(context)),
        'execution_purpose': policy['mode'], 'created_at': now,
        'expires_at': min(now+900, frame['expires_at'], policy['expires_at'])}
    validate_binding(raw, grant, policy_raw, context, ready)
    with store() as fd:
        with fs.subdirectory(fd, 'grants') as target: fs.exclusive(target, summary['request_id']+'.json', canonical(grant))
    return grant


def load_bound(raw, policy_raw, context, now=None):
    summary = inspect(raw, now); policy, ready = installed(policy_raw, context, now)
    with store() as fd:
        with fs.subdirectory(fd, 'grants') as target: grant = fs.read(target, summary['request_id']+'.json', 8192)
    summary, request, source = validate_binding(raw, decode(grant, 8192), policy_raw, context, ready, now)
    return grant, summary, request, source


def consume(raw, policy_raw, context):
    require(os.geteuid() == 0, 'root_representation_authority_required')
    require(canonical(capture(context['profile'])) == canonical(context), 'representation_actual_context_changed')
    grant, summary, request, source = load_bound(raw, policy_raw, context)
    ledger = {'schema': 'paw-s14-representation-consumed-v1', 'request_id': summary['request_id'],
              'request_sha256': digest(raw), 'grant_sha256': digest(grant),
              'policy_sha256': digest(policy_raw), 'context_sha256': digest(canonical(context)), 'consumed_at': int(time.time())}
    with store() as fd:
        with fs.subdirectory(fd, 'consumed') as target: fs.exclusive(target, summary['request_id']+'.json', canonical(ledger))
    return ledger, grant, summary, request, source


def confirm_consumed(ledger):
    with store() as fd:
        with fs.subdirectory(fd, 'consumed') as target:
            require(fs.read(target, ledger['request_id']+'.json', 8192) == canonical(ledger), 'representation_consumption_changed')
