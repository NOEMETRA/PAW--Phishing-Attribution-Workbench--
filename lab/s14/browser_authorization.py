"""Separate root HTML authority bound to derived browser image and exact context."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import time
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from paw.core import browser_bridge as contract
import hash_authorization as platform
from browser_vm import BROWSER_BASE, BROWSER_META, LIMITS
from benign_guest_validation import BASE, digest as file_digest

fs = platform.fs
canonical = contract.canonical
require = contract.require
ROOT = Path('/var/lib/paw-s14/browser-authorization-v1')
SCOPE = 'hash-pinned-offline-html-browser-v1'
MAX_FRAME = contract.REQUEST_LIMIT


def digest(raw): return hashlib.sha256(raw).hexdigest()


@contextlib.contextmanager
def store():
    with fs.root_directory(ROOT) as fd: yield fd


def certificate(raw):
    value = json.loads(raw)
    require(raw == canonical(value) and value['schema'] == 'paw-s14-browser-image-v1' and
            value['foundation_sha256'] == fs.IMAGE_SHA256 and value['backing_file'] == str(BASE), 'browser_image_certificate')
    guest = value['guest']
    require(guest['kernel_release'] == '6.8.0-147-generic' and guest['network_interfaces'] == ['lo'] and
            guest['userns_restriction'] == '1' and guest['cpu_sensitive_features_absent'] is True and
            all(guest['probe'][k] is True for k in ['renderer_seen', 'renderer_nnp', 'renderer_seccomp',
                'renderer_pid_namespace', 'all_uids_nonroot']) and guest['probe']['title'] == 'PAW-BROWSER-PROBE', 'browser_image_probe')
    require(type(guest['chrome_version']) is str and guest['chrome_version'].startswith('Google Chrome ') and
            re.fullmatch('[0-9a-f]{64}', guest['chrome_binary_sha256']) and
            re.fullmatch('[0-9a-f]{64}', value['image_sha256']), 'browser_image_binary')
    return value


def capture():
    with fs.root_directory(BROWSER_META.parent) as fd: raw = fs.read(fd, BROWSER_META.name, 1024**2)
    image = certificate(raw); fs.trusted(BROWSER_BASE.stat())
    require(BROWSER_BASE.stat().st_mode & 0o777 == 0o444 and file_digest(BROWSER_BASE) == image['image_sha256'], 'browser_image_changed')
    return {'platform': platform.capture(), 'image_sha256': image['image_sha256'], 'image_certificate_sha256': digest(raw),
            'chrome_version': image['guest']['chrome_version'], 'chrome_binary_sha256': image['guest']['chrome_binary_sha256'],
            'bridge_contract_sha256': contract.contract_hash(), 'qemu_limits': dict(LIMITS),
            'guest_memory_bytes': 1024**3, 'job_memory_bytes': 512*1024**2, 'job_tasks': 256}


def validate_context(context):
    require(type(context) is dict and set(context) == {'platform', 'image_sha256', 'image_certificate_sha256',
            'chrome_version', 'chrome_binary_sha256', 'bridge_contract_sha256', 'qemu_limits',
            'guest_memory_bytes', 'job_memory_bytes', 'job_tasks'}, 'browser_context_shape')
    platform.validate_context(context['platform'])
    require(all(type(context[k]) is str and re.fullmatch('[0-9a-f]{64}', context[k]) for k in
                ['image_sha256', 'image_certificate_sha256', 'chrome_binary_sha256', 'bridge_contract_sha256']) and
            context['bridge_contract_sha256'] == contract.contract_hash() and context['qemu_limits'] == LIMITS and
            context['guest_memory_bytes'] == 1024**3 and context['job_memory_bytes'] == 512*1024**2 and
            context['job_tasks'] == 256 and type(context['chrome_version']) is str and
            context['chrome_version'].startswith('Google Chrome '), 'browser_context_policy')


def validate_readiness(raw, context, now=None):
    value = json.loads(raw); now = time.time() if now is None else now
    require(raw == canonical(value) and set(value) == {'schema', 'decision', 'context_sha256', 'reviewed_head',
            'review_url', 'ci_runs', 'ci_successful_jobs', 'created_at', 'expires_at'}, 'browser_readiness_shape')
    require(value['schema'] == 'paw-s14-browser-i08-readiness-v1' and
            value['decision'] == 'ready-for-explicit-single-hash-offline-html-grants' and
            value['context_sha256'] == digest(canonical(context)), 'browser_readiness_context')
    require(type(value['reviewed_head']) is str and re.fullmatch('[0-9a-f]{40}', value['reviewed_head']) and
            type(value['review_url']) is str and re.fullmatch(r'https://github\.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/[0-9]+#issuecomment-[0-9]+', value['review_url']), 'browser_review_receipt')
    require(type(value['ci_runs']) is list and len(value['ci_runs']) == 2 and len(set(value['ci_runs'])) == 2 and
            all(type(v) is int and v > 0 for v in value['ci_runs']) and type(value['ci_successful_jobs']) is int and
            value['ci_successful_jobs'] == 7, 'browser_ci_receipt')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at'] + 86400, 'browser_readiness_clock')
    return value


def validate_policy(raw, context, ready=None, now=None):
    value = json.loads(raw); validate_context(context); now = time.time() if now is None else now
    require(raw == canonical(value) and set(value) == {'schema', 'scope', 'context', 'mode', 'approved_source_hashes',
            'readiness_sha256', 'validation_manifest_sha256', 'created_at', 'expires_at'} and
            value['schema'] == 'paw-s14-browser-policy-v1' and value['scope'] == SCOPE and value['context'] == context, 'browser_policy_binding')
    hashes = value['approved_source_hashes']
    require(type(hashes) is list and 1 <= len(hashes) <= 32 and len(set(hashes)) == len(hashes) and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in hashes), 'browser_approved_hashes')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at'] + 86400, 'browser_policy_clock')
    if value['mode'] == 'validation':
        require(value['readiness_sha256'] is None and type(value['validation_manifest_sha256']) is str and
                re.fullmatch('[0-9a-f]{64}', value['validation_manifest_sha256']), 'browser_validation_not_readiness')
    elif value['mode'] == 'sample-analysis':
        require(ready is not None and len(hashes) == 1 and value['validation_manifest_sha256'] is None, 'browser_single_hash_readiness')
        record = validate_readiness(ready, context, now)
        require(value['readiness_sha256'] == digest(ready) and value['expires_at'] <= record['expires_at'], 'browser_policy_readiness')
    else: raise ValueError('browser_policy_mode')
    return value


def make_policy(context, hashes, *, mode='validation', validation_manifest_sha256=None, readiness_raw=None):
    now = int(time.time()); expiry = now + 86400
    if mode == 'sample-analysis':
        require(readiness_raw is not None, 'browser_readiness_required'); expiry = min(expiry, json.loads(readiness_raw)['expires_at'])
    raw = canonical({'schema': 'paw-s14-browser-policy-v1', 'scope': SCOPE, 'context': context, 'mode': mode,
        'approved_source_hashes': list(hashes), 'readiness_sha256': digest(readiness_raw) if readiness_raw else None,
        'validation_manifest_sha256': validation_manifest_sha256, 'created_at': now, 'expires_at': expiry})
    validate_policy(raw, context, readiness_raw); return raw


def inspect(raw, now=None):
    value = contract.validate_frame(raw, now)
    return {k: value[k] for k in ['request_id', 'case_reference_sha256']} | {
        'frame_sha256': digest(raw), 'source_sha256': value['source']['sha256']}


def initialize():
    """Administrator only; fixed namespace with no caller-selected storage root."""
    require(os.geteuid() == 0, 'root_browser_operator_required')
    with fs.root_directory(ROOT.parent):
        try: ROOT.mkdir(mode=0o700)
        except FileExistsError: pass
    with store() as fd:
        require(os.fstat(fd).st_mode & 0o777 == 0o700, 'browser_authority_private_directory')


def install_readiness(raw, context):
    """Explicit local admin receipt, never inferred from an input or HTTP200."""
    require(os.geteuid() == 0, 'root_browser_operator_required')
    validate_context(context); validate_readiness(raw, context)
    require(capture() == context, 'browser_readiness_actual_context')
    with store() as fd: fs.exclusive(fd, 'readiness-'+digest(raw)+'.json', raw)


def install_policy(raw, context):
    require(os.geteuid() == 0, 'root_browser_operator_required')
    value = json.loads(raw)
    with store() as fd:
        ready = fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] else None
        validate_policy(raw, context, ready)
        require(capture() == context, 'browser_policy_actual_context')
        fs.exclusive(fd, 'policy-'+digest(raw)+'.json', raw)


def installed(raw, context, now=None):
    value = json.loads(raw)
    with store() as fd:
        require(fs.read(fd, 'policy-'+digest(raw)+'.json') == raw, 'browser_policy_not_installed')
        ready = fs.read(fd, 'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] else None
    return validate_policy(raw, context, ready, now), ready


def validate_binding(raw, grant, policy_raw, context, ready=None, now=None):
    summary = inspect(raw, now); value = contract.validate_frame(raw, now)
    policy = validate_policy(policy_raw, context, ready, now); now = time.time() if now is None else now
    require(type(grant) is dict and set(grant) == {'schema', 'scope', 'request_id', 'case_reference_sha256',
            'frame_sha256', 'source_sha256', 'policy_sha256', 'execution_purpose', 'created_at', 'expires_at'} and
            grant['schema'] == 'paw-s14-browser-grant-v1' and grant['scope'] == SCOPE, 'browser_grant_shape')
    require(all(grant[k] == v for k, v in summary.items()) and grant['source_sha256'] in policy['approved_source_hashes'] and
            grant['policy_sha256'] == digest(policy_raw) and grant['execution_purpose'] == policy['mode'], 'browser_grant_binding')
    require(type(grant['created_at']) is int and type(grant['expires_at']) is int and
            value['created_at'] <= grant['created_at'] <= now < grant['expires_at'] <=
            min(value['expires_at'], policy['expires_at'], grant['created_at'] + 900), 'browser_grant_lease')
    return summary, value, bytes.fromhex(value['source']['data_hex'])


def issue(raw, policy_raw, context):
    require(os.geteuid() == 0, 'root_browser_operator_required')
    policy, ready = installed(policy_raw, context); summary = inspect(raw); value = contract.validate_frame(raw); now = int(time.time())
    grant = {'schema': 'paw-s14-browser-grant-v1', 'scope': SCOPE, **summary, 'policy_sha256': digest(policy_raw),
        'execution_purpose': policy['mode'], 'created_at': now, 'expires_at': min(now+900, value['expires_at'], policy['expires_at'])}
    validate_binding(raw, grant, policy_raw, context, ready)
    with store() as fd:
        with fs.subdirectory(fd, 'grants') as sub: fs.exclusive(sub, summary['request_id']+'.json', canonical(grant))
    return grant


def load_bound(raw, policy_raw, context, now=None):
    summary = inspect(raw, now); policy, ready = installed(policy_raw, context, now)
    with store() as fd:
        with fs.subdirectory(fd, 'grants') as sub: grant = fs.read(sub, summary['request_id']+'.json', 4096)
    summary, value, source = validate_binding(raw, json.loads(grant), policy_raw, context, ready, now)
    return grant, summary, value, source


def consume(raw, policy_raw, context):
    require(os.geteuid() == 0, 'root_browser_operator_required')
    grant, summary, value, source = load_bound(raw, policy_raw, context)
    ledger = {'schema': 'paw-s14-browser-consumed-v1', 'request_id': summary['request_id'], 'frame_sha256': digest(raw),
              'grant_sha256': digest(grant), 'policy_sha256': digest(policy_raw), 'consumed_at': int(time.time())}
    with store() as fd:
        with fs.subdirectory(fd, 'consumed') as sub: fs.exclusive(sub, summary['request_id']+'.json', canonical(ledger))
    return ledger, grant, summary, value, source


def confirm_consumed(ledger):
    with store() as fd:
        with fs.subdirectory(fd, 'consumed') as sub:
            require(fs.read(sub, ledger['request_id']+'.json', 4096) == canonical(ledger), 'browser_consumption_changed')
