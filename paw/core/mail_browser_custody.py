"""Bounded selected real-mail custody data, never an execution grant.

The caller must independently establish protected approval, trusted BLAKE3,
immutable runtime, one-use consumption, stopped writers and network admission.
No socket, process, Root endpoint or public capability is provided here.
"""
import base64
import hashlib
import json
import re
import time
import uuid

from . import synthetic_bridge as shared
from .browser_mediator import endpoint

PROFILE = 'linux-chrome-url-brokered-v1'
REQUEST_MAX = 128 * 1024
SOURCE_MAX = 65536
PARTS = {'manifest.json': 32768, 'evidence/merkle_index.json': 32768,
         'url_evidence.json': 32768, 'execution.json': 8192,
         'evidence/inventory_scope.json': 4096}
LIMITS = {'requests': 32, 'public_hosts': 8, 'redirects_total': 5,
          'response_bytes': 4*1024**2, 'browser_seconds': 15,
          'dom_bytes': 256*1024, 'screenshot_bytes': 256*1024,
          'network_bytes': 1024**2, 'external_stop_seconds': 12}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def decode64(value, maximum):
    require(type(value) is str and len(value) <= 4*((maximum+2)//3), 'mail_custody_base64_budget')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError('mail_custody_base64') from None
    require(len(raw) <= maximum and base64.b64encode(raw).decode('ascii') == value,
            'mail_custody_base64_canonical')
    return raw


def validate(raw, content_hash, *, now=None):
    """Check selected content against its BLAKE3 index via a trusted hasher.

    This pure function does not establish the origin of content_hash. A Root
    caller must supply the hash implementation from its separately verified
    immutable dependency; an untrusted callback cannot confer Root authority.
    Other parent artifacts are represented by the index, not independently
    read here. UID preparation/import must verify the whole stopped case.
    """
    require(callable(content_hash), 'mail_custody_trusted_hasher_required')
    value = shared._decode(raw, REQUEST_MAX)
    require(type(value) is dict and set(value) == {
        'schema', 'state', 'execution_authority', 'profile', 'request_id',
        'created_at', 'expires_at', 'case_reference', 'source_b64',
        'source_sha256', 'pieces_b64', 'snapshot_sha256', 'url_index', 'url', 'limits'
    } and raw == canonical(value), 'mail_custody_request_shape')
    require(value['schema'] == 'paw-real-mail-browser-request-v1' and
            value['state'] == 'PREPARED_NOT_ACTIVE' and value['execution_authority'] == 'none' and
            value['profile'] == PROFILE and type(value['request_id']) is str and
            re.fullmatch('[0-9a-f]{32}', value['request_id']), 'mail_custody_not_authority')
    require(canonical(value['limits']) == canonical(LIMITS), 'mail_custody_limits')
    now = time.time() if now is None else now
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at']+900,
            'mail_custody_request_expired')
    source = decode64(value['source_b64'], SOURCE_MAX)
    require(source and value['source_sha256'] == digest(source), 'mail_custody_source_digest')
    ref = value['case_reference']
    require(type(ref) is dict and set(ref) == {
        'case_id', 'manifest_sha256', 'merkle_index_sha256', 'merkle_root_blake3'
    } and type(ref['case_id']) is str and re.fullmatch(r'case-[A-Za-z0-9_:-]{1,120}', ref['case_id']) and
        all(hex64(ref[k]) for k in ref if k != 'case_id'), 'mail_custody_parent_reference')
    require(type(value['pieces_b64']) is dict and set(value['pieces_b64']) == set(PARTS),
            'mail_custody_piece_names')
    pieces = {name: decode64(value['pieces_b64'][name], cap) for name, cap in PARTS.items()}
    require(value['snapshot_sha256'] == {name: digest(data) for name, data in pieces.items()} and
            digest(pieces['manifest.json']) == ref['manifest_sha256'] and
            digest(pieces['evidence/merkle_index.json']) == ref['merkle_index_sha256'],
            'mail_custody_parent_substitution')
    index = shared._decode(pieces['evidence/merkle_index.json'], PARTS['evidence/merkle_index.json'])
    require(type(index) is dict and 1 <= len(index) <= 512 and list(index) == sorted(index) and
            all(type(k) is str and 0 < len(k) <= 1024 and hex64(v) for k, v in index.items()),
            'mail_custody_index_shape')
    require(content_hash(''.join(index.values()).encode('ascii')) == ref['merkle_root_blake3'],
            'mail_custody_index_root')
    for name, data in {**pieces, 'input.eml': source}.items():
        if name != 'evidence/merkle_index.json':
            require(index.get(name) == content_hash(data), 'mail_custody_selected_piece_hash')
    manifest = shared._decode(pieces['manifest.json'], PARTS['manifest.json'])
    require(type(manifest) is dict and type(manifest.get('case_id')) is str and
            'case-'+manifest['case_id'] == ref['case_id'] and type(manifest.get('inputs')) is list and
            len(manifest['inputs']) == 1 and type(manifest['inputs'][0]) is dict and
            type(manifest['inputs'][0].get('size')) is int and manifest['inputs'][0] == {
                'path': 'input.eml', 'size': len(source), 'blake3': content_hash(source)
            }, 'mail_custody_manifest_source')
    execution = shared._decode(pieces['execution.json'], PARTS['execution.json'])
    scope = shared._decode(pieces['evidence/inventory_scope.json'], PARTS['evidence/inventory_scope.json'])
    require(type(execution) is dict and execution.get('status') == 'completed' and
            execution.get('no_egress') is True and type(scope) is dict and
            scope.get('policy') == 'all_case_files_v1', 'mail_custody_completed_offline_parent')
    rows = shared._decode(pieces['url_evidence.json'], PARTS['url_evidence.json'])
    i = value['url_index']
    require(type(rows) is list and 0 < len(rows) <= 128 and type(i) is int and 0 <= i < len(rows) and
            type(rows[i]) is dict and rows[i].get('network_target') is True and
            rows[i].get('url') == value['url'], 'mail_custody_selected_url')
    endpoint(value['url'])
    return value


def selection(value):
    """Stable native-approval subject; no caller may treat this as approval."""
    return {**{k: value[k] for k in ['profile', 'source_sha256', 'case_reference',
                                     'snapshot_sha256', 'url_index', 'url', 'limits']},
            'url_sha256': digest(value['url'].encode('ascii'))}


def require_selection(value, protected_selection):
    require(type(protected_selection) is dict and
            canonical(selection(value)) == canonical(protected_selection),
            'mail_custody_not_selected_by_protected_authority')


@shared._offline
def prepare(directory, url_index, *, now=None):
    """Ordinary UID preparation; no publication or administrative action."""
    import blake3
    case, ref = shared._case_reference(directory)
    source = shared._read_regular(case/'input.eml', SOURCE_MAX)
    pieces = {name: shared._read_regular(case/name, cap) for name, cap in PARTS.items()}
    rows = shared._decode(pieces['url_evidence.json'], PARTS['url_evidence.json'])
    require(type(rows) is list and type(url_index) is int and 0 <= url_index < len(rows) and
            type(rows[url_index]) is dict, 'mail_custody_selection')
    created = int(time.time()) if now is None else now
    value = {'schema': 'paw-real-mail-browser-request-v1', 'state': 'PREPARED_NOT_ACTIVE',
             'execution_authority': 'none', 'profile': PROFILE, 'request_id': uuid.uuid4().hex,
             'created_at': created, 'expires_at': created+900, 'case_reference': ref,
             'source_b64': base64.b64encode(source).decode('ascii'), 'source_sha256': digest(source),
             'pieces_b64': {n: base64.b64encode(v).decode('ascii') for n, v in pieces.items()},
             'snapshot_sha256': {n: digest(v) for n, v in pieces.items()},
             'url_index': url_index, 'url': rows[url_index].get('url'), 'limits': dict(LIMITS)}
    raw = canonical(value)
    validate(raw, lambda data: blake3.blake3(data).hexdigest(), now=created)
    require(shared._case_reference(case)[1] == ref and
            shared._read_regular(case/'input.eml', SOURCE_MAX) == source and
            all(shared._read_regular(case/name, PARTS[name]) == data for name, data in pieces.items()),
            'mail_custody_parent_changed')
    return raw
