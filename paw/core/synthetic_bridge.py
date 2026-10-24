"""Offline PAW case linkage for one fixed harmless S14 fixture, never a launcher."""
from contextlib import contextmanager, redirect_stdout
from functools import wraps
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

PROFILE = 'linux-python-offline-v1'
FIXTURE = 'owned-marker-v1'
FIXTURE_SHA256 = '7903bbd3b2484f23a66ce72e9578c6f639f762fd1ec47e52c2d9910289ac84ae'
IMAGE_SHA256 = 'b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658'
EXPORT_ROOT = Path('/var/lib/paw-s14-exports')
REQUEST_LIMIT = 4096
RECEIPT_LIMIT = 16384
MARKER = b'OWNED-IMMUTABLE-INPUT\n'


def require(value, reason):
    if not value: raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode() + b'\n'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _decode(raw, limit):
    require(type(raw) is bytes and len(raw) <= limit, 'synthetic_json_budget')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'synthetic_duplicate_key'); result[key] = value
        return result
    def constant(value): raise ValueError('synthetic_nonfinite_json')
    try: return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('synthetic_invalid_json') from error


def validate_request(raw, now=None):
    value = _decode(raw, REQUEST_LIMIT)
    require(type(value) is dict and set(value) == {'schema', 'request_id', 'profile', 'fixture', 'fixture_sha256',
                'created_at', 'expires_at', 'case_reference', 'case_reference_sha256'}, 'synthetic_request_shape')
    require(value['schema'] == 'paw-s14-synthetic-request-v1' and value['profile'] == PROFILE and
            value['fixture'] == FIXTURE and value['fixture_sha256'] == FIXTURE_SHA256, 'synthetic_fixture_scope')
    require(type(value['request_id']) is str and re.fullmatch('[0-9a-f]{32}', value['request_id']), 'synthetic_request_id')
    ref = value['case_reference']
    require(type(ref) is dict and set(ref) == {'case_id', 'manifest_sha256', 'merkle_index_sha256', 'merkle_root_blake3'}, 'synthetic_case_reference')
    require(type(ref['case_id']) is str and re.fullmatch(r'case-[A-Za-z0-9_:-]{1,120}', ref['case_id']), 'synthetic_case_id')
    require(all(_hex(ref[k]) for k in ['manifest_sha256', 'merkle_index_sha256', 'merkle_root_blake3']), 'synthetic_case_digest')
    require(value['case_reference_sha256'] == digest(canonical(ref)), 'synthetic_case_reference_digest')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] < value['expires_at'] <= value['created_at'] + 900, 'synthetic_request_clock')
    current = time.time() if now is None else now
    require(value['created_at'] <= current < value['expires_at'], 'synthetic_request_expired')
    return value


def _linux():
    require(sys.platform.startswith('linux'), 'synthetic_bridge_requires_Linux')


def _offline(function):
    @wraps(function)
    def run(*args, **kwargs):
        from .network_policy import offline_policy
        with offline_policy(): return function(*args, **kwargs)
    return run


def _read_regular(path, maximum, *, directory_fd=None, root_owned=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'synthetic_regular_file_budget')
        if root_owned: require(before.st_uid == 0 and not before.st_mode & 0o022, 'synthetic_untrusted_producer_file')
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        after = os.fstat(fd)
        require(len(data) <= maximum and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'synthetic_file_changed')
        return bytes(data)
    finally: os.close(fd)


def _case_reference(directory):
    from .evidence import file_inventory
    from .job_registry import require_stopped_case
    from .verify import verify_case
    root = Path(directory).resolve(strict=True)
    require(root.is_dir(), 'synthetic_case_directory')
    files = file_inventory(root)  # Reject links before reading excluded seal files.
    require(len(files) <= 10000 and sum(p.stat().st_size for p in files.values()) <= 512 * 1024**2, 'synthetic_case_budget')
    for path in root.rglob('*'):
        require(stat.S_ISDIR(path.lstat().st_mode) or stat.S_ISREG(path.lstat().st_mode), 'synthetic_case_special_file')
    manifest = _read_regular(root / 'manifest.json', 1024**2)
    parsed = _decode(manifest, 1024**2)
    require(type(parsed) is dict and type(parsed.get('analysis_job')) is str and parsed['analysis_job'], 'synthetic_case_owner_missing')
    require_stopped_case(root)
    execution = _decode(_read_regular(root / 'execution.json', 1024**2), 1024**2)
    scope = _decode(_read_regular(root / 'evidence/inventory_scope.json', 4096), 4096)
    require(type(execution) is dict and execution.get('status') == 'completed' and
            type(scope) is dict and scope.get('policy') == 'all_case_files_v1', 'synthetic_completed_sealed_case_required')
    index = _read_regular(root / 'evidence/merkle_index.json', 8 * 1024**2)
    merkle = _read_regular(root / 'evidence/merkle_root.bin', 128).decode('ascii').strip()
    with redirect_stdout(io.StringIO()): valid = verify_case(root)
    require(valid, 'synthetic_case_seal_invalid')
    return root, {'case_id': root.name, 'manifest_sha256': digest(manifest), 'merkle_index_sha256': digest(index), 'merkle_root_blake3': merkle}


def _destination(path, case):
    result = Path(path).resolve()
    require(not result.is_relative_to(case) and not case.is_relative_to(result), 'synthetic_output_must_be_separate_from_case')
    require(not result.exists(), 'synthetic_output_already_exists')
    return result


@_offline
def prepare(directory, output):
    _linux(); case, ref = _case_reference(directory); destination = _destination(output, case)
    now = int(time.time())
    value = {'schema': 'paw-s14-synthetic-request-v1', 'request_id': uuid.uuid4().hex,
             'profile': PROFILE, 'fixture': FIXTURE, 'fixture_sha256': FIXTURE_SHA256,
             'created_at': now, 'expires_at': now + 900, 'case_reference': ref,
             'case_reference_sha256': digest(canonical(ref))}
    raw = canonical(value); validate_request(raw)
    require(_case_reference(case)[1] == ref, 'synthetic_case_changed_during_prepare')
    destination.parent.mkdir(parents=True, exist_ok=True); destination.mkdir(mode=0o700)
    with (destination / 'request.json').open('xb') as stream: stream.write(raw)
    (destination / 'request.json').chmod(0o400)
    return {'status': 'prepared', 'request': str(destination / 'request.json'), 'request_id': value['request_id'],
            'request_sha256': digest(raw), 'scope': 'one fixed harmless no-NIC fixture; no execution requested from PAW'}


@contextmanager
def _trusted_export(request_id):
    # Walk the fixed root from / using descriptor-relative no-follow opens.
    _linux(); fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in [*EXPORT_ROOT.parts[1:], request_id]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'synthetic_untrusted_export_directory')
        yield fd
    finally: os.close(fd)


def validate_receipt(raw, request, request_sha256, now=None):
    value = _decode(raw, RECEIPT_LIMIT)
    require(type(value) is dict and set(value) == {'schema', 'request_id', 'request_sha256', 'case_reference_sha256',
                'profile', 'fixture_sha256', 'producer_kind', 'status', 'runtime', 'artifacts', 'raw_result_sha256'}, 'synthetic_receipt_shape')
    require(value['schema'] == 'paw-s14-synthetic-result-v1' and value['producer_kind'] == 'local-root-verified-no-nic-synthetic' and
            value['status'] == 'completed' and value['profile'] == PROFILE and value['fixture_sha256'] == FIXTURE_SHA256, 'synthetic_receipt_scope')
    require(value['request_id'] == request['request_id'] and value['request_sha256'] == request_sha256 and
            value['case_reference_sha256'] == request['case_reference_sha256'], 'synthetic_receipt_request_binding')
    runtime = value['runtime']
    require(type(runtime) is dict and set(runtime) == {'vm_uuid', 'job_sha256', 'image_sha256', 'source_inventory_sha256',
                'bridge_contract_sha256', 'source_count', 'started_at', 'completed_at', 'stop_seconds', 'writers_stopped'}, 'synthetic_runtime_shape')
    require(type(runtime['vm_uuid']) is str and str(uuid.UUID(runtime['vm_uuid'])) == runtime['vm_uuid'], 'synthetic_vm_identity')
    require(runtime['image_sha256'] == IMAGE_SHA256 and all(_hex(runtime[k]) for k in
            ['job_sha256', 'source_inventory_sha256', 'bridge_contract_sha256']) and _hex(value['raw_result_sha256']), 'synthetic_runtime_digest')
    require(runtime['bridge_contract_sha256'] == digest(Path(__file__).read_bytes()), 'synthetic_bridge_contract_version')
    require(type(runtime['source_count']) is int and 60 <= runtime['source_count'] <= 128, 'synthetic_source_inventory')
    require(type(runtime['started_at']) is int and type(runtime['completed_at']) is int and
            request['created_at'] <= runtime['started_at'] < request['expires_at'] and
            runtime['started_at'] <= runtime['completed_at'] <= (time.time() if now is None else now) + 5, 'synthetic_runtime_clock')
    require(type(runtime['stop_seconds']) in {int, float} and math.isfinite(runtime['stop_seconds']) and
            0 <= runtime['stop_seconds'] < 12 and runtime['writers_stopped'] is True, 'synthetic_unknown_stop')
    artifacts = value['artifacts']
    require(type(artifacts) is list and len(artifacts) == 2, 'synthetic_output_inventory')
    for index, item in enumerate(artifacts):
        require(type(item) is dict and set(item) == {'stored_as', 'bytes', 'sha256'} and
                item['stored_as'] == f'artifact-{index:02d}.bin' and type(item['bytes']) is int and
                0 <= item['bytes'] <= 1024 and _hex(item['sha256']), 'synthetic_output_metadata')
    return value


@_offline
def import_result(directory, request_path, output):
    _linux(); case, ref = _case_reference(directory); destination = _destination(output, case)
    request_raw = _read_regular(request_path, REQUEST_LIMIT)
    # Historical import is allowed; execution itself must have started in the lease.
    decoded = _decode(request_raw, REQUEST_LIMIT)
    require(type(decoded) is dict and type(decoded.get('created_at')) is int, 'synthetic_request_clock')
    request = validate_request(request_raw, now=decoded['created_at'])
    require(ref == request['case_reference'], 'synthetic_request_does_not_match_case')
    with _trusted_export(request['request_id']) as fd:
        require(set(os.listdir(fd)) == {'request.json', 'receipt.json', 'artifact-00.bin', 'artifact-01.bin'}, 'synthetic_export_inventory')
        require(_read_regular('request.json', REQUEST_LIMIT, directory_fd=fd, root_owned=True) == request_raw, 'synthetic_export_request_changed')
        receipt_raw = _read_regular('receipt.json', RECEIPT_LIMIT, directory_fd=fd, root_owned=True)
        receipt = validate_receipt(receipt_raw, request, digest(request_raw))
        data = []
        for item in receipt['artifacts']:
            raw = _read_regular(item['stored_as'], 1024, directory_fd=fd, root_owned=True)
            require(len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'synthetic_export_output_digest')
            data.append(raw)
    require(data == [MARKER, b''], 'synthetic_positive_marker_required')
    require(_case_reference(case)[1] == ref, 'synthetic_case_changed_during_import')
    destination.parent.mkdir(parents=True, exist_ok=True); destination.mkdir(mode=0o700)
    pending = destination / 'pending'; pending.mkdir(mode=0o700)
    (pending / 'request.json').write_bytes(request_raw); (pending / 'receipt.json').write_bytes(receipt_raw)
    for index, raw in enumerate(data): (pending / f'artifact-{index:02d}.bin').write_bytes(raw)
    (pending / 'result.json').write_bytes(canonical({'status': 'completed', 'profile': PROFILE, 'case_reference': ref,
        'request_sha256': digest(request_raw), 'meaning': 'fixed synthetic execution only; not an email verdict or isolation certification',
        'producer_trust': 'local root-owned export; not a remote signature or content authenticity proof'}))
    from .evidence import seal_case
    from .verify import verify_case
    seal_case(pending)
    with redirect_stdout(io.StringIO()): valid = verify_case(pending)
    require(valid and _case_reference(case)[1] == ref, 'synthetic_publication_integrity')
    # The only published stable result is an already-sealed private child directory.
    os.rename(pending, destination / 'result')
    return {'status': 'completed', 'result': str(destination / 'result'), 'request_id': request['request_id'],
            'case_unchanged': True, 'scope': 'fixed harmless fixture; opaque data; no risk/score interpretation'}
