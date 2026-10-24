"""Case-bound offline Python handoff and sealed opaque sidecars; never a launcher."""
from contextlib import contextmanager, redirect_stdout
import io
import json
import math
import os
from pathlib import Path
import re
import time
import uuid

from . import synthetic_bridge as shared

canonical = shared.canonical
digest = shared.digest
require = shared.require
EXPORT_ROOT = Path('/var/lib/paw-s14-case-exports')
REQUEST_LIMIT = 48 * 1024
RECEIPT_LIMIT = 16384
MAX_SOURCE = 16384
STATUSES = {'completed', 'failed', 'timeout', 'cancelled', 'output_budget'}


def contract_hash():
    return digest(Path(__file__).read_bytes())


def validate_request(raw, now=None):
    value = shared._decode(raw, REQUEST_LIMIT)
    require(raw == canonical(value) and type(value) is dict and
            set(value) == {'schema', 'binding', 'candidate'} and
            value['schema'] == 'paw-s14-case-request-v1', 'case_request_shape')
    binding, frame = value['binding'], value['candidate']
    require(type(binding) is dict and set(binding) == {'case_reference', 'attachment_path', 'part_id',
            'source_sha256', 'bridge_contract_sha256'}, 'case_binding_shape')
    ref = binding['case_reference']
    require(type(ref) is dict and set(ref) == {'case_id', 'manifest_sha256', 'merkle_index_sha256',
            'merkle_root_blake3'} and type(ref['case_id']) is str and
            re.fullmatch(r'case-[A-Za-z0-9_:-]{1,120}', ref['case_id']) and
            all(shared._hex(ref[k]) for k in ref if k != 'case_id'), 'case_reference')
    require(type(binding['attachment_path']) is str and
            re.fullmatch(r'attachments/part-[0-9-]+-[0-9a-f]{64}\.bin', binding['attachment_path']) and
            type(binding['part_id']) is str and re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', binding['part_id']) and
            shared._hex(binding['source_sha256']) and binding['bridge_contract_sha256'] == contract_hash(), 'case_attachment_binding')
    require(binding['attachment_path'] == 'attachments/part-' + binding['part_id'].replace('.', '-') +
            '-' + binding['source_sha256'] + '.bin', 'case_attachment_path_digest')
    require(type(frame) is dict and set(frame) == {'schema', 'profile', 'request_id', 'case_reference_sha256',
            'source', 'provenance', 'created_at', 'expires_at', 'purpose'}, 'case_candidate_shape')
    require(frame['schema'] == 'paw-s14-offline-candidate-v1' and frame['profile'] == shared.PROFILE and
            frame['purpose'] == 'offline-single-job-review' and type(frame['request_id']) is str and
            re.fullmatch('[0-9a-f]{32}', frame['request_id']) and
            frame['case_reference_sha256'] == digest(canonical(binding)), 'case_candidate_binding')
    require(frame['provenance'] == {'kind': 'operator-supplied', 'reference': 'PAW sealed-case attachment; custody only'},
            'case_provenance')
    require(type(frame['created_at']) is int and type(frame['expires_at']) is int and
            frame['created_at'] <= (time.time() if now is None else now) < frame['expires_at'] <= frame['created_at'] + 900,
            'case_candidate_lease')
    source = frame['source']
    require(type(source) is dict and set(source) == {'media_type', 'encoding', 'bytes', 'sha256', 'data_hex'} and
            source['media_type'] == 'text/x-python' and source['encoding'] == 'utf-8' and
            type(source['bytes']) is int and 0 < source['bytes'] <= MAX_SOURCE and
            type(source['data_hex']) is str and len(source['data_hex']) == 2 * source['bytes'] and
            re.fullmatch('[0-9a-f]+', source['data_hex']), 'case_source_budget_or_type')
    data = bytes.fromhex(source['data_hex'])
    data.decode('utf-8', errors='strict')
    require(b'\0' not in data and source['sha256'] == digest(data) == binding['source_sha256'], 'case_source_digest')
    return value


def _attachment(case, relative):
    # The sealed inventory owns the path; MIME filenames are never opened.
    require(type(relative) is str and re.fullmatch(r'attachments/part-[0-9-]+-[0-9a-f]{64}\.bin', relative),
            'case_attachment_path')
    inventory = shared._decode(shared._read_regular(case / 'attachments.json', 4 * 1024**2), 4 * 1024**2)
    require(type(inventory) is list and len(inventory) <= 10000, 'case_attachment_inventory')
    matches = [row for row in inventory if type(row) is dict and row.get('evidence_path') == relative]
    require(len(matches) == 1, 'case_attachment_not_unique')
    row = matches[0]
    require(type(row.get('filename')) is str and row['filename'].lower().endswith('.py') and
            not row.get('decoding_defects') and not row.get('transfer_decoding') and not row.get('original_wire'),
            'case_python_ingress_only_no_ambiguous_decoding')
    fd = os.open(case / 'attachments', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: data = shared._read_regular(Path(relative).name, MAX_SOURCE, directory_fd=fd)
    finally: os.close(fd)
    require(row.get('sha256') == digest(data) and type(row.get('size')) is int and row['size'] == len(data),
            'case_attachment_inventory_digest')
    return row, data


@shared._offline
def prepare(directory, attachment_path, output):
    shared._linux(); case, ref = shared._case_reference(directory)
    destination = shared._destination(output, case); row, data = _attachment(case, attachment_path)
    binding = {'case_reference': ref, 'attachment_path': attachment_path, 'part_id': row['part_id'],
               'source_sha256': digest(data), 'bridge_contract_sha256': contract_hash()}
    now = int(time.time())
    frame = {'schema': 'paw-s14-offline-candidate-v1', 'profile': shared.PROFILE, 'request_id': uuid.uuid4().hex,
             'case_reference_sha256': digest(canonical(binding)), 'source': {'media_type': 'text/x-python',
             'encoding': 'utf-8', 'bytes': len(data), 'sha256': digest(data), 'data_hex': data.hex()},
             'provenance': {'kind': 'operator-supplied', 'reference': 'PAW sealed-case attachment; custody only'},
             'created_at': now, 'expires_at': now + 900, 'purpose': 'offline-single-job-review'}
    raw = canonical({'schema': 'paw-s14-case-request-v1', 'binding': binding, 'candidate': frame})
    validate_request(raw)
    require(shared._case_reference(case)[1] == ref and _attachment(case, attachment_path)[1] == data,
            'case_changed_during_prepare')
    destination.parent.mkdir(parents=True, exist_ok=True); destination.mkdir(mode=0o700)
    for name, content in [('request.json', raw), ('candidate.json', canonical(frame))]:
        with (destination / name).open('xb') as stream: stream.write(content)
        (destination / name).chmod(0o400)
    return {'status': 'prepared', 'request': str(destination / 'request.json'), 'request_sha256': digest(raw),
            'candidate': str(destination / 'candidate.json'), 'candidate_sha256': digest(canonical(frame)),
            'source_sha256': digest(data), 'request_id': frame['request_id'], 'execution_authorized': False,
            'scope': 'explicit root hash grant and maintained I08 required; no launch from PAW'}


def validate_receipt(raw, request, request_sha256, now=None):
    value = shared._decode(raw, RECEIPT_LIMIT); frame = request['candidate']
    require(raw == canonical(value) and type(value) is dict and set(value) == {'schema', 'producer_kind',
            'request_id', 'request_sha256', 'candidate_sha256', 'binding_sha256', 'source_sha256',
            'execution_status', 'runtime', 'artifacts'}, 'case_receipt_shape')
    require(value['schema'] == 'paw-s14-case-result-v1' and value['producer_kind'] == 'local-root-verified-hash-offline' and
            value['request_id'] == frame['request_id'] and value['request_sha256'] == request_sha256 and
            value['candidate_sha256'] == digest(canonical(frame)) and value['binding_sha256'] == frame['case_reference_sha256'] and
            value['source_sha256'] == frame['source']['sha256'] and type(value['execution_status']) is str and value['execution_status'] in STATUSES, 'case_receipt_binding')
    runtime = value['runtime']
    hashes = {'job_sha256', 'raw_result_sha256', 'source_inventory_sha256', 'policy_sha256', 'grant_sha256',
              'readiness_sha256', 'consumption_sha256', 'bridge_contract_sha256'}
    require(type(runtime) is dict and set(runtime) == hashes | {'vm_uuid', 'image_sha256', 'source_count',
            'admitted_at', 'completed_at', 'stop_seconds', 'writers_stopped'}, 'case_runtime_shape')
    require(all(shared._hex(runtime[k]) for k in hashes) and runtime['bridge_contract_sha256'] == contract_hash() and
            runtime['image_sha256'] == shared.IMAGE_SHA256 and type(runtime['vm_uuid']) is str and
            str(uuid.UUID(runtime['vm_uuid'])) == runtime['vm_uuid'] and
            type(runtime['source_count']) is int and 60 <= runtime['source_count'] <= 128, 'case_runtime_identity')
    require(type(runtime['admitted_at']) is int and type(runtime['completed_at']) is int and
            frame['created_at'] <= runtime['admitted_at'] < frame['expires_at'] and
            runtime['admitted_at'] <= runtime['completed_at'] <= (time.time() if now is None else now) + 5 and
            runtime['writers_stopped'] is True and type(runtime['stop_seconds']) in {int, float} and
            math.isfinite(runtime['stop_seconds']) and 0 <= runtime['stop_seconds'] < 12, 'case_runtime_stop_or_clock')
    require(type(value['artifacts']) is list and len(value['artifacts']) <= 4, 'case_artifact_count')
    for index, item in enumerate(value['artifacts']):
        require(type(item) is dict and set(item) == {'stored_as', 'bytes', 'sha256'} and
                item['stored_as'] == f'artifact-{index:02d}.bin' and type(item['bytes']) is int and
                0 <= item['bytes'] <= 1024 and shared._hex(item['sha256']), 'case_artifact_metadata')
    return value


@contextmanager
def trusted_export(identifier):
    require(type(identifier) is str and re.fullmatch('[0-9a-f]{32}', identifier), 'case_export_id')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in [*EXPORT_ROOT.parts[1:], identifier]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child; info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'case_untrusted_export_directory')
        yield fd
    finally: os.close(fd)


@shared._offline
def import_result(directory, request_path, output):
    shared._linux(); case, ref = shared._case_reference(directory); destination = shared._destination(output, case)
    raw = shared._read_regular(request_path, REQUEST_LIMIT)
    parsed = shared._decode(raw, REQUEST_LIMIT)
    require(type(parsed) is dict and type(parsed.get('candidate')) is dict and
            type(parsed['candidate'].get('created_at')) is int, 'case_request_clock')
    request = validate_request(raw, now=parsed['candidate']['created_at'])
    require(request['binding']['case_reference'] == ref and
            _attachment(case, request['binding']['attachment_path'])[1].hex() == request['candidate']['source']['data_hex'],
            'case_request_does_not_match_case')
    rid = request['candidate']['request_id']
    with trusted_export(rid) as fd:
        receipt_raw = shared._read_regular('receipt.json', RECEIPT_LIMIT, directory_fd=fd, root_owned=True)
        receipt = validate_receipt(receipt_raw, request, digest(raw))
        require(set(os.listdir(fd)) == {'request.json', 'receipt.json'} | {v['stored_as'] for v in receipt['artifacts']},
                'case_export_inventory')
        require(shared._read_regular('request.json', REQUEST_LIMIT, directory_fd=fd, root_owned=True) == raw,
                'case_export_request_changed')
        data = []
        for item in receipt['artifacts']:
            content = shared._read_regular(item['stored_as'], 1024, directory_fd=fd, root_owned=True)
            require(len(content) == item['bytes'] and digest(content) == item['sha256'], 'case_output_digest')
            data.append(content)
    require(shared._case_reference(case)[1] == ref, 'case_changed_during_import')
    destination.parent.mkdir(parents=True, exist_ok=True); destination.mkdir(mode=0o700)
    pending = destination / 'pending'; pending.mkdir(mode=0o700)
    (pending / 'request.json').write_bytes(raw); (pending / 'receipt.json').write_bytes(receipt_raw)
    for index, content in enumerate(data): (pending / f'artifact-{index:02d}.bin').write_bytes(content)
    (pending / 'result.json').write_bytes(canonical({'status': 'collected', 'execution_status': receipt['execution_status'],
        'case_reference': ref, 'source_sha256': receipt['source_sha256'], 'request_sha256': digest(raw),
        'meaning': 'opaque VM execution evidence; not malware classification, attribution or authenticity',
        'producer_trust': 'local root-protected export, not remote attestation', 'original_case_modified': False}))
    from .evidence import seal_case
    from .verify import verify_case
    seal_case(pending)
    with redirect_stdout(io.StringIO()): valid = verify_case(pending)
    require(valid and shared._case_reference(case)[1] == ref, 'case_publication_integrity')
    os.rename(pending, destination / 'result')
    return {'status': 'collected', 'execution_status': receipt['execution_status'], 'result': str(destination / 'result'),
            'request_id': rid, 'case_unchanged': True, 'scope': 'opaque offline evidence; scoring unchanged'}
