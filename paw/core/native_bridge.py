"""Separate finite Linux custody contract; never a host or guest launcher.

Only exact explicitly selected shell/AMD64 ELF bytes are transported. Legacy
Python/HTML request, receipt and grant namespaces remain unsupported here.
Native Root authority and scoped no-NIC readiness are separate prerequisites.
"""
from contextlib import contextmanager, redirect_stdout
import io
import math
import os
from pathlib import Path
import re
import time
import uuid

from . import synthetic_bridge as shared
from . import representation_bridge as lineage
from . import linux_profiles

# Reuse bounded lineage parsing, without changing the P3 contract or its limits.
_decode, _nodes, _ancestors = lineage._decode, lineage._nodes, lineage._ancestors
_directory = lineage._directory

canonical, digest, require = shared.canonical, shared.digest, shared.require
EXPORT_ROOT = Path('/var/lib/paw-s14-native-exports')
REQUEST_LIMIT = 4 * 1024**2
GRAPH_LIMIT = 768 * 1024
RECEIPT_LIMIT = 16384
PROFILES = linux_profiles.PROFILES
STATUSES = {'completed', 'failed', 'timeout', 'cancelled', 'output_budget', 'memory_budget'}


def contract_hash():
    # Bind the explicitly shared validators and admission implementation too.
    modules = {'native': Path(__file__), 'lineage': Path(lineage.__file__),
               'admission': Path(linux_profiles.__file__), 'shared': Path(shared.__file__)}
    return digest(canonical({name: digest(path.read_bytes()) for name, path in modules.items()}))


def validate_request(raw, now=None):
    value = _decode(raw, REQUEST_LIMIT)
    require(raw == canonical(value) and type(value) is dict and
            set(value) == {'schema', 'binding', 'candidate'} and
            value['schema'] == 'paw-s14-native-request-v1', 'native_request_shape')
    binding, frame = value['binding'], value['candidate']
    require(type(binding) is dict and set(binding) == {'case_reference', 'original_source', 'graph_sha256',
            'interpretations_sha256', 'case_coverage', 'derivation', 'bridge_contract_sha256'}, 'native_binding_shape')
    ref, original, derivation = binding['case_reference'], binding['original_source'], binding['derivation']
    require(type(ref) is dict and set(ref) == {'case_id', 'manifest_sha256', 'merkle_index_sha256', 'merkle_root_blake3'} and
            type(ref['case_id']) is str and re.fullmatch('case-forensic-[0-9a-f]{32}', ref['case_id']) and
            all(shared._hex(ref[k]) for k in ref if k != 'case_id'), 'native_case_reference')
    require(type(original) is dict and set(original) == {'bytes', 'sha256'} and
            type(original['bytes']) is int and 0 <= original['bytes'] <= 8*1024**2 and
            shared._hex(original['sha256']), 'native_original_source')
    require(shared._hex(binding['graph_sha256']) and shared._hex(binding['interpretations_sha256']) and
            binding['bridge_contract_sha256'] == contract_hash() and type(binding['case_coverage']) is str and
            binding['case_coverage'] in {'partial', 'bounded_views_observed'}, 'native_case_metadata')
    require(type(derivation) is dict and set(derivation) == {'root', 'selected', 'nodes'}, 'native_derivation_shape')
    nodes = _nodes(derivation['nodes'], derivation['root'], original)
    lineage = _ancestors(nodes, derivation['selected'])
    require(lineage == derivation['nodes'], 'native_unrelated_derivation_node')
    selected = nodes[derivation['selected']]
    require(type(frame) is dict and set(frame) == {'schema', 'profile', 'request_id', 'selection_binding_sha256',
            'source', 'provenance', 'created_at', 'expires_at', 'purpose'}, 'native_candidate_shape')
    profiles = {spec.engine: (name, spec) for name, spec in PROFILES.items()}
    require(frame['schema'] == 'paw-s14-native-candidate-v1' and type(frame['profile']) is str and
            frame['profile'] in profiles and frame['purpose'] == 'offline-explicit-native-selection-v1' and
            type(frame['request_id']) is str and re.fullmatch('[0-9a-f]{32}', frame['request_id']) and
            frame['selection_binding_sha256'] == digest(canonical(binding)), 'native_candidate_binding')
    require(frame['provenance'] == {'kind': 'operator-selected-forensic-representation',
            'origin_verified': False, 'interpretation_authenticated': False, 'execution_authority': 'none'},
            'native_custody_not_authenticity')
    require(type(frame['created_at']) is int and type(frame['expires_at']) is int and
            frame['created_at'] <= (time.time() if now is None else now) < frame['expires_at'] <= frame['created_at']+900,
            'native_candidate_lease')
    source = frame['source']; name, spec = profiles[frame['profile']]
    maximum, media_type = spec.maximum_bytes, spec.media_type
    require(type(source) is dict and set(source) == {'media_type', 'encoding', 'bytes', 'sha256', 'data_hex'} and
            source['media_type'] == media_type and source['encoding'] == 'opaque' and
            type(source['bytes']) is int and 0 < source['bytes'] <= maximum and
            type(source['data_hex']) is str and len(source['data_hex']) == 2*source['bytes'] and
            re.fullmatch('[0-9a-f]+', source['data_hex']), 'native_profile_source')
    data = bytes.fromhex(source['data_hex'])
    require(source['sha256'] == digest(data) == selected['sha256'] and
            source['bytes'] == selected['bytes'], 'native_selected_bytes')
    linux_profiles.inspect_source(name, data)
    return value


def _selection(case, ref, selected):
    with _directory(case) as fd:
        manifest = _decode(shared._read_regular('manifest.json', 1024**2, directory_fd=fd), 1024**2)
        require(manifest.get('schema') == 'paw-forensic-case-v1' and
                manifest.get('case_kind') == 'forensic_representations' and manifest.get('case_id') == ref['case_id'] and
                manifest.get('classification') == 'not_evaluated' and manifest.get('execution_authority') == 'none',
                'native_forensic_case_required')
        source = manifest.get('source')
        require(type(source) is dict and set(source) == {'path', 'bytes', 'sha256'} and
                source['path'] == 'source.bin' and type(source['bytes']) is int and 0 <= source['bytes'] <= 8*1024**2,
                'native_manifest_source')
        raw = shared._read_regular('source.bin', 8*1024**2, directory_fd=fd)
        require(len(raw) == source['bytes'] and digest(raw) == source['sha256'], 'native_original_changed')
        execution = _decode(shared._read_regular('execution.json', 1024**2, directory_fd=fd), 1024**2)
    with _directory(case/'report') as fd:
        graph_raw = shared._read_regular('representations.json', GRAPH_LIMIT, directory_fd=fd)
        interpretations = shared._read_regular('interpretations.json', 4*1024**2, directory_fd=fd)
    graph = _decode(graph_raw, GRAPH_LIMIT)
    require(type(graph) is dict and graph.get('schema') == 'paw-forensic-representations-v1' and
            graph.get('root') == manifest['representation_root'] and graph.get('source_sha256') == source['sha256'] and
            graph.get('execution_authority') == 'none' and graph.get('origin_verified') is False, 'native_graph_source')
    original = {k: source[k] for k in ['bytes', 'sha256']}
    nodes = _nodes(graph.get('nodes'), graph['root'], original); lineage = _ancestors(nodes, selected)
    node = nodes[selected]
    # Read only a fixed digest-derived basename. No selected path is accepted.
    with _directory(case/'blobs') as fd:
        data = shared._read_regular(node['sha256']+'.bin', 1024**2, directory_fd=fd)
    require(len(data) == node['bytes'] and digest(data) == node['sha256'], 'native_selected_blob_changed')
    return {'case_reference': ref, 'original_source': original, 'graph_sha256': digest(graph_raw),
            'interpretations_sha256': digest(interpretations), 'case_coverage': execution.get('coverage'),
            'derivation': {'root': graph['root'], 'selected': selected, 'nodes': lineage},
            'bridge_contract_sha256': contract_hash()}, data


def _matches(case, request):
    root, ref = shared._case_reference(case)
    binding, data = _selection(root, ref, request['binding']['derivation']['selected'])
    require(binding == request['binding'] and data.hex() == request['candidate']['source']['data_hex'],
            'native_request_does_not_match_case')


@shared._offline
def prepare(directory, selected, profile, output):
    shared._linux(); require(type(profile) is str and profile in PROFILES, 'native_profile_not_supported')
    case, ref = shared._case_reference(directory); destination = shared._destination(output, case)
    binding, data = _selection(case, ref, selected); now = int(time.time())
    spec = PROFILES[profile]; engine, media_type = spec.engine, spec.media_type
    frame = {'schema': 'paw-s14-native-candidate-v1', 'profile': engine, 'request_id': uuid.uuid4().hex,
             'selection_binding_sha256': digest(canonical(binding)),
             'source': {'media_type': media_type, 'encoding': 'opaque', 'bytes': len(data), 'sha256': digest(data), 'data_hex': data.hex()},
             'provenance': {'kind': 'operator-selected-forensic-representation', 'origin_verified': False,
                            'interpretation_authenticated': False, 'execution_authority': 'none'},
             'created_at': now, 'expires_at': now+900, 'purpose': 'offline-explicit-native-selection-v1'}
    raw = canonical({'schema': 'paw-s14-native-request-v1', 'binding': binding, 'candidate': frame})
    request = validate_request(raw); _matches(case, request)
    destination.parent.mkdir(parents=True, exist_ok=True); destination.mkdir(mode=0o700)
    for name, content in [('request.json', raw), ('candidate.json', canonical(frame))]:
        fd = os.open(destination/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as stream: stream.write(content)
    return {'status': 'prepared', 'request': str(destination/'request.json'), 'request_sha256': digest(raw),
            'candidate': str(destination/'candidate.json'), 'candidate_sha256': digest(canonical(frame)),
            'source_sha256': digest(data), 'selected_node': selected, 'request_id': frame['request_id'],
            'execution_authorized': False, 'scope': 'custody only; separate native hash grant and scoped no-NIC I08 required'}


def validate_receipt(raw, request, request_sha256, now=None):
    value = _decode(raw, RECEIPT_LIMIT); frame = request['candidate']
    require(raw == canonical(value) and type(value) is dict and set(value) == {'schema', 'producer_kind',
            'request_id', 'request_sha256', 'candidate_sha256', 'selection_binding_sha256', 'source_sha256',
            'profile', 'execution_status', 'runtime', 'artifacts'}, 'native_receipt_shape')
    require(value['schema'] == 'paw-s14-native-result-v1' and
            value['producer_kind'] == 'local-root-verified-native-no-nic-v1' and
            value['request_id'] == frame['request_id'] and value['request_sha256'] == request_sha256 and
            value['candidate_sha256'] == digest(canonical(frame)) and value['profile'] == frame['profile'] and
            value['selection_binding_sha256'] == frame['selection_binding_sha256'] and
            value['source_sha256'] == frame['source']['sha256'] and type(value['execution_status']) is str and
            value['execution_status'] in STATUSES, 'native_receipt_binding')
    runtime = value['runtime']
    hashes = {'job_sha256', 'raw_result_sha256', 'source_inventory_sha256', 'policy_sha256', 'grant_sha256',
              'readiness_sha256', 'consumption_sha256', 'bridge_contract_sha256', 'image_certificate_sha256', 'context_sha256'}
    require(type(runtime) is dict and set(runtime) == hashes | {'vm_uuid', 'image_sha256', 'source_count',
            'admitted_at', 'completed_at', 'stop_seconds', 'writers_stopped', 'network_interfaces'}, 'native_runtime_shape')
    require(all(shared._hex(runtime[k]) for k in hashes) and runtime['bridge_contract_sha256'] == contract_hash() and
            shared._hex(runtime['image_sha256']) and type(runtime['vm_uuid']) is str and
            str(uuid.UUID(runtime['vm_uuid'])) == runtime['vm_uuid'] and type(runtime['source_count']) is int and
            60 <= runtime['source_count'] <= 256 and runtime['network_interfaces'] == [] and
            type(runtime['admitted_at']) is int and type(runtime['completed_at']) is int and
            frame['created_at'] <= runtime['admitted_at'] < frame['expires_at'] and
            runtime['admitted_at'] <= runtime['completed_at'] <= (time.time() if now is None else now)+5 and
            runtime['writers_stopped'] is True and type(runtime['stop_seconds']) in {int, float} and
            math.isfinite(runtime['stop_seconds']) and 0 <= runtime['stop_seconds'] < 12, 'native_runtime_identity_or_stop')
    require(type(value['artifacts']) is list and len(value['artifacts']) <= 4, 'native_artifact_count')
    for index, item in enumerate(value['artifacts']):
        require(type(item) is dict and set(item) == {'stored_as', 'bytes', 'sha256'} and
                item['stored_as'] == f'artifact-{index:02d}.bin' and type(item['bytes']) is int and
                0 <= item['bytes'] <= 1024 and shared._hex(item['sha256']), 'native_artifact_metadata')
    return value


@contextmanager
def trusted_export(identifier):
    require(type(identifier) is str and re.fullmatch('[0-9a-f]{32}', identifier), 'native_export_id')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in [*EXPORT_ROOT.parts[1:], identifier]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child; info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'native_untrusted_export_directory')
        yield fd
    finally: os.close(fd)



def _write_private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(raw)


@shared._offline
def import_result(directory, request_path, output):
    shared._linux(); case, _ = shared._case_reference(directory); destination = shared._destination(output, case)
    raw = shared._read_regular(request_path, REQUEST_LIMIT); decoded = _decode(raw, REQUEST_LIMIT)
    require(type(decoded) is dict and type(decoded.get('candidate')) is dict and
            type(decoded['candidate'].get('created_at')) is int, 'native_historical_request_clock')
    request = validate_request(raw, now=decoded['candidate']['created_at']); _matches(case, request)
    rid = request['candidate']['request_id']
    with trusted_export(rid) as fd:
        receipt_raw = shared._read_regular('receipt.json', RECEIPT_LIMIT, directory_fd=fd, root_owned=True)
        receipt = validate_receipt(receipt_raw, request, digest(raw))
        require(set(os.listdir(fd)) == {'request.json', 'receipt.json'} | {item['stored_as'] for item in receipt['artifacts']},
                'native_export_inventory')
        require(shared._read_regular('request.json', REQUEST_LIMIT, directory_fd=fd, root_owned=True) == raw,
                'native_export_request_changed')
        data = []
        for item in receipt['artifacts']:
            blob = shared._read_regular(item['stored_as'], 1024, directory_fd=fd, root_owned=True)
            require(len(blob) == item['bytes'] and digest(blob) == item['sha256'], 'native_artifact_digest')
            data.append(blob)
    _matches(case, request)
    destination.parent.mkdir(parents=True, exist_ok=True); destination.mkdir(mode=0o700)
    pending = destination/'pending'; pending.mkdir(mode=0o700)
    _write_private(pending/'request.json', raw); _write_private(pending/'receipt.json', receipt_raw)
    for index, blob in enumerate(data): _write_private(pending/f'artifact-{index:02d}.bin', blob)
    _write_private(pending/'result.json', canonical({'status': 'collected', 'execution_status': receipt['execution_status'],
        'selection_binding': request['binding'], 'request_sha256': digest(raw), 'original_case_modified': False,
        'meaning': 'opaque no-NIC execution evidence, no classification, origin authentication or attribution',
        'producer_trust': 'local root-protected export, not remote attestation'}))
    from .evidence import seal_case
    from .verify import verify_case
    seal_case(pending)
    # Fresh generated seal files are opaque too; parent is already private.
    for path in (pending/'evidence').iterdir(): path.chmod(0o600)
    (pending/'evidence').chmod(0o700)
    with redirect_stdout(io.StringIO()): valid = verify_case(pending)
    require(valid, 'native_sidecar_integrity'); _matches(case, request)
    os.rename(pending, destination/'result')
    return {'status': 'collected', 'execution_status': receipt['execution_status'], 'result': str(destination/'result'),
            'request_id': rid, 'case_unchanged': True, 'scope': 'opaque evidence; original and scoring unchanged'}
