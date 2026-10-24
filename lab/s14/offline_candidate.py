"""Data-only preparation boundary for a future offline Python input adapter.

Validation is not authorization. No launcher consumes this schema. Content is
never imported, compiled, resolved or executed on the development host.
"""
import argparse
import hashlib
import json
import re
import sys
import time

PROFILE = 'linux-python-offline-v1'
MAX_SOURCE = 16384
MAX_FRAME = 2 * MAX_SOURCE + 4096
REQUIRED_ACCEPTANCE = (
    'independent-I08-effective-platform-and-maintenance-review',
    'reviewed-single-job-operator-authorization-and-replay-ledger',
    'same-adapter-harmless-runtime-failure-and-publication-matrix',
    'separate-PAW-noncatalog-request-and-result-contract',
)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_FRAME, 'candidate_frame_budget')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'candidate_duplicate_key')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('candidate_nonfinite_json')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError('candidate_json_encoding_or_depth') from error


def inspect_candidate(raw, now=None):
    """Validate exact bytes and return metadata only; always execution-disabled.

    Parent/provenance are operator claims, not proof of PAW custody/authenticity.
    An eventual root adapter must separately admit and freeze the original frame.
    """
    value = decode(raw)
    require(type(value) is dict and set(value) == {
        'schema', 'profile', 'request_id', 'case_reference_sha256', 'source',
        'provenance', 'created_at', 'expires_at', 'purpose'}, 'candidate_shape')
    require(value['schema'] == 'paw-s14-offline-candidate-v1' and
            value['profile'] == PROFILE and value['purpose'] == 'offline-single-job-review', 'candidate_scope')
    require(type(value['request_id']) is str and re.fullmatch('[0-9a-f]{32}', value['request_id']), 'candidate_id')
    require(type(value['case_reference_sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', value['case_reference_sha256']), 'candidate_parent_hash')
    for key in ['created_at', 'expires_at']:
        require(type(value[key]) is int, 'candidate_clock_type')
    current = time.time() if now is None else now
    require(value['created_at'] <= current < value['expires_at'] <= value['created_at'] + 900, 'candidate_expired_or_unbounded')
    provenance = value['provenance']
    require(type(provenance) is dict and set(provenance) == {'kind', 'reference'} and
            provenance['kind'] == 'operator-supplied' and type(provenance['reference']) is str and
            re.fullmatch('[\x20-\x7e]{1,256}', provenance['reference']) and
            provenance['reference'].strip(), 'candidate_provenance')
    source = value['source']
    require(type(source) is dict and set(source) == {'media_type', 'encoding', 'bytes', 'sha256', 'data_hex'}, 'candidate_source_shape')
    require(source['media_type'] == 'text/x-python' and source['encoding'] == 'utf-8', 'candidate_source_type')
    require(type(source['bytes']) is int and 0 < source['bytes'] <= MAX_SOURCE, 'candidate_source_budget')
    encoded = source['data_hex']
    require(type(encoded) is str and len(encoded) == source['bytes'] * 2 and
            re.fullmatch('[0-9a-f]+', encoded), 'candidate_source_encoding')
    content = bytes.fromhex(encoded)
    try:
        content.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('candidate_source_utf8') from error
    require(b'\0' not in content, 'candidate_source_nul')
    digest = hashlib.sha256(content).hexdigest()
    require(source['sha256'] == digest, 'candidate_source_digest')
    return {'status': 'valid-review-candidate', 'request_id': value['request_id'], 'profile': PROFILE,
            'frame_sha256': hashlib.sha256(raw).hexdigest(),
            'candidate_sha256': hashlib.sha256(canonical(value)).hexdigest(),
            'case_reference_sha256': value['case_reference_sha256'],
            'source_sha256': digest, 'source_bytes': len(content),
            'execution_authorized': False, 'runtime_adapter': 'unavailable',
            'provenance_meaning': 'operator claim only; no authenticity or PAW custody proof',
            'required_acceptance': list(REQUIRED_ACCEPTANCE)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspect-stdin', action='store_true', required=True)
    parser.parse_args()
    try:
        result = inspect_candidate(sys.stdin.buffer.read(MAX_FRAME + 1))
    except (ValueError, TypeError) as error:
        print(json.dumps({'status': 'refused', 'execution_authorized': False, 'error': str(error)}))
        raise SystemExit(2)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
