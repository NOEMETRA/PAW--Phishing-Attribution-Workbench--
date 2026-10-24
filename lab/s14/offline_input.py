"""Immutable offline Python job admission; no sample is executed on this host."""
import argparse
import hashlib
import json
import re
import sys
import time

PROFILE = 'linux-python-offline-v1'
MAX_SOURCE = 16384
MAX_FRAME = MAX_SOURCE * 2 + 4096


def decode(raw):
    if type(raw) is not bytes or len(raw) > MAX_FRAME:
        raise ValueError('job_frame_budget')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def admit(value, now=None):
    """Return a detached canonical job. A digest is integrity, not authorization."""
    required = {'profile', 'job_id', 'parent_sha256', 'source_hex', 'source_sha256',
                'operator_authorization', 'created_at', 'expires_at'}
    if type(value) is not dict or set(value) != required: raise ValueError('job_shape')
    if value['profile'] != PROFILE: raise ValueError('unsupported_profile')
    if type(value['job_id']) is not str or re.fullmatch('[a-z0-9-]{1,48}', value['job_id']) is None:
        raise ValueError('job_id')
    for key in ['parent_sha256', 'source_sha256']:
        if type(value[key]) is not str or re.fullmatch('[0-9a-f]{64}', value[key]) is None: raise ValueError(key)
    if value['operator_authorization'] != 'synthetic-only-this-pc': raise ValueError('authorization_scope')
    for key in ['created_at', 'expires_at']:
        if type(value[key]) is not int: raise ValueError('job_clock_type')
    current = time.time() if now is None else now
    if not value['created_at'] <= current < value['expires_at'] <= value['created_at'] + 900:
        raise ValueError('job_expired_or_unbounded')
    encoded = value['source_hex']
    if type(encoded) is not str or not 0 < len(encoded) <= MAX_SOURCE * 2 or len(encoded) % 2 or re.fullmatch('[0-9a-f]+', encoded) is None:
        raise ValueError('source_budget_or_encoding')
    source = bytes.fromhex(encoded)
    source.decode('utf-8', errors='strict')
    if b'\0' in source or hashlib.sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('source_digest_or_nul')
    result = json.loads(json.dumps(value))
    canonical = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    return {'job': result, 'job_sha256': hashlib.sha256(canonical).hexdigest(),
            'source': source, 'profile': PROFILE, 'network': 'no-nic',
            'authorization': 'synthetic-only; runtime must independently match its trusted catalog'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate-stdin', action='store_true', required=True)
    parser.parse_args()
    result = admit(decode(sys.stdin.buffer.read(MAX_FRAME + 1)))
    print(json.dumps({k: v for k, v in result.items() if k != 'source'}))


if __name__ == '__main__': main()
