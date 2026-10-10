"""Bounded local key evidence; analyst metadata never establishes DNS trust."""
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 64 * 1024
MAX_RECORDS = 32


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('Duplicate DKIM key evidence field')
        result[key] = value
    return result


def parse_key_evidence(evidence):
    if not isinstance(evidence, dict) or set(evidence) != {'text'} or not isinstance(evidence['text'], str):
        raise ValueError('Invalid DKIM key evidence snapshot')
    raw = evidence['text'].encode('utf-8')
    if len(raw) > MAX_BYTES: raise ValueError('DKIM key evidence exceeds 64 KiB')
    bundle = json.loads(raw, object_pairs_hook=_unique)
    return raw, bundle, validate_key_bundle(bundle)


def validate_key_bundle(bundle):
    if not isinstance(bundle, dict) or set(bundle) != {'schema_version', 'source', 'records'}:
        raise ValueError('DKIM key evidence requires schema_version, source and records')
    if type(bundle['schema_version']) is not int or bundle['schema_version'] != 1:
        raise ValueError('Unsupported DKIM key evidence schema')
    source = bundle['source']
    if not isinstance(source, str) or not source.strip() or len(source) > 1024 or any(ord(c) < 32 for c in source):
        raise ValueError('DKIM key source must be a bounded analyst description')
    supplied = bundle['records']
    if not isinstance(supplied, dict) or len(supplied) > MAX_RECORDS:
        raise ValueError('DKIM key evidence supports at most 32 records')
    records = {}
    for name, value in supplied.items():
        if not isinstance(name, str): raise ValueError('DKIM key names must be strings')
        key = name.lower().removesuffix('.')
        if (len(key) > 253 or not re.fullmatch(r'[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*', key)
                or key.count('._domainkey.') != 1):
            raise ValueError('Invalid DKIM selector record name')
        if key in records: raise ValueError('Duplicate normalized DKIM key name')
        if (not isinstance(value, str) or not value or len(value) > 8192
                or not value.isascii() or any(ord(c) < 32 and c not in '\t\r\n' for c in value)):
            raise ValueError('DKIM TXT records must be bounded ASCII strings')
        records[key] = value
    return records


def snapshot_key_bundle(bundle):
    validate_key_bundle(bundle)
    evidence = {'text': json.dumps(bundle, ensure_ascii=False, separators=(',', ':'))}
    parse_key_evidence(evidence)
    return evidence


def load_key_file(path):
    path = Path(path)
    if str(path).startswith(('\\\\', '//')):
        raise ValueError('DKIM evidence must be a local regular file')
    # Nonblocking open prevents a FIFO from hanging CLI admission. Check the
    # opened descriptor, rather than trusting a pre-open stat or file suffix.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('DKIM evidence must be a local regular file')
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES: raise ValueError('DKIM key evidence exceeds 64 KiB')
    evidence = {'text': raw.decode('utf-8')}
    parse_key_evidence(evidence)
    return evidence
