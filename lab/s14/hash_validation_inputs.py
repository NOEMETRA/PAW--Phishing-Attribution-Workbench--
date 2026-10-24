"""Generate fresh owned harmless approval inputs, never execution authority."""
import hashlib
import uuid

from owned_grant_fixtures import SOURCES

CASES=('positive','failed','timeout','cancel','overflow','paused-refusal','owner-loss','protocol-loss')


def generate():
    nonce=uuid.uuid4().hex;inputs=[]
    for case in CASES:
        original=SOURCES[case if case in SOURCES else 'positive']
        # New bytes for every case and run, outside both historical catalogues.
        source=(b'# Owned harmless per-hash validation '+nonce.encode()+b' '+case.encode()+b'\n'+original)
        if case=='positive':
            source+=b"import platform\nassert platform.release()=='6.8.0-147-generic'\nprint('OWNED-HASH-VALIDATION-"+nonce.encode()+b"')\n"
        assert source not in SOURCES.values()
        inputs.append({'case':case,'source_hex':source.hex(),'source_sha256':hashlib.sha256(source).hexdigest()})
    return {'schema':'paw-s14-owned-hash-inputs-v2','nonce':nonce,'inputs':inputs,
            'meaning':'owned harmless approval input bytes; no runtime authority from this file alone'}


def parse(raw):
    import json,re
    from offline_candidate import require,MAX_SOURCE
    require(type(raw) is bytes and len(raw)<=320*1024,'approval_manifest_budget')
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'approval_manifest_duplicate');result[key]=value
        return result
    try:value=json.loads(raw,object_pairs_hook=pairs)
    except (RecursionError,UnicodeError) as error:raise ValueError('approval_manifest_json') from error
    require(type(value) is dict and set(value)=={'schema','nonce','inputs','meaning'} and
            value['schema']=='paw-s14-owned-hash-inputs-v2','approval_manifest_shape')
    require(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}',value['nonce']),'approval_nonce')
    require(value['meaning']=='owned harmless approval input bytes; no runtime authority from this file alone','approval_meaning')
    entries=value['inputs'];require(type(entries) is list and len(entries)==len(CASES),'approval_cases')
    seen=set();hashes=set()
    for entry in entries:
        require(type(entry) is dict and set(entry)=={'case','source_hex','source_sha256'},'approval_entry')
        case=entry['case'];require(type(case) is str and case in CASES and case not in seen,'approval_case');seen.add(case)
        encoded=entry['source_hex'];require(type(encoded) is str and 0<len(encoded)<=2*MAX_SOURCE and len(encoded)%2==0 and
                re.fullmatch('[0-9a-f]+',encoded),'approval_source_encoding')
        content=bytes.fromhex(encoded);content.decode('utf-8',errors='strict');require(b'\0' not in content,'approval_source_nul')
        require(entry['source_sha256']==hashlib.sha256(content).hexdigest() and entry['source_sha256'] not in hashes,'approval_source_hash')
        hashes.add(entry['source_sha256'])
    return value
