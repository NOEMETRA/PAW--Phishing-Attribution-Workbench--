"""Fresh owned inert HTML source manifest; bytes never execute on the host."""
import hashlib
import json
import re
import time
import uuid

from browser_authorization import canonical, require, digest, contract

CASES = ('positive', 'script-error', 'timeout', 'cancel', 'overflow', 'memory',
         'paused-refusal', 'owner-loss', 'protocol-loss')


def make(nonce):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'owned_browser_nonce')
    title = 'PAW-'+nonce
    positive = ('<!doctype html><meta charset="utf-8"><title>before</title>'
                '<script>document.title="'+title+'"</script><p>Owned no-NIC browser acceptance.</p>').encode()
    sources = {
        'positive': positive,
        'script-error': ('<title>'+title+'</title><script>throw new Error("Owned intentional exception")</script>').encode(),
        'timeout': b'<title>owned-timeout</title><script>for(;;){}</script>',
        'cancel': b'<title>owned-cancel</title><script>for(;;){}</script>',
        'overflow': b'<title>owned-output</title><body><script>document.body.textContent="X".repeat(300000)</script>',
        # One retained allocation larger than the unchanged512MiB job cgroup,
        # with a store to every page. Repeated64MiB fill allocations can spend
        # the15s deadline reclaiming without ever producing an OOM kill.
        'memory': b'<title>owned-memory</title><script>const a=new Uint8Array(1024*1024*1024);for(let i=0;i<a.length;i+=4096){a[i]=7;}for(;;){}</script>',
        'paused-refusal': positive,
        **{case: b'<title>owned-fault-loop</title><script>for(;;){}</script>' for case in ['owner-loss', 'protocol-loss']},
    }
    value = {'schema': 'paw-s14-owned-browser-inputs-v1', 'scope': 'owned harmless HTML only; no host execution or real samples',
             'nonce': nonce, 'inputs': [{'case': case, 'source_hex': sources[case].hex(),
                'source_sha256': digest(sources[case])} for case in CASES]}
    return canonical(value)


def parse(raw):
    value = json.loads(raw)
    require(raw == canonical(value) and type(value) is dict and
            set(value) == {'schema', 'scope', 'nonce', 'inputs'} and
            value['schema'] == 'paw-s14-owned-browser-inputs-v1' and
            value['scope'] == 'owned harmless HTML only; no host execution or real samples' and
            type(value['nonce']) is str and re.fullmatch('[0-9a-f]{16}', value['nonce']) and
            type(value['inputs']) is list and len(value['inputs']) == len(CASES), 'owned_browser_manifest')
    require(raw == make(value['nonce']), 'owned_browser_manifest_exact_generated_bytes')
    return value


def frame(entry, nonce):
    source = bytes.fromhex(entry['source_hex']); now = int(time.time())
    parent = digest(('Owned synthetic browser parent '+nonce+'/'+entry['case']).encode())
    value = {'schema': 'paw-s14-browser-candidate-v1', 'profile': contract.PROFILE,
             'request_id': uuid.uuid4().hex, 'case_reference_sha256': parent,
             'source': {'media_type': 'text/html', 'encoding': 'opaque', 'bytes': len(source),
                        'sha256': digest(source), 'data_hex': source.hex()},
             'provenance': {'kind': 'operator-supplied', 'reference': 'PAW sealed-case HTML attachment; custody only'},
             'created_at': now, 'expires_at': now+900, 'purpose': 'offline-html-single-job-review'}
    raw = canonical(value); contract.validate_frame(raw); return raw
