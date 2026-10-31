"""One fixed owned email -> browser evidence custody; no launcher or real input.

Root's future owned recipe may authorize only SOURCE/SEED from immutable code.
Its SHA256 snapshot binds the supplied parent bytes, without claiming a Root
BLAKE3 seal verification. UID prepare/import independently verify the actual
PAW seal and stopped writers. Caller metadata never grants execution authority.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from . import synthetic_bridge as shared

SOURCE=(b'From: owned-sender@paw-owned.invalid\r\nTo: acceptance@paw-owned.invalid\r\n'
    b'Subject: PAW owned browser pipeline fixture\r\nDate: Sat, 31 Oct 2026 12:00:00 +0000\r\n'
    b'MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'
    b'<!doctype html><title>PAW owned fixture</title><p>Constructed acceptance data, not ground truth.</p>'
    b'<a href="https://paw-owned.invalid/">Owned isolated browser fixture</a>\r\n')
SEED='https://paw-owned.invalid/'
PROFILE='owned-mail-browser-v1'
EXPORT_ROOT=Path('/var/lib/paw-vm-exports')
PARTS={'manifest.json':16384,'url_evidence.json':16384,'execution.json':16384,
       'evidence/inventory_scope.json':4096,'evidence/merkle_index.json':32768}
REQUEST_MAX=128*1024
RECEIPT_MAX=32768
ARTIFACTS={'dom.html':256*1024,'screenshot.png':256*1024,'network.json':1024**2}
LIMITS={'browser_seconds':15,'requests':32,'response_bytes':4*1024**2,
        'dom_bytes':256*1024,'screenshot_bytes':256*1024,'network_bytes':1024**2}
PARENT_SCOPE='Root SHA256 snapshot of supplied owned parent; UID independently verifies BLAKE3 seal'
SANDBOX={'renderer_seen','renderer_nnp','renderer_seccomp','renderer_pid_namespace','all_uids_nonroot'}


def require(v,reason):
    if not v:raise ValueError(reason)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def hex64(v):return type(v)is str and re.fullmatch('[0-9a-f]{64}',v)is not None
def decode(raw,maximum):return shared._decode(raw,maximum)
def decode64(value,maximum):
    require(type(value)is str and len(value)<=4*((maximum+2)//3),'owned_mail_b64_budget')
    raw=base64.b64decode(value,validate=True)
    require(len(raw)<=maximum and base64.b64encode(raw).decode('ascii')==value,'owned_mail_b64_canonical')
    return raw


def validate_request(raw,now=None):
    """Pure fixed-owned admission data. Does not verify a BLAKE3 seal or grant."""
    v=decode(raw,REQUEST_MAX)
    require(type(v)is dict and set(v)=={'schema','state','execution_authority','profile','request_id',
        'created_at','expires_at','case_reference','source_b64','source_sha256','pieces_b64',
        'snapshot_sha256','url_index','url','limits'}and raw==canonical(v),'owned_mail_request_shape')
    require(v['schema']=='paw-owned-mail-browser-request-v1'and v['state']=='PREPARED_NOT_ACTIVE'and
        v['execution_authority']=='none'and v['profile']==PROFILE and type(v['request_id'])is str and
        re.fullmatch('[0-9a-f]{32}',v['request_id']),'owned_mail_not_authority')
    require(canonical(v['limits'])==canonical(LIMITS),'owned_mail_limits')
    current=time.time()if now is None else now
    require(type(v['created_at'])is int and type(v['expires_at'])is int and
        v['created_at']<=current<v['expires_at']<=v['created_at']+900,'owned_mail_request_expired')
    source=decode64(v['source_b64'],65536)
    require(source==SOURCE and v['source_sha256']==digest(SOURCE),'owned_mail_fixed_source_only')
    ref=v['case_reference']
    require(type(ref)is dict and set(ref)=={'case_id','manifest_sha256','merkle_index_sha256','merkle_root_blake3'}and
        type(ref['case_id'])is str and re.fullmatch(r'case-[A-Za-z0-9_:-]{1,120}',ref['case_id'])and
        all(hex64(ref[k])for k in ref if k!='case_id'),'owned_mail_parent_reference')
    require(type(v['pieces_b64'])is dict and set(v['pieces_b64'])==set(PARTS),'owned_mail_snapshot_names')
    pieces={n:decode64(v['pieces_b64'][n],cap)for n,cap in PARTS.items()}
    require(v['snapshot_sha256']=={n:digest(data)for n,data in pieces.items()}and
        ref['manifest_sha256']==digest(pieces['manifest.json'])and
        ref['merkle_index_sha256']==digest(pieces['evidence/merkle_index.json']),'owned_mail_snapshot_binding')
    manifest=decode(pieces['manifest.json'],PARTS['manifest.json'])
    require(type(manifest)is dict and type(manifest.get('case_id'))is str and 'case-'+manifest['case_id']==ref['case_id']and
        type(manifest.get('inputs'))is list and len(manifest['inputs'])==1 and
        type(manifest['inputs'][0])is dict and set(manifest['inputs'][0])=={'path','size','blake3'}and
        manifest['inputs'][0]['path']=='input.eml'and type(manifest['inputs'][0]['size'])is int and
        manifest['inputs'][0]['size']==len(SOURCE)and hex64(manifest['inputs'][0]['blake3']),
        'owned_mail_parent_source_description')
    execution=decode(pieces['execution.json'],PARTS['execution.json'])
    scope=decode(pieces['evidence/inventory_scope.json'],PARTS['evidence/inventory_scope.json'])
    require(type(execution)is dict and execution.get('status')=='completed'and execution.get('no_egress')is True and
        type(scope)is dict and scope.get('policy')=='all_case_files_v1','owned_mail_parent_claim')
    rows=decode(pieces['url_evidence.json'],PARTS['url_evidence.json']);i=v['url_index']
    require(v['url']==SEED and type(rows)is list and 0<len(rows)<=32 and type(i)is int and 0<=i<len(rows)and
        type(rows[i])is dict and rows[i].get('url')==SEED and rows[i].get('network_target')is True,
        'owned_mail_fixed_url_only')
    return v


def _case_snapshot(directory):
    case,ref=shared._case_reference(directory)
    require(shared._read_regular(case/'input.eml',65536)==SOURCE,'owned_mail_fixed_source_only')
    pieces={name:shared._read_regular(case/name,cap)for name,cap in PARTS.items()}
    return case,ref,pieces


def _key(fd):
    s=os.fstat(fd);return s.st_dev,s.st_ino


def _outside(fd,case_key):
    current=os.dup(fd)
    try:
        for _ in range(128):
            here=_key(current);require(here!=case_key,'owned_mail_output_inside_parent')
            parent=os.open('..',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            if _key(parent)==here:os.close(parent);return
            os.close(current);current=parent
        raise ValueError('owned_mail_directory_depth')
    finally:os.close(current)


def _walk(path,create=False,case_key=None):
    path=Path(path);require(path.is_absolute()and len(path.parts)<=64,'owned_mail_absolute_output')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            require(name not in {'','.', '..'},'owned_mail_output_component')
            try:child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:
                require(create,'owned_mail_missing_output_directory')
                if case_key is not None:_outside(fd,case_key)
                try:os.mkdir(name,0o700,dir_fd=fd)
                except FileExistsError:pass
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
            if case_key is not None:_outside(fd,case_key)
        return fd
    except BaseException:os.close(fd);raise


def _new_directory(parent,name,case_key):
    _outside(parent,case_key);os.mkdir(name,0o700,dir_fd=parent)
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
    try:_outside(fd,case_key);return fd
    except BaseException:os.close(fd);raise


def _named_output(path,fd,case_key):
    named=_walk(path,case_key=case_key)
    try:require(_key(named)==_key(fd),'owned_mail_output_directory_changed')
    finally:os.close(named)


@contextmanager
def _output(path,case):
    case_fd=_walk(case)
    try:case_key=_key(case_fd)
    finally:os.close(case_fd)
    parent=_walk(path.parent,create=True,case_key=case_key)
    try:fd=_new_directory(parent,path.name,case_key)
    finally:os.close(parent)
    try:yield fd,case_key
    finally:os.close(fd)


def _write(fd,name,raw,case_key,mode=0o600):
    require(type(name)is str and '/'not in name and name not in {'','.','..'},'owned_mail_output_name')
    _outside(fd,case_key)
    handle=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=fd)
    with os.fdopen(handle,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def _seal_fd(fd,contents,case_key):
    """Same finite-file BLAKE3 case format, written/read via pinned directories."""
    import blake3
    from .evidence import EXCLUDED
    evidence=_new_directory(fd,'evidence',case_key)
    try:
        scope=json.dumps({'policy':'all_case_files_v1','excluded':sorted(EXCLUDED),
            'limitation':'Content integrity; no independent signature, origin or Rekor proof is established'},indent=2).encode()
        _write(evidence,'inventory_scope.json',scope,case_key)
        bodies={**contents,'evidence/inventory_scope.json':scope}
        hashes={name:blake3.blake3(body).hexdigest()for name,body in sorted(bodies.items())}
        index=json.dumps(hashes,indent=2).encode();root=blake3.blake3(''.join(hashes.values()).encode()).hexdigest().encode()
        _write(evidence,'merkle_index.json',index,case_key);_write(evidence,'merkle_root.bin',root,case_key)
        require(set(os.listdir(fd))==set(contents)|{'evidence'}and
            set(os.listdir(evidence))=={'inventory_scope.json','merkle_index.json','merkle_root.bin'},'owned_mail_sidecar_inventory')
        entry=os.stat('evidence',dir_fd=fd,follow_symlinks=False)
        require(stat.S_ISDIR(entry.st_mode)and(entry.st_dev,entry.st_ino)==_key(evidence),'owned_mail_evidence_directory_changed')
        for name,body in contents.items():
            require(shared._read_regular(name,len(body),directory_fd=fd)==body,'owned_mail_sidecar_write_changed')
        for name,body in [('inventory_scope.json',scope),('merkle_index.json',index),('merkle_root.bin',root)]:
            require(shared._read_regular(name,len(body),directory_fd=evidence)==body,'owned_mail_sidecar_seal_changed')
        os.fsync(evidence);os.fsync(fd)
    finally:os.close(evidence)


def _publish(fd,pending):
    import ctypes
    entry=os.stat('pending',dir_fd=fd,follow_symlinks=False)
    require(stat.S_ISDIR(entry.st_mode)and(entry.st_dev,entry.st_ino)==_key(pending),'owned_mail_pending_changed')
    libc=ctypes.CDLL(None,use_errno=True)
    libc.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    libc.renameat2.restype=ctypes.c_int
    # Linux RENAME_NOREPLACE: existing published evidence is never overwritten.
    if libc.renameat2(fd,b'pending',fd,b'result',1)!=0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    entry=os.stat('result',dir_fd=fd,follow_symlinks=False)
    require(stat.S_ISDIR(entry.st_mode)and(entry.st_dev,entry.st_ino)==_key(pending),'owned_mail_publication_changed')
    os.fsync(fd)


@shared._offline
def prepare(directory,output):
    shared._linux();case,ref,pieces=_case_snapshot(directory);dest=shared._destination(output,case)
    rows=decode(pieces['url_evidence.json'],PARTS['url_evidence.json'])
    require(type(rows)is list,'owned_mail_url_inventory')
    indices=[i for i,row in enumerate(rows)if type(row)is dict and row.get('url')==SEED and row.get('network_target')is True]
    require(len(indices)==1,'owned_mail_unique_seed')
    now=int(time.time());v={'schema':'paw-owned-mail-browser-request-v1','state':'PREPARED_NOT_ACTIVE',
        'execution_authority':'none','profile':PROFILE,'request_id':uuid.uuid4().hex,'created_at':now,'expires_at':now+900,
        'case_reference':ref,'source_b64':base64.b64encode(SOURCE).decode('ascii'),'source_sha256':digest(SOURCE),
        'pieces_b64':{n:base64.b64encode(data).decode('ascii')for n,data in pieces.items()},
        'snapshot_sha256':{n:digest(data)for n,data in pieces.items()},'url_index':indices[0],'url':SEED,'limits':dict(LIMITS)}
    raw=canonical(v);validate_request(raw)
    require(_case_snapshot(case)[1:]==(ref,pieces),'owned_mail_case_changed')
    with _output(dest,case)as(fd,case_key):
        _write(fd,'request.json',raw,case_key,0o400)
        require(_case_snapshot(case)[1:]==(ref,pieces),'owned_mail_case_changed_after_prepare')
        _named_output(dest,fd,case_key)
    return {'status':'prepared','request':str(dest/'request.json'),'request_id':v['request_id'],
        'request_sha256':digest(raw),'execution_authorized':False,'scope':'fixed owned email only; no Root call or browser launch'}


def validate_receipt(raw,request,now=None):
    v=decode(raw,RECEIPT_MAX)
    require(type(v)is dict and set(v)=={'schema','profile','producer_kind','request_id','request_sha256',
        'source_sha256','snapshot_sha256','parent_validation','status','fixture_nonce','runtime','artifacts'}and
        raw==canonical(v),'owned_mail_receipt_shape')
    require(v['schema']=='paw-owned-mail-browser-result-v1'and v['profile']==PROFILE and
        v['producer_kind']=='local-root-fixed-owned-browser'and v['parent_validation']==PARENT_SCOPE and
        v['request_id']==request['request_id']and v['request_sha256']==digest(canonical(request))and
        v['source_sha256']==digest(SOURCE)and v['snapshot_sha256']==request['snapshot_sha256']and
        type(v['status'])is str and v['status']in {'completed','failed','timeout','cancelled','refused'}and
        type(v['fixture_nonce'])is str and re.fullmatch('[0-9a-f]{32}',v['fixture_nonce']),'owned_mail_receipt_binding')
    r=v['runtime'];hashes={'context_sha256','image_sha256','chrome_binary_sha256','raw_attestation_sha256'}
    require(type(r)is dict and set(r)==hashes|{'release_sha','job','vm_uuid','admitted_at','completed_at',
        'stop_ns','writers_stopped','host_restored','sandbox','real_connections'}and
        all(hex64(r[k])for k in hashes)and type(r['release_sha'])is str and re.fullmatch('[0-9a-f]{40}',r['release_sha'])and
        type(r['job'])is str and re.fullmatch('[0-9a-f]{32}',r['job'])and type(r['vm_uuid'])is str and
        str(uuid.UUID(r['vm_uuid']))==r['vm_uuid'],'owned_mail_runtime_identity')
    current=time.time()if now is None else now
    require(type(r['admitted_at'])is int and type(r['completed_at'])is int and
        request['created_at']<=r['admitted_at']<request['expires_at']and
        r['admitted_at']<=r['completed_at']<=current+5 and type(r['stop_ns'])is int and 0<=r['stop_ns']<12*10**9 and
        r['writers_stopped']is True and r['host_restored']is True and
        type(r['real_connections'])is int and r['real_connections']==0 and type(r['sandbox'])is dict and
        set(r['sandbox'])==SANDBOX and all(type(x)is bool for x in r['sandbox'].values()),'owned_mail_known_stop')
    if v['status']=='completed':require(all(r['sandbox'].values()),'owned_mail_completed_sandbox')
    require(type(v['artifacts'])is list and len(v['artifacts'])<=len(ARTIFACTS),'owned_mail_artifact_count')
    names=set()
    for a in v['artifacts']:
        require(type(a)is dict and set(a)=={'name','bytes','sha256'}and a['name']in ARTIFACTS and a['name']not in names and
            type(a['bytes'])is int and 0<a['bytes']<=ARTIFACTS[a['name']]and hex64(a['sha256']),'owned_mail_artifact_inventory')
        names.add(a['name'])
    if v['status']=='completed':require(names==set(ARTIFACTS),'owned_mail_completed_artifacts')
    return v


@contextmanager
def trusted_export(request_id):
    require(type(request_id)is str and re.fullmatch('[0-9a-f]{32}',request_id),'owned_mail_export_id')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in [*EXPORT_ROOT.parts[1:],'mail-browser-owned-'+request_id]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            s=os.fstat(fd);require(s.st_uid==0 and not s.st_mode&0o022,'owned_mail_untrusted_export')
        yield fd
    finally:os.close(fd)


@shared._offline
def import_result(directory,request_path,output):
    shared._linux();case,ref,pieces=_case_snapshot(directory);dest=shared._destination(output,case)
    raw=shared._read_regular(request_path,REQUEST_MAX);parsed=decode(raw,REQUEST_MAX)
    require(type(parsed)is dict and type(parsed.get('created_at'))is int,'owned_mail_request_clock')
    request=validate_request(raw,now=parsed['created_at'])
    require(request['case_reference']==ref and request['snapshot_sha256']=={n:digest(data)for n,data in pieces.items()},
        'owned_mail_request_parent_changed')
    with trusted_export(request['request_id'])as fd:
        receipt_raw=shared._read_regular('receipt.json',RECEIPT_MAX,directory_fd=fd,root_owned=True)
        receipt=validate_receipt(receipt_raw,request)
        require(set(os.listdir(fd))=={'request.json','receipt.json'}|{a['name']for a in receipt['artifacts']},'owned_mail_export_inventory')
        require(shared._read_regular('request.json',REQUEST_MAX,directory_fd=fd,root_owned=True)==raw,'owned_mail_export_request')
        artifacts={}
        for a in receipt['artifacts']:
            body=shared._read_regular(a['name'],ARTIFACTS[a['name']],directory_fd=fd,root_owned=True)
            require(len(body)==a['bytes']and digest(body)==a['sha256'],'owned_mail_output_hash');artifacts[a['name']]=body
    require(_case_snapshot(case)[1:]==(ref,pieces),'owned_mail_case_changed_before_import')
    contents={'request.json':raw,'receipt.json':receipt_raw,**artifacts}
    contents['result.json']=canonical({'status':'collected','execution_status':receipt['status'],
        'case_reference':ref,'request_sha256':digest(raw),'original_case_modified':False,
        'producer_trust':'local Root-protected fixed-owned export; no remote attestation',
        'parent_validation':PARENT_SCOPE,'meaning':'browser observations and custody only; no verdict or authentication claim'})
    with _output(dest,case)as(fd,case_key):
        pending=_new_directory(fd,'pending',case_key)
        try:
            for name,body in contents.items():_write(pending,name,body,case_key)
            _seal_fd(pending,contents,case_key)
            require(_case_snapshot(case)[1:]==(ref,pieces),'owned_mail_publication_integrity')
            _named_output(dest,fd,case_key);_publish(fd,pending);_named_output(dest,fd,case_key)
        finally:os.close(pending)
    return {'status':'collected','execution_status':receipt['status'],'result':str(dest/'result'),
        'request_id':request['request_id'],'case_unchanged':True,'scope':'separate sealed owned browser observations; scoring unchanged'}
