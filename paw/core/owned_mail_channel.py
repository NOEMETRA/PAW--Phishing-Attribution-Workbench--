"""Finite fixed-owned descriptor admission and protected terminal publication."""
import array
from contextlib import contextmanager
from pathlib import Path
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import struct
import time
from . import mail_browser_owned as custody

def require(v,r):
    if not v:raise ValueError(r)
def identity(job,nonce):
    require(type(job)is str and re.fullmatch('[0-9a-f]{32}',job)and type(nonce)is str and
        re.fullmatch('[0-9a-f]{32}',nonce),'owned_mail_channel_identity')
def descriptor(fd):
    before=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    require(stat.S_ISREG(before.st_mode)and before.st_uid==1000 and before.st_nlink==1 and
        stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=custody.REQUEST_MAX and
        flags&os.O_ACCMODE==os.O_RDONLY and not flags&getattr(os,'O_PATH',0),'owned_mail_descriptor')
    raw=bytearray()
    while len(raw)<=before.st_size:
        part=os.pread(fd,min(65536,before.st_size+1-len(raw)),len(raw))
        if not part:break
        raw.extend(part)
    after=os.fstat(fd);keys=['st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_nlink']
    require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)for k in keys),'owned_mail_changed_descriptor')
    return bytes(raw)
def send(peer,job,nonce,fd):
    identity(job,nonce);require(peer.family==socket.AF_UNIX and peer.type==socket.SOCK_SEQPACKET,'owned_mail_unix_packet')
    raw=custody.canonical({'kind':'owned-mail-request-fd-v1','job':job,'nonce':nonce})
    require(peer.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])==len(raw),
        'owned_mail_short_send')
def receive(peer,job,nonce):
    identity(job,nonce);require(peer.family==socket.AF_UNIX and peer.type==socket.SOCK_SEQPACKET,'owned_mail_unix_packet')
    pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    require(pid>1 and uid==gid==1000,'owned_mail_peer_identity');fds=[]
    try:
        peer.settimeout(2)
        raw,ancillary,flags,_=peer.recvmsg(4097,socket.CMSG_SPACE(array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
        unknown=False
        for level,kind,body in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                values=array.array('i');values.frombytes(body[:len(body)-len(body)%values.itemsize]);fds.extend(values)
            else:unknown=True
        require(not unknown and not flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)and len(fds)==1 and
            0<len(raw)<=4096,'owned_mail_descriptor_envelope')
        envelope=custody.decode(raw,4096)
        require(envelope=={'kind':'owned-mail-request-fd-v1','job':job,'nonce':nonce}and
            raw==custody.canonical(envelope),'owned_mail_descriptor_binding')
        data=descriptor(fds[0]);value=custody.validate_request(data)
        return {'request':value,'raw':data,'request_sha256':hashlib.sha256(data).hexdigest(),
            'peer_pid':pid,'authority':'fixed data only; Root admission and execution required'}
    finally:
        for fd in fds:os.close(fd)


def _root(job,release):
    identity(job,'0'*32)
    require(type(release)is str and re.fullmatch('[0-9a-f]{40}',release)and
        os.getuid()==os.geteuid()==0 and Path(__file__).resolve()==
        Path('/opt/paw-vm/releases')/release/'paw/core/owned_mail_channel.py','owned_mail_immutable_root_only')
    from vm_operator_host import trusted_directory
    return trusted_directory


def admit(job,release,announce):
    """One fixed-owned rendezvous; only the reviewed Root recipe may call it."""
    import uuid
    trusted=_root(job,release);exports=Path('/var/lib/paw-vm-exports');state=Path('/var/lib/paw-vm')
    folder=exports/('owned-mail-input-'+job);nonce=uuid.uuid4().hex
    with trusted(state/'jobs'/job):pass
    with trusted(exports)as fd:os.mkdir(folder.name,0o700,dir_fd=fd)
    listener=None;peer=None
    try:
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);listener.settimeout(60)
        listener.bind(str(folder/'request.sock'));os.chown(folder/'request.sock',0,1000);os.chmod(folder/'request.sock',0o660)
        listener.listen(1);os.chown(folder,0,1000);os.chmod(folder,0o750)
        announce({'phase':'owned_mail_input','job':job,'nonce':nonce})
        peer,_=listener.accept();received=receive(peer,job,nonce)
        request=received['request'];raw=received['raw']
        # Snapshot copied bytes, not caller paths or a claim of Root BLAKE3 validation.
        with trusted(state/'jobs'/job)as fd:
            handle=os.open('owned-mail-request.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
            with os.fdopen(handle,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.fsync(fd)
        custody.validate_request(raw)
        with trusted(state)as fd:
            try:os.mkdir('owned-mail-used',0o700,dir_fd=fd)
            except FileExistsError:pass
        admitted=int(time.time())
        with trusted(state/'owned-mail-used')as fd:
            handle=os.open(request['request_id'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            marker=custody.canonical({'schema':'paw-fixed-owned-mail-consumed-v1','job':job,'nonce':nonce,
                'request_sha256':received['request_sha256'],'admitted_at':admitted,
                'authorization_basis':'compiled harmless source and fixed owned URL only'})
            with os.fdopen(handle,'wb')as stream:stream.write(marker);stream.flush();os.fsync(stream.fileno())
            os.fsync(fd)
        custody.validate_request(raw)  # Expiry after consumption remains denial, never a fresh grant.
        reply=custody.canonical({'accepted':True,'job':job,'nonce':nonce,'request_id':request['request_id'],
            'request_sha256':received['request_sha256']})
        require(peer.send(reply)==len(reply),'owned_mail_admission_ack')
        return {**received,'job':job,'nonce':nonce,'admitted_at':admitted,'release_sha':release}
    finally:
        if peer is not None:peer.close()
        if listener is not None:listener.close()
        try:(folder/'request.sock').unlink()
        except FileNotFoundError:pass
        folder.rmdir()


@contextmanager
def protected_directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in Path(path).parts[1:]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            s=os.fstat(fd);require(s.st_uid==0 and not s.st_mode&0o022,'owned_mail_protected_directory')
        yield fd
    finally:os.close(fd)


def submit(job,nonce,request_path):
    """UID-only data handoff to an already running protected owned recipe."""
    identity(job,nonce);require(os.getuid()==os.geteuid()==1000,'owned_mail_submit_uid')
    folder=Path('/var/lib/paw-vm-exports')/('owned-mail-input-'+job)
    with protected_directory(folder)as parent:
        info=os.stat('request.sock',dir_fd=parent,follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode)and info.st_uid==0 and info.st_gid==1000 and
            stat.S_IMODE(info.st_mode)==0o660,'owned_mail_protected_socket')
        fd=os.open(request_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            raw=descriptor(fd);request=custody.validate_request(raw)
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)as peer:
                peer.settimeout(3);peer.connect(str(folder/'request.sock'))
                pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                require(pid>1 and uid==gid==0,'owned_mail_root_peer')
                send(peer,job,nonce,fd);reply=peer.recv(4097)
                expected={'accepted':True,'job':job,'nonce':nonce,'request_id':request['request_id'],
                    'request_sha256':custody.digest(raw)}
                require(len(reply)<=4096 and custody.decode(reply,4096)==expected and reply==custody.canonical(expected),
                    'owned_mail_submit_ack')
        finally:os.close(fd)
    return {'status':'submitted','request_id':request['request_id'],'job':job,
        'scope':'fixed owned data delivered; terminal execution and import still required'}


def bound_result(admission,attestation_raw,context,artifacts):
    """Pure receipt data; only protected Root publication establishes producer trust."""
    request=custody.validate_request(admission['raw'],now=admission['request']['created_at'])
    require(request==admission['request']and custody.digest(admission['raw'])==admission['request_sha256'],
        'owned_mail_admission_changed')
    a=custody.decode(attestation_raw,1024**2)
    require(type(a)is dict and a.get('schema')=='paw-owned-brokered-browser-v1'and
        a.get('job')==admission['job']and a.get('release_sha')==admission['release_sha']and
        a.get('writers_stopped')is True and a.get('host_restored')is True and not a.get('cleanup_errors')and
        a.get('real_connections')==0 and type(a.get('real_connections'))is int and
        a.get('real_samples_executed')==0 and type(a.get('real_samples_executed'))is int and
        a.get('context_sha256')==context['context_sha256'],'owned_mail_capture_identity_or_stop')
    require(type(artifacts)is dict and set(artifacts)<=set(custody.ARTIFACTS)-{'network.json'},'owned_mail_capture_names')
    manifest=a.get('capture_artifacts');require(type(manifest)is list and len(manifest)<=2,'owned_mail_capture_manifest')
    expected={}
    for item in manifest:
        require(type(item)is dict and set(item)=={'name','bytes','sha256'}and item['name']in {'dom.html','screenshot.png'}and
            item['name']not in expected and type(item['bytes'])is int and
            0<item['bytes']<=custody.ARTIFACTS[item['name']]and custody.hex64(item['sha256']),
            'owned_mail_capture_manifest_entry')
        expected[item['name']]={'bytes':item['bytes'],'sha256':item['sha256']}
    require(expected=={name:{'bytes':len(raw),'sha256':custody.digest(raw)}for name,raw in artifacts.items()if type(raw)is bytes}and
        all(type(raw)is bytes for raw in artifacts.values()),'owned_mail_capture_bytes')
    guest=a.get('guest')or{};require(type(guest)is dict,'owned_mail_guest_summary')
    complete=a.get('result')=='PASS'
    if complete:
        require(set(artifacts)=={'dom.html','screenshot.png'}and guest.get('status')=='completed'and
            guest.get('writers_stopped')is True and guest.get('network_interfaces')==['lo']and
            custody.digest(artifacts['dom.html'])==guest.get('dom_sha256')and
            ('PAW-OWNED-'+a['fixture_nonce']).encode()in artifacts['dom.html']and
            b'data-owned="done"'in artifacts['dom.html'],'owned_mail_actual_DOM_missing')
        png=artifacts['screenshot.png'];require(png.startswith(b'\x89PNG\r\n\x1a\n')and len(png)>=33,'owned_mail_actual_PNG_missing')
    else:require(a.get('result')=='FAIL','owned_mail_capture_result')
    observations=a.get('observations',[]);require(type(observations)is list and len(observations)<=64,'owned_mail_network_inventory')
    network=custody.canonical({'schema':'paw-owned-mail-browser-network-v1','seed':custody.SEED,
        'fixture_nonce':a['fixture_nonce'],'raw_attestation_sha256':custody.digest(attestation_raw),
        'observations':observations,'ledger':a.get('ledger')or a.get('ledger_progress'),
        'missing_coverage':guest.get('missing_coverage',[]),
        'scope':'filtered broker observations; not complete browser HAR, packet capture or browser TLS fingerprint',
        'tls_verifier':'broker with isolated owned CA; not browser TLS identity','real_connections':0})
    require(len(network)<=custody.ARTIFACTS['network.json'],'owned_mail_network_cap')
    outputs={**artifacts,'network.json':network}
    receipt={'schema':'paw-owned-mail-browser-result-v1','profile':custody.PROFILE,
        'producer_kind':'local-root-fixed-owned-browser','request_id':request['request_id'],
        'request_sha256':admission['request_sha256'],'source_sha256':custody.digest(custody.SOURCE),
        'snapshot_sha256':request['snapshot_sha256'],'parent_validation':custody.PARENT_SCOPE,
        'status':'completed'if complete else'failed','fixture_nonce':a['fixture_nonce'],
        'runtime':{'release_sha':admission['release_sha'],'job':admission['job'],'vm_uuid':a['vm_uuid'],
            'admitted_at':admission['admitted_at'],'completed_at':int(time.time()),
            'stop_ns':a['stop_ns'],'writers_stopped':True,'host_restored':True,'real_connections':0,
            'sandbox':guest.get('sandbox',{k:False for k in custody.SANDBOX}),
            'context_sha256':context['context_sha256'],'image_sha256':context['image_sha256'],
            'chrome_binary_sha256':context['chrome_binary_sha256'],'raw_attestation_sha256':custody.digest(attestation_raw)},
        'artifacts':[{'name':name,'bytes':len(raw),'sha256':custody.digest(raw)}for name,raw in outputs.items()]}
    custody.validate_receipt(custody.canonical(receipt),request)
    return receipt,outputs


def publish(admission):
    """Publish one consumed owned request's known terminal capture, never arbitrary paths."""
    job=admission['job'];release=admission['release_sha'];trusted=_root(job,release)
    import browser_authorization as auth
    from reader_export import publish_reader_tree
    exports=Path('/var/lib/paw-vm-exports');state=Path('/var/lib/paw-vm')
    with trusted(state/'jobs'/job)as fd:
        raw=custody.shared._read_regular('owned-mail-request.json',custody.REQUEST_MAX,directory_fd=fd,root_owned=True)
    require(raw==admission['raw'],'owned_mail_private_snapshot_changed')
    request=custody.validate_request(raw,now=admission['request']['created_at'])
    with trusted(state/'owned-mail-used')as fd:
        marker=custody.decode(custody.shared._read_regular(request['request_id'],4096,directory_fd=fd,root_owned=True),4096)
    require(marker=={'schema':'paw-fixed-owned-mail-consumed-v1','job':job,'nonce':admission['nonce'],
        'request_sha256':custody.digest(raw),'admitted_at':admission['admitted_at'],
        'authorization_basis':'compiled harmless source and fixed owned URL only'},'owned_mail_consumption_changed')
    with trusted(exports/('owned-broker-'+job))as fd:
        attestation_raw=custody.shared._read_regular('attestation.json',1024**2,directory_fd=fd,root_owned=True)
    a=custody.decode(attestation_raw,1024**2)
    require(type(a)is dict,'owned_mail_attestation_shape');nonce=a.get('fixture_nonce')
    require(type(a.get('capture_artifacts'))is list and len(a['capture_artifacts'])<=2,'owned_mail_private_inventory')
    require(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'owned_mail_capture_nonce')
    artifacts={}
    with trusted(Path('/var/lib/paw-s14/control')/('owned-broker-'+nonce))as fd:
        for item in a.get('capture_artifacts',[]):
            name=item.get('name');require(name in {'dom.html','screenshot.png'},'owned_mail_private_artifact_name')
            artifacts[name]=custody.shared._read_regular('capture-'+name,custody.ARTIFACTS[name],directory_fd=fd,root_owned=True)
    context=auth.capture();auth.validate_context(context)
    facts={'context_sha256':custody.digest(auth.canonical(context)),'image_sha256':context['image_sha256'],
        'chrome_binary_sha256':context['chrome_binary_sha256']}
    receipt,bodies=bound_result(admission,attestation_raw,facts,artifacts)
    folder=exports/('mail-browser-owned-'+request['request_id'])
    with trusted(exports)as fd:os.mkdir(folder.name,0o700,dir_fd=fd)
    with trusted(folder)as fd:
        for name,body in {'request.json':raw,'receipt.json':custody.canonical(receipt),**bodies}.items():
            handle=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
            with os.fdopen(handle,'wb')as f:f.write(body);f.flush();os.fsync(f.fileno())
        os.fsync(fd)
    publish_reader_tree(folder)
    return {'status':receipt['status'],'request_id':request['request_id'],'export':str(folder),
        'request_sha256':custody.digest(raw),'receipt_sha256':custody.digest(custody.canonical(receipt)),
        'scope':'fixed owned email/VM evidence only; no public or real-source acceptance'}
