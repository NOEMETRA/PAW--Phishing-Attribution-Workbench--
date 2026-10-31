"""Fixed owned DNS/HTTP/TLS -> private serial -> no-NIC Chrome acceptance.

Not a real-input/public launcher. The enrolled helper supplies only job/release
identities; every endpoint, source, certificate purpose and phase is fixed here.
Owned fixture TLS trust is confined to the worker's private readonly root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import selectors
import stat
import subprocess
import sys
import time
import uuid

from . import owned_kernel_runtime as kernel
from . import browser_mediator as mediator,mail_browser_dns as dns
from . import browser_broker_wire as wire,browser_broker_console as console,browser_cdp as cdp

HERE=Path(__file__).resolve()
PROGRAMS=['browser_owned_broker.py','browser_owned_broker_guest.py','browser_broker_console.py',
    'browser_owned_protocol.py','browser_mediator.py','mail_browser_dns.py','browser_broker_wire.py',
    'browser_cdp.py','browser_owned_cdp_guest.py','owned_kernel_runtime.py','owned_kernel_policy.py']
SEED='https://paw-owned.invalid/'


def require(value,reason):
    if not value:raise ValueError(reason)


def partition(parent,restore=False):
    subprocess.run(['/usr/bin/systemctl','set-property','--runtime',parent,
        'MemoryMax='+('512M'if restore else'256M'),'TasksMax='+('64'if restore else'32'),
        'CPUQuota='+('100%'if restore else'50%')],check=True,capture_output=True,timeout=2)


def prepare(job,epoch,release):
    ids=kernel.policy.identity(job,epoch,release);folder=Path(ids['directory'])
    kernel.prepare_case(folder,job,epoch,release)
    for name in PROGRAMS:
        source=HERE.with_name(name);info=source.stat()
        require(info.st_uid==0 and not info.st_mode&0o022 and stat.S_ISREG(info.st_mode) and
            info.st_size<=128*1024,'owned_broker_immutable_program')
        target=folder/'code'/name
        if target.exists():require(target.read_bytes()==source.read_bytes(),'owned_broker_source_mismatch')
        else:target.write_bytes(source.read_bytes());target.chmod(0o444)
    cert=folder/'owned-cert.pem';key=folder/'owned-key.pem'
    result=subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=paw-owned.invalid','-addext','subjectAltName=DNS:paw-owned.invalid',
        '-keyout',str(key),'-out',str(cert)],capture_output=True,timeout=5)
    require(result.returncode==0 and len(result.stdout)+len(result.stderr)<=8192,
            'owned_broker_fixture_certificate_generation')
    for source,name in [(cert,'paw-owned-cert.pem'),(key,'paw-owned-key.pem')]:
        raw=source.read_bytes();require(0<len(raw)<=16384,'owned_broker_fixture_certificate_budget')
        target=folder/'fixture-root/etc'/name;target.write_bytes(raw);target.chmod(0o444)
    trust=folder/'probe-root/etc/ssl/certs';trust.mkdir(parents=True,mode=0o755)
    target=trust/'ca-certificates.crt';target.write_bytes(cert.read_bytes());target.chmod(0o444)
    return folder,hashlib.sha256(cert.read_bytes()).hexdigest()


def write_private(fd,raw,deadline):
    require(type(raw)is bytes and len(raw)<=65536,'owned_broker_private_command_budget')
    os.set_blocking(fd,False);view=memoryview(raw)
    with selectors.DefaultSelector()as selected:
        selected.register(fd,selectors.EVENT_WRITE)
        while view:
            left=deadline-time.monotonic()
            require(left>0,'owned_broker_private_write_deadline')
            if not selected.select(min(.1,left)):continue
            try:count=os.write(fd,view)
            except BlockingIOError:continue
            require(count>0,'owned_broker_private_pipe_closed');view=view[count:]


class Mediation:
    def __init__(self,owner,worker,nonce,started_ns):
        self.owner=owner;self.worker=worker;self.nonce=nonce;self.control_sequence=0;self.sequence=0
        self.ledger=mediator.BrowserRequestLedger(SEED,nonce,started_ns)
        self.observations=[]

    def control(self,op,**fields):
        started=time.monotonic_ns()
        value={'op':op,'epoch':self.nonce,'id':self.control_sequence,**fields}
        try:
            self.owner.send(value);answer=self.owner.receive()
            require(answer.get('accepted')is True and type(answer.get('id'))is int and
                answer['id']==self.control_sequence and time.monotonic_ns()-started<2*10**9,
                'owned_broker_keeper_ack')
            self.control_sequence+=1
        except (OSError,ValueError):
            self.ledger.closed=True;raise

    def transaction(self,kind,fields):
        sequence=self.sequence;self.sequence+=1
        try:
            write_private(self.worker.process.stdin.fileno(),wire.frame(self.nonce,sequence,kind,fields),
                time.monotonic()+2)
            value=self.worker.receive(5)
            require(set(value)=={'wire','body'} and type(value['body'])is bytes,'owned_broker_response_shape')
            header=value['wire']
            require(header['kind']=='reply' and header['sequence']==sequence and
                header['nonce']==self.nonce and type(header['fields'])is dict and
                type(header['fields'].get('request_sequence'))is int and
                header['fields']['request_sequence']==sequence and
                header['fields'].get('operation')==kind,'owned_broker_response_identity')
            return header['fields'],value['body']
        except (OSError,ValueError,KeyError,TypeError):
            self.ledger.closed=True;raise ValueError('owned_broker_private_protocol_closed') from None

    def resolver(self,host,deadline_ns):
        require(host=='paw-owned.invalid','owned_broker_fixed_resolver_name')
        issued=time.monotonic_ns();self.control('lease',kind='dns',milliseconds=1000)
        ident=secrets.randbelow(65536)
        fields,raw=self.transaction('dns',{'host':host,'ident':ident,
            'deadline_ns':min(deadline_ns,time.monotonic_ns()+10**9)})
        try:
            require(set(fields)=={'request_sequence','operation','host','ident','received_ns'} and
                fields['host']==host and type(fields['ident'])is int and fields['ident']==ident and
                type(fields['received_ns'])is int and issued<=fields['received_ns']<=time.monotonic_ns()and
                time.monotonic_ns()<deadline_ns,'owned_broker_actual_dns_binding')
        except ValueError:
            self.ledger.closed=True;raise
        # Conservative age starts before the query, never from the peer's clock.
        facts=dns.parse_answer(raw,host,ident)
        self.observations.append({'operation':'dns','packet_sha256':hashlib.sha256(raw).hexdigest(),
            'answers':facts['answers'],'ttl_ns':facts['ttl_ns']})
        return {**facts,'observed_ns':issued}

    def response(self,request):
        plan=self.ledger.admit_resolved(request,self.resolver)
        plan=self.ledger.lease(plan,time.monotonic_ns())
        # Reserve the complete bounded2s keeper transaction: a relative nft
        # timeout starts at commit, so it must not overrun the absolute lease.
        milliseconds=kernel_lease_milliseconds(plan,time.monotonic_ns())
        try:
            self.control('lease',kind=plan['scheme'],milliseconds=milliseconds)
            fields,body=self.transaction('http',{'plan':plan,'remaining_bytes':mediator.LIMITS['bytes']-self.ledger.received})
            require(set(fields)=={'request_sequence','operation','transport'}and
                type(fields['transport'])is dict,'owned_broker_transport_response')
            facts=fields['transport']
            require(set(facts)=={'http_status','headers','peer_ipv4','tls_verified_by_broker','body_bytes','body_sha256'} and
                type(facts['body_bytes'])is int and facts['body_bytes']==len(body) and
                facts['body_sha256']==hashlib.sha256(body).hexdigest(),'owned_broker_body_binding')
            metadata=self.ledger.complete(plan,facts['http_status'],facts['headers'],body,
                facts['peer_ipv4'],facts['tls_verified_by_broker'],time.monotonic_ns())
            self.control('revoke')
            self.observations.append({'operation':'http','slot':plan['slot'],'url_sha256':plan['url_sha256'],
                'status':metadata['http_status'],'body_bytes':len(body),'body_sha256':metadata['body_sha256'],
                'peer_ipv4':facts['peer_ipv4'],'tls_verified_by_broker':metadata['tls_verified_by_broker'],
                'tls_fingerprint_source':metadata['tls_fingerprint_source']})
            allowed={k:metadata[k]for k in ['status','slot','http_status','headers','body_bytes','body_sha256']}
            return allowed,body
        except (OSError,ValueError,KeyError,TypeError):
            self.ledger.closed=True;self.ledger.received=mediator.LIMITS['bytes']
            raise ValueError('owned_broker_transport_closed') from None



class NetworkPreparation:
    """Advance the same three bounded roles without blocking guest polling."""
    def __init__(self,job,epoch,release,actors):
        self.job=job;self.epoch=epoch;self.release=release;self.actors=actors
        self.owner=kernel.Managed(job,epoch,release,'keeper',registry=actors,defer_ready=True)
        self.server=None;self.worker=None;self.inode=None;self.server_live=False;self.worker_live=False
        self.ready=False

    def poll(self):
        if self.ready:return True
        if self.inode is None:
            if not self.owner.poll_ready():return False
            self.inode=kernel.live_role(self.owner,'keeper')
            require(self.inode!=os.stat('/proc/self/ns/net').st_ino,'owned_broker_host_namespace')
            # These already-budgeted processes may initialize together. No
            # request/lease can start until both independent live checks pass.
            self.server=kernel.Managed(self.job,self.epoch,self.release,'fixture',self.owner.pid,
                registry=self.actors,protocol=True,defer_ready=True)
            self.worker=kernel.Managed(self.job,self.epoch,self.release,'probe',self.owner.pid,
                registry=self.actors,protocol=True,defer_ready=True)
        if not self.server_live and self.server.poll_ready():
            kernel.live_role(self.server,'fixture',self.inode);self.server_live=True
        if not self.worker_live and self.worker.poll_ready():
            kernel.live_role(self.worker,'probe',self.inode);self.worker_live=True
        self.ready=self.server_live and self.worker_live
        return self.ready


def kernel_lease_milliseconds(plan,now_ns):
    milliseconds=min(3000,(plan['expires_ns']-now_ns)//10**6-2000)
    require(milliseconds>0,'owned_broker_expired_kernel_lease')
    return milliseconds


def send_response(channel,nonce,slot,metadata,body):
    raw=cdp.canonical(metadata)
    console.transfer(channel,{'kind':'begin','nonce':nonce,'seq':slot,'bytes':len(raw),
        'sha256':hashlib.sha256(raw).hexdigest()})
    for section,payload in [('metadata',raw),('body',body)]:
        for row in cdp.response_chunks(nonce,slot,payload):
            console.transfer(channel,{'kind':'part','nonce':nonce,'seq':slot,'section':section,'row':row})


def run_owned(job,release):
    require(os.geteuid()==0 and HERE==Path('/opt/paw-vm/releases')/release/'paw/core/browser_owned_broker.py',
            'owned_broker_immutable_root_only')
    kernel.policy.identity(job,'0'*32,release)
    # Fresh exact-source raw kernel acceptance, before this new VM scope.
    kernel_result=kernel.owned_validation(job,release)
    require(kernel_result.get('result')=='PASS'and kernel_result.get('vm_started')is False and
        type(kernel_result.get('attestation_sha256'))is str and
        re.fullmatch('[0-9a-f]{64}',kernel_result['attestation_sha256']),
        'owned_broker_current_kernel_component')
    repo=HERE.parents[2];sys.path.insert(0,str(repo/'lab/s14'))
    import browser_authorization as auth
    from browser_vm import BrowserVM,BROWSER_BASE,LIMITS
    from browser_offline_adapter import input_media,available_memory
    from benign_guest_validation import BASE,digest
    from vm_runtime_revalidation import network_state
    from reader_export import publish_reader_tree
    context=auth.capture();auth.validate_context(context)
    epoch=uuid.uuid4().hex;ids=kernel.policy.identity(job,epoch,release)
    record={'schema':'paw-owned-brokered-browser-v1','result':'FAIL','job':job,'release_sha':release,
        'real_connections':0,'real_samples_executed':0,'i08_installed':False,'production_grants_enabled':False,
        'kernel_component':kernel_result,
        'scope':'owned private DNS, plain HTTP transport and actual HTTPS no-NIC Chrome; not full O3 fault/custody or public authority'}
    actors=[];gate=None;vm=None;partitioned=False;mediation=None
    with auth.fs.execution_lock():
        folder,cert_sha=prepare(job,epoch,release)
        require(available_memory()>=2*1024**3 and shutil.disk_usage(BROWSER_BASE.parent).free>=10*1024**3,
                'owned_broker_host_resources')
        out=Path('/var/lib/paw-s14/control')/('owned-broker-'+epoch)
        media=input_media(b'PAW fixed owned broker fixture only',epoch)
        gate=BrowserVM(argparse.Namespace(output=out),phase='owned_brokered',media=media,
            seed_config={'kind':'owned-cdp-probe-v1','nonce':epoch})
        gate.canary=out/'host-owned-canary.bin';gate.canary.write_bytes(os.urandom(32));gate.canary.chmod(0o600)
        canary=digest(gate.canary);before=gate.snapshot_host();network=network_state()
        try:
            vm=gate.start('owned-brokered-browser')
            inspected=vm['channel'].call('inspect',seconds=8)
            require(inspected['network_interfaces']==['lo'] and inspected['chrome_version']==context['chrome_version'] and
                inspected['chrome_binary_sha256']==context['chrome_binary_sha256'],'owned_broker_exact_browser')
            record['timing_ns']={'guest_start_call':time.monotonic_ns()}
            admitted=vm['channel'].call('start',seconds=8)
            require(admitted.get('started')is True,'owned_broker_guest_start_ack')
            # Guest start includes its mandatory image check/preparation. The
            # same15s execution clock begins at the successful start boundary,
            # not before those prerequisites. Guest15s/keeper8s/worker10s stay.
            began=time.monotonic_ns();record['timing_ns']['guest_start_ack']=began
            end=time.monotonic()+18;preparation=None
            while time.monotonic()<end:
                value=vm['channel'].call('poll',seconds=5)
                request=value.get('network_request')
                if request is not None and 'first_paused_request'not in record['timing_ns']:
                    record['timing_ns']['first_paused_request']=time.monotonic_ns()
                if value.get('done')is True:break
                # Align the existing keeper8s with the remaining part of the
                # guest15s. Earlier requests start preparation immediately.
                # Continue polling the same VM while PID1 roles initialize.
                if preparation is None and (request is not None or time.monotonic_ns()-began>=7*10**9):
                    parent=kernel.unit_properties(ids['parent'])
                    require(parent['ActiveState']=='active'and parent['MainPID']==str(os.getpid())and
                        parent['MemoryMax']==str(512*1024**2)and parent['TasksMax']=='64',
                        'owned_broker_parent_budget')
                    partitioned=True;partition(ids['parent'])
                    record['timing_ns']['network_preparation_start']=time.monotonic_ns()
                    preparation=NetworkPreparation(job,epoch,release,actors)
                if preparation is not None and mediation is None and preparation.poll():
                    owner,server,worker=preparation.owner,preparation.server,preparation.worker
                    inode=preparation.inode
                    record['timing_ns']['actors_ready']=time.monotonic_ns()
                    mediation=Mediation(owner,worker,epoch,began)
                if mediation is not None and request is not None:
                    record['broker_progress']={'phase':'browser_request','slot':request['seq'],
                        'url_sha256':hashlib.sha256(request['url'].encode('utf-8',errors='surrogatepass')).hexdigest()}
                    try:metadata,body=mediation.response(request)
                    except ValueError:
                        if mediation.ledger.closed:raise
                        mediation.control('revoke')
                        console.transfer(vm['channel'],{'kind':'refusal','nonce':epoch,'seq':request['seq']})
                    else:send_response(vm['channel'],epoch,request['seq'],metadata,body)
                time.sleep(.03)
            else:raise ValueError('owned_broker_poll_deadline')
            require(value.get('status')=='completed'and value.get('writers_stopped')is True and
                value.get('network_interfaces')==['lo'] and type(value.get('sandbox'))is dict and
                set(value['sandbox'])=={'renderer_seen','renderer_nnp','renderer_seccomp','renderer_pid_namespace','all_uids_nonroot'}and
                all(v is True for v in value['sandbox'].values()),'owned_broker_actual_guest_failed')
            http=[r for r in mediation.observations if r['operation']=='http']
            require(len(http)>=2 and all(r['tls_verified_by_broker']is True for r in http),
                    'owned_broker_actual_tls_resources_missing')
            # Separate fixed transport probe: this does not claim Chrome
            # executed mixed-content HTTP. The Chrome observations above use TLS.
            record['guest']=value
            record['broker_progress']={'phase':'plain_http_probe','slot':mediation.ledger.used,
                'url_sha256':hashlib.sha256(b'http://paw-owned.invalid/owned-data').hexdigest()}
            plain,plain_body=mediation.response({'nonce':epoch,'seq':mediation.ledger.used,
                'url':'http://paw-owned.invalid/owned-data','method':'GET','resource':'Fetch'})
            require(plain['http_status']==200 and plain_body==('PAW-OWNED-'+epoch).encode('ascii') and
                mediation.observations[-1]['tls_verified_by_broker']is False,
                'owned_broker_plain_http_transport_missing')
            # A completed DOM and absent units cannot excuse an unexpected
            # network-owner/worker exit. Observe live identities, then perform
            # the typed worker stop and expected keeper stop explicitly.
            for actor in actors:
                state=kernel.unit_properties(actor.unit)
                require(state['ActiveState']=='active'and state['MainPID']==str(actor.pid),
                        'owned_broker_unexpected_network_exit')
            fields,body=mediation.transaction('stop',{})
            require(fields=={'request_sequence':mediation.sequence-1,'operation':'stop','stopped':True}and
                fields['stopped']is True and body==b''and worker.process.wait(timeout=2)==0,'owned_broker_worker_stop')
            mediation.control('stop')
            require(owner.process.wait(timeout=2)==0,'owned_broker_keeper_stop')
            network_owner=kernel.private_json(folder/'owner-result.json')
            require(network_owner.get('reason')=='requested_stop'and network_owner.get('epoch')==epoch and
                network_owner.get('namespace_inode')==inode,'owned_broker_network_owner_disposition')
            record['network_owner_disposition']=network_owner
            record.update(result='PASS',guest=value,observations=mediation.observations,
                ledger=mediation.ledger.close(),fixture_ca_sha256=cert_sha,
                role_observations=[v.observation for v in actors],vm_uuid=vm['node']['uuid'],qemu_limits=dict(LIMITS))
        except Exception as error:
            record.update(result='FAIL',error=type(error).__name__+':'+str(error)[:1024])
        finally:
            failures=[];stopped=time.monotonic()
            try:kernel.cleanup_actors(actors);kernel.vacant_ids()
            except Exception as error:failures.append('network:'+type(error).__name__)
            try:
                if partitioned:partition(ids['parent'],restore=True)
            except Exception as error:failures.append('budget:'+type(error).__name__)
            try:
                if gate.active_vm is not None:gate.stop(gate.active_vm)
                require(vm is not None and Path(vm['owner_result_path']).parent==gate.output,
                        'owned_broker_owner_result_path')
                with auth.fs.root_directory(gate.output)as fd:
                    owner_result=json.loads(auth.fs.read(fd,Path(vm['owner_result_path']).name,65536))
                require(owner_result.get('reason')=='requested_stop'and owner_result.get('connection_closed')is True and
                    owner_result.get('vm_uuid')==vm['node']['uuid'],'owned_broker_owner_disposition')
                record['owner_disposition']=owner_result
                # Capture the actual external stop before hashing images and
                # revalidating context. Slow proof work is reported separately.
                record['stop_ns']=int((time.monotonic()-stopped)*10**9)
                verified_from=time.monotonic_ns()
                require(0<=record['stop_ns']<12*10**9 and not gate.connection.listAllDomains(0)and
                    before==gate.snapshot_host()and network==network_state()and digest(BASE)==auth.fs.IMAGE_SHA256 and
                    digest(BROWSER_BASE)==context['image_sha256']and digest(gate.canary)==canary and
                    auth.capture()==context,'owned_broker_external_stop_or_restore')
                record.update(writers_stopped=True,host_restored=True,verification_ns=time.monotonic_ns()-verified_from)
            except Exception as error:failures.append('VM:'+type(error).__name__+':'+str(error)[:256])
            gate.connection.close()
            if failures:record.update(result='FAIL',cleanup_errors=failures)
            # Bounded progress is useful on FAIL too. It is diagnostic only,
            # never readiness, approval or a replacement for known termination.
            if mediation is not None:
                record['observations']=mediation.observations
                record['ledger_progress']={'requests_consumed':mediation.ledger.used,
                    'response_bytes':mediation.ledger.received,'closed':mediation.ledger.closed}
            record['role_observations']=[v.observation for v in actors if hasattr(v,'observation')]
            record['role_diagnostics']=[{'unit':v.unit,'launcher_returncode':v.process.poll(),
                'stderr':bytes(v.errors).decode('utf-8','replace')}for v in actors]
            record['programs']={name:digest(HERE.with_name(name))for name in PROGRAMS}
            record['context_sha256']=hashlib.sha256(auth.canonical(context)).hexdigest()
            (out/'results.json').write_bytes(auth.canonical(record))
        # A terminal FAIL is diagnostic, never success or readiness. Unknown
        # writers/host restoration prevent even bounded diagnostic publication.
        require(record.get('writers_stopped')is True and record.get('host_restored')is True and
            not record.get('cleanup_errors'),'owned_broker_unknown_stop_no_publication')
        target=Path('/var/lib/paw-vm-exports')/('owned-broker-'+job)
        with auth.fs.root_directory(target.parent):pass
        target.mkdir(mode=0o700)
        (target/'attestation.json').write_bytes(auth.canonical(record));publish_reader_tree(target)
        require(record['result']=='PASS','owned_broker_probe_failed')
        return {'result':'PASS','attestation':str(target/'attestation.json'),'scope':record['scope']}
