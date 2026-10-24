"""Read-only reconciliation of the complete owned one-use adapter acceptance."""
import json
import os
import re
import stat
from pathlib import Path
import xml.etree.ElementTree as ET

from offline_candidate import canonical, require
from one_use_authorization import validate_binding, digest
from owned_grant_fixtures import SOURCES, CPU_DISABLED
from verify_synthetic_gate import verify_sources, REQUIRED_SOURCES

NORMAL = {'positive':'completed','failed':'failed','timeout':'timeout','cancel':'cancelled','overflow':'output_budget'}
FAULTS = {'paused-refusal','owner-loss','protocol-loss'}


def regular(path, limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_size<=limit,'audit_file_type_or_budget')
        chunks=[];total=0
        while total<=limit:
            data=os.read(fd,min(8192,limit+1-total))
            if not data:break
            chunks.append(data);total+=len(data)
        after=os.fstat(fd)
        require(total<=limit and (info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
                (after.st_size,after.st_mtime_ns,after.st_ctime_ns),'audit_file_changed')
        return b''.join(chunks)
    finally:os.close(fd)


def verify(root):
    root=Path(root);require(root.is_dir() and not root.is_symlink(),'audit_root')
    r=json.loads(regular(root/'results.json',2*1024**2));policy_raw=regular(root/'policy.json',65536);policy=json.loads(policy_raw)
    require(policy_raw==canonical(policy),'canonical_policy_required')
    require(r['result']=='PASS' and not r.get('cleanup_error'),'acceptance_failed')
    require(all(r.get(k) is True for k in ['host_restored','base_unchanged','host_canary_unchanged','writers_stopped',
            'source_freeze_unchanged','global_replay_refused','unknown_stop_publication_refused']),'lifecycle_integrity')
    require(r['host_before']==r['host_after'] and r['real_connections']==0,'host_or_network')
    require(r['source_hashes']==policy['context']['source_hashes'],'policy_source_inventory')
    required=REQUIRED_SOURCES|{'one_use_authorization.py','granted_offline_adapter.py','i08_context.py',
                              'owned_grant_fixtures.py','granted_offline_matrix.py','verify_granted_offline.py'}
    verify_sources(root,r['source_hashes'],required)
    require(len(r['runs'])==len(NORMAL)+len(FAULTS) and {v['case'] for v in r['runs']}==set(NORMAL)|FAULTS,'case_inventory')
    require(len({v['request_id'] for v in r['runs']})==len(r['runs']),'request_reuse')
    require((root/'admissions').is_dir() and not (root/'admissions').is_symlink(),'admission_directory')
    require(len(r['vms'])==len(r['runs']) and len({v['uuid'] for v in r['vms']})==len(r['vms']),'vm_inventory')
    require({v['label'] for v in r['vms']}=={'grant-'+v['request_id'] for v in r['runs']},'vm_label_inventory')
    require(len({(v['actual']['pid'],v['actual']['pid_identity']) for v in r['vms']})==len(r['vms']),'process_reuse')
    for run in r['runs']:
        case=run['case'];rid=run['request_id']
        require(type(rid) is str and re.fullmatch('[0-9a-f]{32}',rid),'request_id')
        folder=root/'authority-copy'/rid
        require((root/'authority-copy').is_dir() and not (root/'authority-copy').is_symlink() and
                folder.is_dir() and not folder.is_symlink(),'authority_copy_directory')
        require({p.name for p in folder.iterdir()}=={'candidate.json','grant.json','consumed.json'},'authority_copy_inventory')
        raw=regular(folder/'candidate.json',36864);grant_raw=regular(folder/'grant.json',4096);grant=json.loads(grant_raw)
        ledger_raw=regular(folder/'consumed.json',4096);ledger=json.loads(ledger_raw)
        require(grant_raw==canonical(grant) and ledger_raw==canonical(ledger),'canonical_authority_required')
        when=run['admitted_at'] if case in NORMAL else ledger['consumed_at']
        summary,value,source=validate_binding(raw,grant,policy_raw,policy['context'],now=when)
        require(summary['request_id']==rid,'request_id')
        require(source==SOURCES[case if case in NORMAL else 'positive'],'fixture_oracle')
        require(ledger=={'schema':'paw-s14-consumed-grant-v1','request_id':rid,'grant_sha256':digest(grant_raw),
                'frame_sha256':digest(raw),'policy_sha256':digest(policy_raw),'consumed_at':ledger['consumed_at'],
                'meaning':'consumed before VM creation, including any subsequent failure'},'consumption_binding')
        require(value['created_at']<=ledger['consumed_at']<=when<grant['expires_at'],'consumption_clock')
        vm=next(v for v in r['vms'] if v['label']=='grant-'+rid)
        require(vm['actual']['uuid']==vm['uuid'] and vm['stopped'] is True and vm['stop_seconds']<12,'stop_and_uuid')
        require(vm['actual']['limits']=={'memory.max':str(768*1024**2),'memory.swap.max':'0','pids.max':'64','cpu.max':'50000 100000'},'effective_limits')
        require(vm['actual']['apparmor'].startswith('libvirt-') and '(enforce)' in vm['actual']['apparmor'] and
                'Seccomp:\t2' in vm['host_status'],'mandatory_controls')
        require(vm['fsize_limit']==256*1024**2 and vm['overlay_bytes']<=vm['fsize_limit'],'overlay_limit')
        xml=ET.fromstring(regular(root/(vm['label']+'-domain.xml'),65536))
        require(xml.findtext('uuid')==vm['uuid'],'xml_uuid')
        require(not any(xml.findall('devices/'+name) for name in ['interface','filesystem','hostdev']),'exposure')
        dac=xml.findtext('seclabel[@model="dac"]/label') or ''
        require(len(dac.split(':'))==2 and all(part.startswith('+') and part[1:].isdigit() and int(part[1:])>0 for part in dac.split(':')),'nonroot_dac')
        memory=xml.find('memory');require(memory is not None and (memory.get('unit'),memory.text) in {('KiB','524288'),('MiB','512')},'guest_memory')
        require(xml.find('defaultiothread').get('thread_pool_max')=='8','io_workers')
        disabled={item.get('name') for item in xml.findall('cpu/feature') if item.get('policy')=='disable'}
        require(set(CPU_DISABLED)<=disabled,'effective_cpu_features')
        if case in FAULTS:
            require(run['status']=='refused-or-failed' and run['error'] and run['writers_stopped'] is True,'fault_accounting')
            if case=='paused-refusal':require('owned_paused_startup_refusal' in run['error'],'paused_fault_oracle')
            if case=='owner-loss':
                witness=next(v for v in r['fault_injections'] if v['case']==case)
                require(witness['vm_uuid']==vm['uuid'] and witness['owner_returncode']==-9 and
                        type(witness['owner_pid']) is int and witness['owner_pid']>0,'owner_loss_oracle')
            if case=='protocol-loss':require('guest_channel_failed:' in run['error'],'protocol_fault_oracle')
            require(not (root/('grant-'+rid+'-quarantine')).exists(),'fault_publication')
            continue
        require(run['grant_sha256']==digest(grant_raw) and run['policy_sha256']==digest(policy_raw) and
                run['candidate_frame_sha256']==digest(raw) and run['candidate_sha256']==summary['candidate_sha256'],'result_authority_binding')
        job=run['job'];require(job=={'source_hex':source.hex(),'source_sha256':summary['source_sha256'],
                'parent_sha256':summary['case_reference_sha256'],'job_id':'grant-'+rid,'profile':summary['profile'],
                'operator_authorization':'root-owned-synthetic-grant-v1','created_at':value['created_at'],
                'expires_at':value['expires_at']},'execution_job_binding')
        require(json.loads(regular(root/'admissions'/(job['job_id']+'.json'),36864))==job and
                run['consumption']==ledger,'local_and_global_ledgers')
        require(run['job_sha256']==digest(canonical(job)) and run['vm_uuid']==vm['uuid'],'guest_job_binding')
        admission=run['guest_admission'];require(admission['source_sha256']==job['source_sha256'] and
                admission['job_sha256']==run['job_sha256'] and admission['prior_marker_absent'] is True,'guest_admission')
        outcome=run['outcome'];require(outcome['status']==NORMAL[case] and run['writers_stopped'] is True,'outcome')
        if case!='cancel':require(outcome['done'] is True and outcome['writers_stopped'] is True and outcome['events']['pids.current']=='0','guest_descendants')
        if case=='positive':
            marker=json.loads(bytes.fromhex(outcome['records'][0]['bytes_hex']))
            require(marker=={'owned_marker':'ONE-USE-OFFLINE','cpu_avx_xsave_absent':True,'uid':65534} and outcome['returncode']==0,'positive_cpu_oracle')
        if case=='failed':require(outcome['returncode']==7,'failure_oracle')
        folder=root/('grant-'+rid+'-quarantine');manifest=run['quarantine']
        require(folder.is_dir() and not folder.is_symlink() and len(manifest)==len(outcome['records'])==(0 if case=='cancel' else 2),'quarantine_count')
        require({p.name for p in folder.iterdir()}=={p['stored_as'] for p in manifest},'quarantine_inventory')
        for i,item in enumerate(manifest):
            require(item['stored_as']==f'artifact-{i:02d}.bin','ordinal_path')
            path=folder/item['stored_as'];require(path.is_file() and not path.is_symlink(),'quarantine_file')
            data=regular(path,1024);require(len(data)==item['bytes']<=1024 and digest(data)==item['sha256'] and
                data==bytes.fromhex(outcome['records'][i]['bytes_hex']),'output_digest')
    return {'result':'PASS','jobs':len(r['runs']),'sources':len(r['source_hashes']),
            'scope':'owned synthetic single-use offline Python adapter only','i08_hostile_authorization':False,'real_connections':0}
