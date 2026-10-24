"""Read-only per-hash execution custody; no input catalogue or risk verdict."""
import json,math,re
from pathlib import Path
import xml.etree.ElementTree as ET

import hash_authorization as auth
from offline_candidate import canonical,require
from owned_grant_fixtures import CPU_DISABLED
from hash_validation_inputs import parse,CASES
from verify_granted_offline import regular,NORMAL,FAULTS
from verify_synthetic_gate import verify_sources,REQUIRED_SOURCES
from gw_quarantine import validate_records


def load(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate_audit_key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)


def vm_evidence(root,vm,context):
    actual=vm['actual'];uid=vm['uuid']
    require(type(uid) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',uid) and actual['uuid']==uid,'vm_uuid')
    require(type(actual['pid']) is int and actual['pid']>0 and type(actual['pid_identity']) is str and actual['pid_identity'].isdecimal(),'process_identity')
    seconds=vm['stop_seconds'];require(vm['stopped'] is True and type(seconds) in {int,float} and math.isfinite(seconds) and 0<=seconds<12,'known_stop')
    require(actual['limits']=={'memory.max':str(768*1024**2),'memory.swap.max':'0','pids.max':'64','cpu.max':'50000 100000'},'effective_limits')
    require(actual['apparmor'].startswith('libvirt-') and '(enforce)' in actual['apparmor'] and 'Seccomp:\t2' in vm['host_status'],'mandatory_controls')
    require(actual['qemu_binary_sha256']==context['qemu_binary_sha256'] and actual['memory_merge_disabled'] is True,'qemu_binary_or_merge')
    require(vm['fsize_limit']==256*1024**2 and vm['overlay_bytes']<=vm['fsize_limit'],'overlay_budget')
    xml=ET.fromstring(regular(root/(vm['label']+'-domain.xml'),65536));require(xml.findtext('uuid')==uid,'xml_uuid')
    require(not any(xml.findall('devices/'+name) for name in ['interface','filesystem','hostdev','vsock']),'exposure')
    dac=xml.findtext('seclabel[@model="dac"]/label') or ''
    require(len(dac.split(':'))==2 and all(v.startswith('+') and v[1:].isdigit() and int(v[1:])>0 for v in dac.split(':')),'nonroot_dac')
    memory=xml.find('memory');require(memory is not None and (memory.get('unit'),memory.text) in {('KiB','524288'),('MiB','512')},'guest_memory')
    require(xml.find('defaultiothread').get('thread_pool_max')=='8','io_workers')
    require(set(CPU_DISABLED)<={v.get('name') for v in xml.findall('cpu/feature') if v.get('policy')=='disable'},'effective_cpu')
    require(xml.find('memoryBacking/nosharepages') is not None and xml.find('features/pmu').get('state')=='off' and
            xml.find('features/vmport').get('state')=='off','memory_and_cpu_surface')
    require(all(v.get('model')=='none' for v in xml.findall('devices/controller') if v.get('type')=='usb'),'usb_surface')


def verify_bundle(root,single=False):
    root=Path(root);require(root.is_dir() and not root.is_symlink(),'audit_root')
    r=load(regular(root/'results.json',2*1024**2));policy_raw=regular(root/'policy.json',65536);policy=load(policy_raw)
    maintenance=regular(root/'maintenance.json',65536)
    ready=regular(root/'readiness.json',65536) if policy['mode']=='sample-analysis' else None
    require(r['result']=='PASS' and not r.get('cleanup_error'),'execution_or_cleanup_failed')
    require(all(r.get(k) is True for k in ['host_restored','base_unchanged','host_canary_unchanged','writers_stopped','source_freeze_unchanged']),'lifecycle_integrity')
    require(r['host_before']==r['host_after'] and r['real_connections']==0,'host_or_network')
    require(r['source_hashes']==policy['context']['host']['source_hashes'],'policy_source_inventory')
    verify_sources(root,r['source_hashes'],REQUIRED_SOURCES|{'hash_authorization.py','hash_offline_adapter.py','hash_offline_matrix.py','verify_hash_offline.py','hostile_maintenance.py'})
    require((root/'admissions').is_dir() and not (root/'admissions').is_symlink() and
            (root/'authority-copy').is_dir() and not (root/'authority-copy').is_symlink(),'audit_directories')
    if single:require(len(r['runs'])==1 and policy['mode']=='sample-analysis','single_analysis_scope');inputs=None
    else:
        inputs_raw=regular(root/'approved-inputs.json',320*1024);inputs=parse(inputs_raw)
        require(policy['mode']=='validation' and policy['validation_manifest_sha256']==auth.digest(inputs_raw) and
                set(policy['approved_source_hashes'])=={v['source_sha256'] for v in inputs['inputs']},'approved_manifest_binding')
        require(len(r['runs'])==8 and {v['case'] for v in r['runs']}==set(CASES) and r['real_samples_executed']==0,'case_inventory')
        require(r.get('global_replay_refused') is True and r.get('unknown_stop_publication_refused') is True,'refusal_inventory')
    require(len(r['vms'])==len(r['runs']) and len({v['uuid'] for v in r['vms']})==len(r['vms']),'vm_inventory')
    require(len({(v['actual']['pid'],v['actual']['pid_identity']) for v in r['vms']})==len(r['vms']),'process_reuse')
    require(len({v['request_id'] for v in r['runs']})==len(r['runs']) and
            {v['label'] for v in r['vms']}=={'hash-'+v['request_id'] for v in r['runs']},'request_vm_inventory')
    for run in r['runs']:
        rid=run['request_id'];require(type(rid) is str and re.fullmatch('[0-9a-f]{32}',rid),'request_id')
        folder=root/'authority-copy'/rid;require(folder.is_dir() and not folder.is_symlink(),'authority_directory')
        require({p.name for p in folder.iterdir()}=={'candidate.json','grant.json','consumed.json'},'authority_inventory')
        raw=regular(folder/'candidate.json',36864);grant_raw=regular(folder/'grant.json',4096);grant=load(grant_raw)
        ledger_raw=regular(folder/'consumed.json',4096);ledger=load(ledger_raw)
        require(grant_raw==canonical(grant) and ledger_raw==canonical(ledger),'canonical_authority')
        fault='outcome' not in run;when=ledger['consumed_at'] if fault else run['admitted_at']
        require(type(when) is int and type(ledger['consumed_at']) is int,'admission_clock_type')
        summary,value,source=auth.validate_binding(raw,grant,policy_raw,policy['context'],maintenance,ready,now=when)
        require(summary['request_id']==rid,'candidate_consumption_request_id')
        if inputs is not None:
            entry=next(v for v in inputs['inputs'] if v['case']==run['case'])
            require(source.hex()==entry['source_hex'],'approved_source_bytes')
        require(ledger=={'schema':'paw-s14-hash-consumed-v2','request_id':rid,'grant_sha256':auth.digest(grant_raw),
                'frame_sha256':auth.digest(raw),'policy_sha256':auth.digest(policy_raw),'consumed_at':ledger['consumed_at']},'global_consumption')
        require(value['created_at']<=ledger['consumed_at']<=when<grant['expires_at'],'admission_lease')
        vm=next(v for v in r['vms'] if v['label']=='hash-'+rid);vm_evidence(root,vm,policy['context'])
        if fault:
            require(run['status']=='refused-or-failed' and run['error'] and run['writers_stopped'] is True and
                    not (root/('hash-'+rid+'-quarantine')).exists(),'fault_publication')
            if not single:
                case=run['case'];require(case in FAULTS,'expected_fault')
                if case=='paused-refusal':require('owned_paused_startup_refusal' in run['error'],'paused_fault')
                if case=='protocol-loss':require('guest_channel_failed:' in run['error'],'serial_fault')
                if case=='owner-loss':
                    witness=next(v for v in r['fault_injections'] if v['case']==case)
                    require(witness['vm_uuid']==vm['uuid'] and witness['owner_returncode']==-9 and type(witness['owner_pid']) is int and witness['owner_pid']>0,'owner_fault')
            continue
        require(run['grant_sha256']==auth.digest(grant_raw) and run['policy_sha256']==auth.digest(policy_raw) and
                run['candidate_frame_sha256']==auth.digest(raw) and run['candidate_sha256']==summary['candidate_sha256'] and
                run['execution_purpose']==policy['mode'] and run['consumption']==ledger,'execution_authority')
        expected={'profile':summary['profile'],'job_id':'hash-'+rid,'parent_sha256':summary['case_reference_sha256'],
                  'source_hex':source.hex(),'source_sha256':summary['source_sha256'],'operator_authorization':'root-hash-grant-v2',
                  'created_at':value['created_at'],'expires_at':value['expires_at']}
        require(run['job']==expected and load(regular(root/'admissions'/('hash-'+rid+'.json'),36864))==expected and
                run['job_sha256']==auth.digest(canonical(expected)) and run['vm_uuid']==vm['uuid'],'guest_job_binding')
        require(run['stop_seconds']==vm['stop_seconds'] and run['writers_stopped'] is True,'result_stop_binding')
        admission=run['guest_admission'];require(admission['job_sha256']==run['job_sha256'] and admission['source_sha256']==summary['source_sha256'] and admission['prior_marker_absent'] is True,'guest_admission')
        outcome=run['outcome'];status=outcome['status'];require(status in {'completed','failed','timeout','cancelled','output_budget'},'outcome_status')
        if status!='cancelled':require(outcome['done'] is True and outcome['writers_stopped'] is True and outcome['events']['pids.current']=='0','guest_descendants')
        directory=root/('hash-'+rid+'-quarantine');manifest=run['quarantine'];records=outcome['records']
        validate_records(records)
        require(directory.is_dir() and not directory.is_symlink() and len(manifest)==len(records)==(0 if status=='cancelled' else 2),'output_inventory')
        require({p.name for p in directory.iterdir()}=={v['stored_as'] for v in manifest},'output_files')
        for i,item in enumerate(manifest):
            require(item['stored_as']==f'artifact-{i:02d}.bin','ordinal_output');data=regular(directory/item['stored_as'],1024)
            require(len(data)==item['bytes'] and auth.digest(data)==item['sha256'] and data==bytes.fromhex(records[i]['bytes_hex']),'output_hash')
            require(item['source_name']==records[i]['name'],'output_source_name')
        if inputs is not None:
            case=run['case'];require(case in NORMAL and status==NORMAL[case],'expected_outcome')
            if case=='positive':
                lines=bytes.fromhex(records[0]['bytes_hex']).decode().splitlines()
                require(outcome['returncode']==0 and len(lines)==2 and load(lines[0])=={'owned_marker':'ONE-USE-OFFLINE','cpu_avx_xsave_absent':True,'uid':65534} and
                        lines[1]=='OWNED-HASH-VALIDATION-'+inputs['nonce'],'positive_oracle')
            if case=='failed':require(outcome['returncode']==7,'failure_oracle')
            if case=='overflow':require(outcome['output_truncated'] is True and manifest[0]['bytes']==1024,'output_budget_oracle')
    return {'result':'PASS','jobs':len(r['runs']),'sources':len(r['source_hashes']),
            'mode':policy['mode'],'meaning':'execution/custody only, no benignness or attribution verdict','real_connections':0}


def verify(root):return verify_bundle(root,single=False)
def verify_single(root):return verify_bundle(root,single=True)
