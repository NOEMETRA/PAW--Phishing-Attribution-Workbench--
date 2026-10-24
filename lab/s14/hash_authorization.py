"""Generic per-hash authority, isolated from the historical fixed fixture store.

Only root installs policy, maintenance and readiness records. Validation uses an
explicit finite set of approved input hashes, not a compiled source catalogue.
Real analysis additionally requires a root-protected, exact-context I08 receipt.
"""
import contextlib
import json
import os
from pathlib import Path
import re
import time
import subprocess

import one_use_authorization as fs
from offline_candidate import canonical, decode, inspect_candidate, require
from i08_context import capture as host_context
from benign_guest_validation import digest as file_digest

ROOT=Path('/var/lib/paw-s14/authorization-v2')
SCOPE='hash-pinned-offline-python-v2'
VERSION='1:10.2.1+ds-1ubuntu3.3'
COMPONENTS=('qemu-system-common','qemu-system-data','qemu-system-gui','qemu-system-modules-opengl',
            'qemu-system-modules-spice','qemu-system-x86','qemu-utils')


def digest(data):return fs.digest(data)


def capture():
    inventory=subprocess.check_output(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\n'],timeout=15).splitlines()
    versions=subprocess.check_output(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\n',*COMPONENTS],text=True,timeout=10)
    cpu=dict(line.split(':',1) for line in Path('/proc/cpuinfo').read_text().split('\n\n',1)[0].splitlines() if ':' in line)
    cpu={k.strip():v.strip() for k,v in cpu.items()}
    return {'host':host_context(),'qemu_binary_sha256':file_digest(Path('/usr/bin/qemu-system-x86_64')),
            'ksm_run':Path('/sys/kernel/mm/ksm/run').read_text().strip(),
            'dpkg_inventory_sha256':digest(b'\n'.join(sorted(inventory))+b'\n'),
            'qemu_components':dict(line.split('\t',1) for line in versions.splitlines()),
            'host_identity_sha256':digest(Path('/etc/machine-id').read_bytes().strip()),
            'cpu_signature':{k:cpu[k] for k in ['vendor_id','cpu family','model','stepping','microcode']}}


@contextlib.contextmanager
def store():
    with fs.root_directory(ROOT) as fd:yield fd


def validate_context(context):
    require(type(context) is dict and set(context)=={'host','qemu_binary_sha256','ksm_run','dpkg_inventory_sha256','qemu_components',
            'host_identity_sha256','cpu_signature'},'hash_context_shape')
    # Reuse the proven platform predicate without its catalogue-specific grant.
    fs.make_policy(context['host'])
    require(context['host']['packages']['qemu-system-x86']==VERSION,'qemu_maintenance_baseline')
    require(type(context['qemu_binary_sha256']) is str and re.fullmatch('[0-9a-f]{64}',context['qemu_binary_sha256']) and
            type(context['dpkg_inventory_sha256']) is str and re.fullmatch('[0-9a-f]{64}',context['dpkg_inventory_sha256']) and
            context['ksm_run'] in {'0','1','2'} and context['qemu_components']=={n:VERSION for n in COMPONENTS},'hash_platform_state')
    require({'hash_authorization.py','hash_offline_adapter.py','hash_offline_matrix.py','verify_hash_offline.py'} <=
            context['host']['source_hashes'].keys(),'hash_required_sources')
    require(type(context['host_identity_sha256']) is str and re.fullmatch('[0-9a-f]{64}',context['host_identity_sha256']) and
            type(context['cpu_signature']) is dict and set(context['cpu_signature'])=={'vendor_id','cpu family','model','stepping','microcode'} and
            all(type(v) is str and 0<len(v)<=128 for v in context['cpu_signature'].values()),'host_identity_or_cpu')


def validate_maintenance(raw,context):
    record=json.loads(raw);validate_context(context)
    require(type(record) is dict and set(record)=={'schema','packages','kernel','image_sha256','qemu_binary_sha256',
            'vendor_manifest_sha256','vendor_signer','guest_kernel_release','reboot_required','review_notes',
            'dpkg_inventory_sha256','qemu_components','host_identity_sha256','cpu_signature'},'maintenance_shape')
    require(record['schema']=='paw-s14-maintenance-v2' and record['packages']==context['host']['packages'] and
            record['kernel']==context['host']['kernel'] and record['image_sha256']==fs.IMAGE_SHA256 and
            record['qemu_binary_sha256']==context['qemu_binary_sha256'] and record['reboot_required'] is False and
            record['dpkg_inventory_sha256']==context['dpkg_inventory_sha256'] and
            record['qemu_components']==context['qemu_components'] and record['host_identity_sha256']==context['host_identity_sha256'] and
            record['cpu_signature']==context['cpu_signature'],'maintenance_binding')
    require(record['vendor_manifest_sha256']=='6cd96c00a9a7f3b77233af758968d94e83f9cec396a1b5035ccd8688a26aa804' and
            record['vendor_signer']=='D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81' and
            record['guest_kernel_release']=='6.8.0-147-generic' and type(record['review_notes']) is str and
            1<=len(record['review_notes'])<=2048,'guest_maintenance_inventory')
    require(raw==canonical(record),'canonical_maintenance')
    return record


def validate_readiness(raw,context,maintenance_raw,now=None):
    record=json.loads(raw);now=time.time() if now is None else now
    require(type(record) is dict and set(record)=={'schema','context_sha256','maintenance_sha256','reviewed_head',
            'review_url','ci_runs','ci_successful_jobs','created_at','expires_at','decision'},'readiness_shape')
    require(record['schema']=='paw-s14-i08-readiness-v2' and record['decision']=='ready-for-explicit-single-hash-offline-python-grants' and
            record['context_sha256']==digest(canonical(context)) and record['maintenance_sha256']==digest(maintenance_raw),'readiness_binding')
    require(type(record['reviewed_head']) is str and re.fullmatch('[0-9a-f]{40}',record['reviewed_head']) and
            type(record['review_url']) is str and re.fullmatch(r'https://github\.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/[0-9]+#issuecomment-[0-9]+',record['review_url']), 'readiness_review_receipt')
    require(type(record['ci_runs']) is list and len(record['ci_runs'])==2 and
            all(type(v) is int and v>0 for v in record['ci_runs']) and len(set(record['ci_runs']))==2 and type(record['ci_successful_jobs']) is int and
            record['ci_successful_jobs']==7,'readiness_ci_receipt')
    require(type(record['created_at']) is int and type(record['expires_at']) is int and
            record['created_at']<=now<record['expires_at']<=record['created_at']+86400,'readiness_clock')
    require(raw==canonical(record),'canonical_readiness')
    return record


def validate_policy(raw,context,maintenance_raw,readiness_raw=None,now=None):
    now=time.time() if now is None else now;value=json.loads(raw);validate_maintenance(maintenance_raw,context)
    require(type(value) is dict and set(value)=={'schema','scope','context','maintenance_sha256','readiness_sha256',
            'mode','approved_source_hashes','created_at','expires_at','validation_manifest_sha256'},'hash_policy_shape')
    require(value['schema']=='paw-s14-hash-policy-v2' and value['scope']==SCOPE and value['context']==context and
            value['maintenance_sha256']==digest(maintenance_raw),'hash_policy_binding')
    hashes=value['approved_source_hashes']
    require(type(hashes) is list and 1<=len(hashes)<=32 and
            all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in hashes) and len(set(hashes))==len(hashes),'approved_hashes')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at']<=now<value['expires_at']<=value['created_at']+86400,'hash_policy_clock')
    if value['mode']=='validation':
        require(value['readiness_sha256'] is None and type(value['validation_manifest_sha256']) is str and
                re.fullmatch('[0-9a-f]{64}',value['validation_manifest_sha256']),'validation_not_readiness')
    elif value['mode']=='sample-analysis':
        require(len(hashes)==1 and readiness_raw is not None,'single_sample_readiness_required')
        require(value['validation_manifest_sha256'] is None,'analysis_not_validation')
        ready=validate_readiness(readiness_raw,context,maintenance_raw,now=now)
        require(value['readiness_sha256']==digest(readiness_raw) and value['expires_at']<=ready['expires_at'],'policy_readiness')
    else:raise ValueError('hash_policy_mode')
    require(raw==canonical(value),'canonical_hash_policy')
    return value


def make_policy(context,maintenance_raw,approved_hashes,mode='validation',readiness_raw=None,validation_manifest_sha256=None):
    now=int(time.time());expiry=now+86400
    if mode=='sample-analysis':
        require(readiness_raw is not None,'single_sample_readiness_required')
        expiry=min(expiry,json.loads(readiness_raw)['expires_at'])
    value={'schema':'paw-s14-hash-policy-v2','scope':SCOPE,'context':context,'maintenance_sha256':digest(maintenance_raw),
           'readiness_sha256':digest(readiness_raw) if readiness_raw else None,'mode':mode,
           'validation_manifest_sha256':validation_manifest_sha256,
           'approved_source_hashes':list(approved_hashes),'created_at':now,'expires_at':expiry}
    raw=canonical(value);validate_policy(raw,context,maintenance_raw,readiness_raw);return raw


def installed(policy_raw,context,now=None):
    value=json.loads(policy_raw)
    with store() as fd:
        require(fs.read(fd,'policy-'+digest(policy_raw)+'.json')==policy_raw,'hash_policy_not_installed')
        maintenance_raw=fs.read(fd,'maintenance-'+value['maintenance_sha256']+'.json')
        ready=fs.read(fd,'readiness-'+value['readiness_sha256']+'.json') if value['readiness_sha256'] is not None else None
    return validate_policy(policy_raw,context,maintenance_raw,ready,now),maintenance_raw,ready


def validate_binding(raw,grant,policy_raw,context,maintenance_raw,readiness_raw=None,now=None):
    summary=inspect_candidate(raw,now=now);value=decode(raw)
    policy=validate_policy(policy_raw,context,maintenance_raw,readiness_raw,now)
    require(type(grant) is dict and set(grant)=={'schema','scope','request_id','frame_sha256','candidate_sha256',
            'source_sha256','case_reference_sha256','policy_sha256','execution_purpose','created_at','expires_at'},'hash_grant_shape')
    require(grant['schema']=='paw-s14-hash-grant-v2' and grant['scope']==SCOPE and grant['execution_purpose']==policy['mode'],'hash_grant_scope')
    for key in ['request_id','frame_sha256','candidate_sha256','source_sha256','case_reference_sha256']:
        require(grant[key]==summary[key],'hash_grant_binding:'+key)
    require(grant['source_sha256'] in policy['approved_source_hashes'] and grant['policy_sha256']==digest(policy_raw),'source_not_explicitly_approved')
    now=time.time() if now is None else now
    require(type(grant['created_at']) is int and type(grant['expires_at']) is int and
            value['created_at']<=grant['created_at']<=now<grant['expires_at']<=min(value['expires_at'],policy['expires_at'],grant['created_at']+900),'hash_grant_clock')
    return summary,value,bytes.fromhex(value['source']['data_hex'])


def issue(raw,policy_raw,context):
    require(os.geteuid()==0,'root_operator_required');policy,maintenance,ready=installed(policy_raw,context)
    summary=inspect_candidate(raw);now=int(time.time());value=decode(raw)
    grant={'schema':'paw-s14-hash-grant-v2','scope':SCOPE,
           **{k:summary[k] for k in ['request_id','frame_sha256','candidate_sha256','source_sha256','case_reference_sha256']},
           'policy_sha256':digest(policy_raw),'execution_purpose':policy['mode'],'created_at':now,
           'expires_at':min(now+900,value['expires_at'],policy['expires_at'])}
    validate_binding(raw,grant,policy_raw,context,maintenance,ready)
    with store() as fd:
        with fs.subdirectory(fd,'grants') as target:fs.exclusive(target,summary['request_id']+'.json',canonical(grant))
    return grant


def load_bound(raw,policy_raw,context,now=None):
    summary=inspect_candidate(raw,now=now);policy,maintenance,ready=installed(policy_raw,context,now=now)
    with store() as fd:
        with fs.subdirectory(fd,'grants') as source:grant_raw=fs.read(source,summary['request_id']+'.json',4096)
    summary,value,content=validate_binding(raw,json.loads(grant_raw),policy_raw,context,maintenance,ready,now=now)
    return grant_raw,summary,value,content


def consume(raw,policy_raw,context):
    require(os.geteuid()==0,'root_operator_required');grant_raw,summary,value,source=load_bound(raw,policy_raw,context)
    ledger={'schema':'paw-s14-hash-consumed-v2','request_id':summary['request_id'],'grant_sha256':digest(grant_raw),
            'frame_sha256':digest(raw),'policy_sha256':digest(policy_raw),'consumed_at':int(time.time())}
    with store() as fd:
        with fs.subdirectory(fd,'consumed') as used:fs.exclusive(used,summary['request_id']+'.json',canonical(ledger))
    return ledger,grant_raw,summary,value,source


def confirm_consumed(ledger):
    with store() as fd:
        with fs.subdirectory(fd,'consumed') as used:require(fs.read(used,ledger['request_id']+'.json',4096)==canonical(ledger),'hash_consumption_changed')
