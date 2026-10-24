"""Complete inert export and substitutions; never creates guests or runs sources."""
import json
from pathlib import Path
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from offline_candidate import canonical,inspect_candidate
from one_use_authorization import make_policy,digest,SCOPE
from test_one_use_authorization import context,frame
from owned_grant_fixtures import SOURCES,CPU_DISABLED
from verify_granted_offline import verify,NORMAL,FAULTS


def bundle(root):
    ctx=context();source_dir=Path(__file__).parent
    manifest={p.name:digest(p.read_bytes()) for p in source_dir.iterdir() if p.suffix in {'.py','.nft','.xml','.service','.conf','.slice'}}
    ctx['source_hashes']=manifest;policy=canonical(make_policy(ctx));(root/'policy.json').write_bytes(policy)
    (root/'sources').mkdir()
    for name in manifest:(root/'sources'/name).write_bytes((source_dir/name).read_bytes())
    (root/'authority-copy').mkdir();(root/'admissions').mkdir()
    r=dict(result='PASS',source_hashes=manifest,host_before={},host_after={},real_connections=0,runs=[],vms=[],fault_injections=[])
    r.update({k:True for k in ['host_restored','base_unchanged','host_canary_unchanged','writers_stopped','source_freeze_unchanged','global_replay_refused','unknown_stop_publication_refused']})
    for index,case in enumerate([*NORMAL,*sorted(FAULTS)]):
        rid=f'{index:032x}';raw=frame(rid,SOURCES[case if case in NORMAL else 'positive']);value=json.loads(raw);summary=inspect_candidate(raw);now=int(time.time())
        grant={'schema':'paw-s14-one-use-grant-v1','scope':SCOPE,**{k:summary[k] for k in ['request_id','frame_sha256','candidate_sha256','source_sha256','case_reference_sha256']},'policy_sha256':digest(policy),'created_at':now,'expires_at':value['expires_at']}
        grant_raw=canonical(grant);ledger=dict(schema='paw-s14-consumed-grant-v1',request_id=rid,grant_sha256=digest(grant_raw),frame_sha256=digest(raw),policy_sha256=digest(policy),consumed_at=now,meaning='consumed before VM creation, including any subsequent failure')
        folder=root/'authority-copy'/rid;folder.mkdir()
        for name,data in [('candidate.json',raw),('grant.json',grant_raw),('consumed.json',canonical(ledger))]:(folder/name).write_bytes(data)
        label='grant-'+rid;uid='owned-'+str(index)
        vm=dict(label=label,uuid=uid,actual=dict(uuid=uid,pid=100+index,pid_identity=str(500+index),apparmor='libvirt-owned (enforce)',
            limits={'memory.max':str(768*1024**2),'memory.swap.max':'0','pids.max':'64','cpu.max':'50000 100000'}),
            host_status='Seccomp:\t2',stopped=True,stop_seconds=.1,fsize_limit=256*1024**2,overlay_bytes=1)
        xml=ET.fromstring('<domain><uuid>'+uid+'</uuid><cpu/><memory unit="KiB">524288</memory><defaultiothread thread_pool_max="8"/><devices/><seclabel model="dac"><label>+64055:+64055</label></seclabel></domain>')
        for name in CPU_DISABLED:ET.SubElement(xml.find('cpu'),'feature',{'name':name,'policy':'disable'})
        (root/(label+'-domain.xml')).write_bytes(ET.tostring(xml));r['vms'].append(vm)
        job={'profile':summary['profile'],'job_id':label,'parent_sha256':summary['case_reference_sha256'],'source_hex':value['source']['data_hex'],'source_sha256':summary['source_sha256'],
             'operator_authorization':'root-owned-synthetic-grant-v1','created_at':value['created_at'],'expires_at':value['expires_at']}
        (root/'admissions'/(label+'.json')).write_text(json.dumps(job))
        if case in FAULTS:
            error={'paused-refusal':'RuntimeError:owned_paused_startup_refusal','owner-loss':'TimeoutError:guest_channel_deadline','protocol-loss':'ValueError:guest_channel_failed:unexpected_response'}[case]
            r['runs'].append(dict(case=case,request_id=rid,status='refused-or-failed',error=error,writers_stopped=True))
            if case=='owner-loss':r['fault_injections'].append(dict(case=case,vm_uuid=uid,owner_pid=300+index,owner_returncode=-9))
            continue
        output=root/(label+'-quarantine');output.mkdir();records=[];quarantine=[]
        if case!='cancel':
            stdout=canonical({'owned_marker':'ONE-USE-OFFLINE','cpu_avx_xsave_absent':True,'uid':65534}) if case=='positive' else b'owned'
            for i,data in enumerate([stdout,b'']):
                stored=f'artifact-{i:02d}.bin';(output/stored).write_bytes(data)
                records.append({'bytes_hex':data.hex()});quarantine.append({'stored_as':stored,'bytes':len(data),'sha256':digest(data)})
        run=dict(case=case,request_id=rid,job=job,job_sha256=digest(canonical(job)),vm_uuid=uid,
            guest_admission={'source_sha256':job['source_sha256'],'job_sha256':digest(canonical(job)),'prior_marker_absent':True},
            outcome=dict(status=NORMAL[case],returncode=7 if case=='failed' else 0,done=case!='cancel',writers_stopped=True,events={'pids.current':'0'},records=records),
            writers_stopped=True,quarantine=quarantine,admitted_at=now,consumption=ledger,grant_sha256=digest(grant_raw),policy_sha256=digest(policy),
            candidate_sha256=summary['candidate_sha256'],candidate_frame_sha256=digest(raw))
        r['runs'].append(run)
    (root/'results.json').write_text(json.dumps(r));return r


class Evidence(unittest.TestCase):
    def test_complete_export_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle(root);self.assertEqual(verify(root)['jobs'],8)

    def test_altered_ledger_quota_guest_cpu_stop_and_binding_refuse(self):
        for mutation in ['ledger','quota','cpu','stop','binding','fault']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);r=bundle(root);rid=r['runs'][0]['request_id']
                if mutation=='ledger':(root/'authority-copy'/rid/'consumed.json').write_bytes(canonical({}))
                elif mutation=='quota':r['vms'][0]['actual']['limits']['cpu.max']='75000 100000'
                elif mutation=='cpu':
                    path=root/('grant-'+rid+'-domain.xml');path.write_text(path.read_text().replace('policy="disable"','policy="require"',1))
                elif mutation=='stop':r['vms'][0]['stopped']=None
                elif mutation=='binding':r['runs'][0]['candidate_sha256']='0'*64
                else:r['fault_injections'][0]['owner_returncode']=0
                (root/'results.json').write_text(json.dumps(r))
                with self.assertRaises((ValueError,KeyError)):verify(root)

    def test_symlink_authority_and_quarantine_and_traversal_refuse(self):
        for mutation in ['authority-dir','authority-file','quarantine','id']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                parent=Path(directory);root=parent/'bundle';root.mkdir();r=bundle(root);rid=r['runs'][0]['request_id'];outside=parent/'outside'
                if mutation=='authority-dir':
                    path=root/'authority-copy'/rid;path.rename(outside);path.symlink_to(outside,target_is_directory=True)
                elif mutation=='authority-file':
                    path=root/'authority-copy'/rid/'grant.json';path.rename(outside);path.symlink_to(outside)
                elif mutation=='quarantine':
                    path=root/('grant-'+rid+'-quarantine')/'artifact-00.bin';path.rename(outside);path.symlink_to(outside)
                else:r['runs'][0]['request_id']='../../outside';(root/'results.json').write_text(json.dumps(r))
                with self.assertRaises((ValueError,OSError)):verify(root)


if __name__=='__main__':unittest.main()
