"""Complete fresh-input audit fixtures; no sample, root service or VM executes."""
import json,time,uuid
from pathlib import Path
import tempfile,unittest
import xml.etree.ElementTree as ET
from test_granted_evidence import bundle as legacy_bundle
from test_hash_authorization import context,maintenance,readiness
from test_one_use_authorization import frame
from offline_candidate import canonical,inspect_candidate
from hash_validation_inputs import generate
import hash_authorization as auth
from verify_hash_offline import verify,verify_single,NORMAL


def bundle(root):
    r=legacy_bundle(root);ctx=context();ctx['host']['source_hashes']=r['source_hashes'];maint=maintenance(ctx)
    inputs=generate();inputs_raw=canonical(inputs);policy=auth.make_policy(ctx,maint,[v['source_sha256'] for v in inputs['inputs']],validation_manifest_sha256=auth.digest(inputs_raw))
    (root/'policy.json').write_bytes(policy);(root/'maintenance.json').write_bytes(maint);(root/'approved-inputs.json').write_bytes(inputs_raw)
    r['real_samples_executed']=0
    for index,run in enumerate(r['runs']):
        rid=run['request_id'];case=run['case'];entry=next(v for v in inputs['inputs'] if v['case']==case);source=bytes.fromhex(entry['source_hex'])
        raw=frame(rid,source);value=json.loads(raw);summary=inspect_candidate(raw);when=value['created_at']
        grant={'schema':'paw-s14-hash-grant-v2','scope':auth.SCOPE,**{k:summary[k] for k in ['request_id','frame_sha256','candidate_sha256','source_sha256','case_reference_sha256']},
               'policy_sha256':auth.digest(policy),'execution_purpose':'validation','created_at':when,'expires_at':value['expires_at']}
        grant_raw=canonical(grant);ledger={'schema':'paw-s14-hash-consumed-v2','request_id':rid,'grant_sha256':auth.digest(grant_raw),'frame_sha256':auth.digest(raw),'policy_sha256':auth.digest(policy),'consumed_at':when}
        folder=root/'authority-copy'/rid
        for name,data in [('candidate.json',raw),('grant.json',grant_raw),('consumed.json',canonical(ledger))]:(folder/name).write_bytes(data)
        vm=r['vms'][index];old_uuid=vm['uuid'];uid=str(uuid.UUID(int=index+1));vm['uuid']=uid;vm['actual']['uuid']=uid
        vm['label']='hash-'+rid;vm['actual'].update(qemu_binary_sha256=ctx['qemu_binary_sha256'],memory_merge_disabled=True)
        path=root/('grant-'+rid+'-domain.xml');xml=ET.fromstring(path.read_bytes());xml.find('uuid').text=uid
        ET.SubElement(ET.SubElement(xml,'memoryBacking'),'nosharepages');features=ET.SubElement(xml,'features')
        ET.SubElement(features,'pmu',{'state':'off'});ET.SubElement(features,'vmport',{'state':'off'});ET.SubElement(xml.find('devices'),'controller',{'type':'usb','model':'none'})
        path.unlink();(root/('hash-'+rid+'-domain.xml')).write_bytes(ET.tostring(xml))
        for witness in r['fault_injections']:
            if witness['vm_uuid']==old_uuid:witness['vm_uuid']=uid
        job={'profile':summary['profile'],'job_id':'hash-'+rid,'parent_sha256':summary['case_reference_sha256'],
             'source_hex':source.hex(),'source_sha256':summary['source_sha256'],'operator_authorization':'root-hash-grant-v2',
             'created_at':value['created_at'],'expires_at':value['expires_at']}
        (root/'admissions'/('grant-'+rid+'.json')).unlink();(root/'admissions'/('hash-'+rid+'.json')).write_text(json.dumps(job))
        if case not in NORMAL:continue
        (root/('grant-'+rid+'-quarantine')).rename(root/('hash-'+rid+'-quarantine'))
        run.update(job=job,job_sha256=auth.digest(canonical(job)),vm_uuid=uid,admitted_at=when,consumption=ledger,grant_sha256=auth.digest(grant_raw),
             policy_sha256=auth.digest(policy),candidate_frame_sha256=auth.digest(raw),candidate_sha256=summary['candidate_sha256'],execution_purpose='validation',stop_seconds=.1)
        run['guest_admission'].update(job_sha256=run['job_sha256'],source_sha256=summary['source_sha256'])
        if case=='cancel':continue
        data=(canonical({'owned_marker':'ONE-USE-OFFLINE','cpu_avx_xsave_absent':True,'uid':65534})+('OWNED-HASH-VALIDATION-'+inputs['nonce']+'\n').encode()) if case=='positive' else b'owned'
        if case=='overflow':data=b'X'*1024;run['outcome']['output_truncated']=True
        run['outcome']['records']=[];run['quarantine']=[]
        for i,content in enumerate([data,b'']):
            name='stdout.bin' if i==0 else 'stderr.bin';stored=f'artifact-{i:02d}.bin';(root/('hash-'+rid+'-quarantine')/stored).write_bytes(content)
            run['outcome']['records'].append({'name':name,'bytes_hex':content.hex(),'sha256':auth.digest(content),'scope':'opaque untrusted job output'})
            run['quarantine'].append({'stored_as':stored,'bytes':len(content),'sha256':auth.digest(content),'source_name':name})
    (root/'results.json').write_text(json.dumps(r));return r


class HashEvidence(unittest.TestCase):
    def test_single_job_reader_checks_ready_mode_without_fixture_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);r=bundle(root);run=r['runs'][0];rid=run['request_id'];folder=root/'authority-copy'/rid
            old=json.loads((root/'policy.json').read_bytes());ctx=old['context'];maint=(root/'maintenance.json').read_bytes()
            ready=readiness(ctx,maint);policy=auth.make_policy(ctx,maint,[run['job']['source_sha256']],mode='sample-analysis',readiness_raw=ready)
            (root/'policy.json').write_bytes(policy);(root/'readiness.json').write_bytes(ready)
            grant=json.loads((folder/'grant.json').read_bytes());now=int(time.time())
            grant.update(policy_sha256=auth.digest(policy),execution_purpose='sample-analysis',created_at=now)
            grant_raw=canonical(grant);(folder/'grant.json').write_bytes(grant_raw)
            ledger=json.loads((folder/'consumed.json').read_bytes());ledger.update(grant_sha256=auth.digest(grant_raw),policy_sha256=auth.digest(policy),consumed_at=now)
            (folder/'consumed.json').write_bytes(canonical(ledger))
            run.update(grant_sha256=auth.digest(grant_raw),policy_sha256=auth.digest(policy),consumption=ledger,admitted_at=now,execution_purpose='sample-analysis')
            r['runs']=[run];r['vms']=r['vms'][:1];r['fault_injections']=[];(root/'results.json').write_text(json.dumps(r))
            self.assertEqual(verify_single(root)['mode'],'sample-analysis')
            (root/'readiness.json').unlink()
            with self.assertRaises(OSError):verify_single(root)

    def test_complete_fresh_source_export_passes_without_catalogue_membership(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle(root);self.assertEqual(verify(root)['jobs'],8)
            with self.assertRaisesRegex(ValueError,'single_analysis_scope'):verify_single(root)

    def test_changed_approval_binary_merge_mode_lease_and_stop_refuse(self):
        for mutation in ['approval','binary','merge','mode','lease','stop','output']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);r=bundle(root)
                if mutation=='approval':(root/'approved-inputs.json').write_bytes(canonical(generate()))
                elif mutation=='binary':r['vms'][0]['actual']['qemu_binary_sha256']='0'*64
                elif mutation=='merge':r['vms'][0]['actual']['memory_merge_disabled']=False
                elif mutation=='mode':r['runs'][0]['execution_purpose']='sample-analysis'
                elif mutation=='lease':r['runs'][0]['admitted_at']+=1000
                elif mutation=='stop':r['vms'][0]['stop_seconds']=-1
                else:r['runs'][0]['outcome']['records'][0]['name']='../escape'
                (root/'results.json').write_text(json.dumps(r))
                with self.assertRaises(ValueError):verify(root)

    def test_authority_symlinks_and_readiness_self_assertion_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);r=bundle(root);path=root/'authority-copy'/r['runs'][0]['request_id']/'grant.json'
            outside=root/'outside';path.rename(outside);path.symlink_to(outside)
            with self.assertRaises(OSError):verify(root)


if __name__=='__main__':unittest.main()
