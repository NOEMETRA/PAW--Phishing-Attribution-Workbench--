"""Real serialized native custody; image/hardware/Root trust explicitly substituted."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

REPO=Path(__file__).resolve().parents[1];sys.path[:0]=[str(REPO),str(REPO/'lab/s14')]
import native_runtime as native
from test_representation_bridge import forensic_case
from test_native_adapter import fixture as abi_fixture
from representation_owned_inputs import native_fixtures
from gw_quarantine import publish


class NativeEvidence(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()

    def fixture(self,profile='shell'):
        root=self.root/uuid.uuid4().hex;root.mkdir();home=self.root/uuid.uuid4().hex;home.mkdir()
        entry=native_fixtures('a'*16,profile)[0];case,graph=forensic_case(home,entry['selected'])
        info=native.contract.prepare(case,graph.root,profile,home/'request');raw=Path(info['request']).read_bytes()
        request=native.contract.validate_request(raw);summary=native.inspect(raw);rid=summary['request_id']
        snapshot=root/'runtime-snapshot';snapshot.mkdir();(root/'sources').mkdir();files={};hashes={}
        for source in (REPO/'lab/s14').iterdir():
            if source.suffix not in {'.py','.nft','.xml','.service','.conf','.slice'}:continue
            name='lab/s14/'+source.name;target=snapshot/name;target.parent.mkdir(parents=True,exist_ok=True)
            data=source.read_bytes();target.write_bytes(data);(root/'sources'/source.name).write_bytes(data)
            files[name]={'bytes':len(data),'sha256':native.digest(data)};hashes[source.name]=native.digest(data)
        (snapshot/'paw').mkdir();(snapshot/'paw/owned.py').write_bytes(b'# inert snapshot marker, never run\n')
        data=(snapshot/'paw/owned.py').read_bytes();files['paw/owned.py']={'bytes':len(data),'sha256':native.digest(data)}
        proof=native.storage.canonical({'repository':native.storage.REPOSITORY,'head_sha':'1'*40,'merge_sha':'2'*40})
        header=native.storage.canonical({'schema':'paw-vm-root-snapshot-v1','repository':native.storage.REPOSITORY,
            'release_sha':'2'*40,'head_sha':'1'*40,'proof_sha256':native.digest(proof),'files':files})
        (snapshot/'release.json').write_bytes(header);(snapshot/'proof.json').write_bytes(proof)
        maintenance=native.canonical({'owned':'inert maintained platform stand-in'});(root/'maintenance.json').write_bytes(maintenance)
        backend={'host':{'source_hashes':hashes,'image_sha256':native.fs.IMAGE_SHA256}}
        ctx={'profile':native.contract.PROFILES[profile].engine,'backend':backend,'contract_sha256':native.contract.contract_hash(),
            'runtime_sources_sha256':native.digest(native.storage.canonical(files)),'maintenance_sha256':native.digest(maintenance),
            'guest_controller_sha256':native.guest_controller_hash()}
        with mock.patch.object(native.python_backend,'validate_context'):
            policy=native.make_policy(ctx,[raw],owned_manifest_sha256='3'*64)
        now=int(time.time());grant={'schema':'paw-s14-native-grant-v1','scope':native.SCOPE,**summary,
            'policy_sha256':native.digest(policy),'context_sha256':native.digest(native.canonical(ctx)),
            'execution_purpose':'owned-validation','created_at':now,'expires_at':min(now+900,request['candidate']['expires_at'])}
        grant_raw=native.canonical(grant);ledger={'schema':'paw-s14-native-consumed-v1','request_id':rid,
            'request_sha256':native.digest(raw),'grant_sha256':native.digest(grant_raw),'policy_sha256':native.digest(policy),
            'context_sha256':native.digest(native.canonical(ctx)),'consumed_at':now}
        copies=root/'authority-copy'/rid;copies.mkdir(parents=True)
        for name,data in [('request.json',raw),('grant.json',grant_raw),('consumed.json',native.canonical(ledger))]:(copies/name).write_bytes(data)
        (root/'policy.json').write_bytes(policy);job=native.native_job(request);label=job['job_id'];job_sha=native.digest(native.canonical(job))
        (root/'admissions').mkdir();(root/'admissions'/(label+'.json')).write_bytes(native.canonical(job))
        uid=str(uuid.uuid4());actual={'uuid':uid,'pid':12345,'pid_identity':'123456'}
        vm={'uuid':uid,'label':label,'stopped':True,'stop_seconds':.05,'actual':actual}
        owner={'reason':'requested_stop','connection_closed':True}
        (root/(label+'-owner-result.json')).write_bytes(native.canonical(owner));(root/(label+'-ready.json')).write_bytes(native.canonical(actual))
        (root/'image-provenance.json').write_bytes(native.canonical({'result':'PASS','signed_manifest':True,'image':native.BASE.name,
            'sha256':native.fs.IMAGE_SHA256,'bytes':259981312,'signature_status':'[GNUPG:] VALIDSIG '+native.SIGNER+' owned inert metadata stand-in'}))
        _,inspection,admission,outcome=abi_fixture();seed=native.native_seed({'job':job,'source':entry['selected'],'job_sha256':job_sha})
        inspection.update(seed);inspection['interpreter']='/bin/dash' if profile=='shell' else None
        inspection['interpreter_sha256']='2'*64 if profile=='shell' else None
        admission.update(source_sha256=summary['source_sha256'],job_sha256=job_sha,profile=ctx['profile'],inspection=inspection)
        opaque=b'OWNED OPAQUE BYTES\n';outcome['records'][0].update(bytes_hex=opaque.hex(),sha256=native.digest(opaque))
        manifest=publish(root/(label+'-quarantine'),outcome['records'],stopped=True)
        run={'request_id':rid,'job':job,'job_sha256':job_sha,'vm_uuid':uid,'owner_result':owner,'request_sha256':native.digest(raw),
            'candidate_sha256':summary['candidate_sha256'],'selection_binding_sha256':summary['selection_binding_sha256'],
            'grant_sha256':native.digest(grant_raw),'policy_sha256':native.digest(policy),'context_sha256':native.digest(native.canonical(ctx)),
            'consumption':ledger,'admitted_at':now,'guest_admission':admission,'outcome':outcome,'quarantine':manifest,
            'writers_stopped':True,'stop_seconds':.05}
        report={'result':'PASS','scope':native.SCOPE,'host_restored':True,'base_unchanged':True,'host_canary_unchanged':True,
            'writers_stopped':True,'source_freeze_unchanged':True,'host_before':{'owned':1},'host_after':{'owned':1},
            'real_connections':0,'source_hashes':hashes,'runs':[run],'vms':[vm]}
        (root/'results.json').write_bytes(native.canonical(report));return root,report,ctx

    @contextmanager
    def hardware(self):
        with mock.patch.object(native.python_backend,'validate_context'),mock.patch.object(native.python_backend,'validate_maintenance'), \
             mock.patch.object(native,'vm_evidence'):yield

    def verify(self,root):
        with self.hardware():return native.verify_native(root)

    def rewrite(self,root,name,change):
        path=root/name;value=json.loads(path.read_bytes());change(value);path.write_bytes(native.canonical(value))

    def test_shell_and_elf_serialized_authority_full_snapshot_and_opaque_output(self):
        for profile in ['shell','elf']:
            root,_,_=self.fixture(profile)
            with self.subTest(profile=profile):self.assertEqual(self.verify(root)['result'],'PASS')

    def test_parent_digest_ledger_grant_and_admission_changes_refuse(self):
        for kind in ['parent','ledger','grant','job','binding']:
            root,report,_=self.fixture();run=report['runs'][0];rid=run['request_id'];label=run['job']['job_id']
            if kind=='parent':self.rewrite(root,'results.json',lambda v:v['runs'][0]['job'].update(parent_sha256='0'*64))
            elif kind=='ledger':self.rewrite(root,'authority-copy/'+rid+'/consumed.json',lambda v:v.update(request_sha256='0'*64))
            elif kind=='grant':self.rewrite(root,'authority-copy/'+rid+'/grant.json',lambda v:v.update(policy_sha256='0'*64))
            elif kind=='job':self.rewrite(root,'admissions/'+label+'.json',lambda v:v.update(source_bytes=True))
            else:self.rewrite(root,'results.json',lambda v:v['runs'][0].update(selection_binding_sha256='0'*64))
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.verify(root)

    def test_unknown_stop_owner_session_or_caps_cannot_be_success(self):
        for kind in ['stop','owner','session','caps','time']:
            root,report,_=self.fixture();label=report['runs'][0]['job']['job_id']
            if kind=='stop':self.rewrite(root,'results.json',lambda v:v['vms'][0].update(stopped=None))
            elif kind=='time':self.rewrite(root,'results.json',lambda v:v['vms'][0].update(stop_seconds=12))
            elif kind=='owner':self.rewrite(root,label+'-owner-result.json',lambda v:v.update(connection_closed=False))
            elif kind=='session':self.rewrite(root,'results.json',lambda v:v['runs'][0]['guest_admission']['boundary'].update(session_id=1))
            else:self.rewrite(root,'results.json',lambda v:v['runs'][0]['guest_admission']['boundary'].update(capabilities='nonzero'))
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.verify(root)

    def test_modified_full_runtime_source_lab_copy_or_extra_job_is_rejected(self):
        for kind in ['snapshot','source','proof','extra']:
            root,report,_=self.fixture()
            if kind=='snapshot':(root/'runtime-snapshot/paw/owned.py').write_bytes(b'changed')
            elif kind=='source':(root/'sources/native_guest.py').write_bytes(b'changed')
            elif kind=='proof':(root/'runtime-snapshot/proof.json').write_bytes(b'changed')
            else:(root/'foreign-job.json').write_bytes(b'{}')
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.verify(root)

    def test_extra_authority_admission_or_quarantine_and_changed_blob_refuse(self):
        for kind in ['authority','admission','quarantine','blob']:
            root,report,_=self.fixture();label=report['runs'][0]['job']['job_id']
            if kind=='authority':(root/'authority-copy'/('f'*32)).mkdir()
            elif kind=='admission':(root/'admissions/foreign.json').write_bytes(b'{}')
            elif kind=='quarantine':(root/(label+'-quarantine')/'foreign.bin').write_bytes(b'owned')
            else:(root/(label+'-quarantine')/'artifact-00.bin').write_bytes(b'changed')
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.verify(root)

    def test_host_cancellation_requires_empty_outputs_and_known_external_stop(self):
        root,report,_=self.fixture();run=report['runs'][0];label=run['job']['job_id']
        shutil.rmtree(root/(label+'-quarantine'));(root/(label+'-quarantine')).mkdir()
        run.update(outcome={'status':'cancelled','records':[],'done':False},quarantine=[])
        (root/'results.json').write_bytes(native.canonical(report));self.assertEqual(self.verify(root)['result'],'PASS')
        self.rewrite(root,'results.json',lambda v:v['runs'][0]['outcome'].update(done=0))
        with self.assertRaises(ValueError):self.verify(root)

    def fault_fixture(self,case):
        root,report,_=self.fixture();run=report['runs'][0];vm=report['vms'][0];label=run['job']['job_id']
        raw=(root/'authority-copy'/run['request_id']/'request.json').read_bytes();shutil.rmtree(root/(label+'-quarantine'))
        witness={'schema':'paw-s14-native-fault-v1','case':case,'vm_uuid':vm['uuid'],'stop_after_fault_seconds':.1}
        report.update(result='FAIL',error=native.FAULTS[case],runs=[])
        if case=='paused-refusal':witness['paused_before_refusal']=True
        else:
            witness.update(admitted_at=run['admitted_at'],guest_admission=run['guest_admission'])
            if case=='owner-loss':
                witness.update(owner_pid=4321,owner_identity='12345',owner_returncode=-9);(root/(label+'-owner-result.json')).unlink()
            else:witness['serial_closed']=True
        (root/'results.json').write_bytes(native.canonical(report));return root,raw,case,witness

    def test_all_three_faults_prove_no_output_and_known_stop(self):
        for case in native.FAULTS:
            with self.hardware():self.assertEqual(native.verify_native_fault(*self.fault_fixture(case))['result'],'PASS')

    def test_fault_unknown_stop_or_output_refuses_even_with_inert_hardware_substitution(self):
        for kind in ['stop','output']:
            args=self.fault_fixture('protocol-loss');root,_,_,_=args
            if kind=='stop':self.rewrite(root,'results.json',lambda v:v['vms'][0].update(stopped=None))
            else:
                report=json.loads((root/'results.json').read_bytes());(root/(report['vms'][0]['label']+'-quarantine')).mkdir()
            with self.subTest(kind=kind),self.hardware(),self.assertRaises(ValueError):native.verify_native_fault(*args)


if __name__=='__main__':unittest.main()
