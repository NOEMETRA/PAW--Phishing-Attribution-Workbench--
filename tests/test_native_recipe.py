"""Finite native producer/recipe tests; no privileged service, VM or payload run."""
import copy
from contextlib import contextmanager, ExitStack
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

REPO=Path(__file__).resolve().parents[1];sys.path[:0]=[str(REPO),str(REPO/'lab/s14')]
import native_runtime as native
from representation_owned_inputs import native_fixtures,NATIVE_CASES
from paw.core.linux_profiles import inspect_source
from test_representation_bridge import forensic_case
from test_vm_release_contract import fixture as release_fixture


class NativeRecipe(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()

    def test_all_owned_fixtures_are_finite_deterministic_and_structurally_admitted_without_exec(self):
        with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('no host source execution')):
            for profile in ['shell','elf']:
                rows=native_fixtures('a'*16,profile)
                self.assertEqual(rows,native_fixtures('a'*16,profile))
                self.assertEqual({r['slot'] for r in rows},set(NATIVE_CASES[profile])|{'smoke'})
                for row in rows:inspect_source(profile,row['selected'])
                self.assertEqual(len(rows[-1]['selected']),65536 if profile=='shell' else 1024**2)
                self.assertNotEqual(rows[0]['selected'],native_fixtures('b'*16,profile)[0]['selected'])
                derived=next(r for r in rows if r['slot']=='derived')
                self.assertNotEqual(derived['original'],derived['selected']);self.assertEqual(derived['kind'],'parser_selected_payload')
        for profile,nonce in [('windows','a'*16),('elf','../x')]:
            with self.assertRaises(ValueError):native_fixtures(nonce,profile)

    def test_validation_batches_fit_unchanged_parent_budget_and_cover_every_case_once(self):
        for profile in ['shell','elf']:
            batches=native.validation_batches(profile)
            self.assertEqual(tuple(slot for batch in batches for slot in batch),NATIVE_CASES[profile])
            self.assertTrue(all(1 <= len(batch) <= 3 for batch in batches))
            # The observed full Shell sequence hit1800s before case8 completed.
            # Three cold boots at the existing220s readiness limit leave room
            # for preparation and verification; the Root1800s cap is unchanged.
            self.assertLess(max(map(len,batches))*260+360,1800)
        with self.assertRaises(ValueError):native.validation_batches('windows')

    def test_full_size_elf_job_keeps_source_opaque_in_ingress_not_in_report(self):
        data=native_fixtures('a'*16,'elf')[-1]['selected'];home=self.root/'input';home.mkdir()
        case,graph=forensic_case(home,data);info=native.contract.prepare(case,graph.root,'elf',home/'request')
        request=native.contract.validate_request(Path(info['request']).read_bytes());job=native.native_job(request)
        self.assertNotIn('source_hex',job);self.assertEqual(job['source_bytes'],1024**2)
        self.assertLess(len(native.canonical(job)),4096)
        seed=native.native_seed({'job':job,'source':data,'job_sha256':native.digest(native.canonical(job))})
        self.assertEqual(seed['source_sha256'],native.digest(data));self.assertEqual(seed['source_bytes'],len(data))

    def test_protected_client_commands_have_fixed_native_slots_and_original_budgets(self):
        for profile in ['shell','elf']:
            spec=native.common.client_command('a'*32,'b'*16,profile,'installed','request',slot='memory')
            command=spec['argv'];self.assertIn('--property=PrivateNetwork=yes',command)
            for prop in ['MemoryMax=256M','MemorySwapMax=0','TasksMax=32','CPUQuota=50%','RuntimeMaxSec=180']:
                self.assertIn('--property='+prop,command)
            self.assertIn('--reuid=1000',command);self.assertIn('--bounding-set=-all',command)
        with self.assertRaises(ValueError):native.common.client_command('a'*32,'b'*16,'shell','source','request',slot='pie')
        with self.assertRaises(ValueError):native.common.client_command('a'*32,'b'*16,'windows','source','prepare')

    def context(self):
        return {'profile':native.SHELL,'backend':{'owned':'inert platform stand-in'},'contract_sha256':native.contract.contract_hash(),
            'runtime_sources_sha256':'1'*64,'maintenance_sha256':'2'*64,'guest_controller_sha256':native.guest_controller_hash()}

    def readiness(self,ctx):
        _,proof=release_fixture();manifest={'head_sha':proof['head_sha']}
        with mock.patch.object(native.common,'snapshot_proof',return_value=(manifest,proof)),mock.patch.object(native.python_backend,'validate_context'):
            return native.new_native_readiness(ctx,b'owned inert matrix bytes')

    def test_readiness_binds_exact_review_head_ci_controller_and_matrix(self):
        ctx=self.context();raw=self.readiness(ctx);value=native.decode(raw)
        self.assertEqual(value['matrix_sha256'],native.digest(b'owned inert matrix bytes'))
        self.assertEqual(value['schema'],'paw-s14-native-i08-v1');self.assertEqual(value['context_sha256'],native.digest(native.canonical(ctx)))
        _,proof=release_fixture();proof['review']['resolved_head_sha']='f'*40
        with mock.patch.object(native.common,'snapshot_proof',return_value=({'head_sha':proof['head_sha']},proof)), \
             mock.patch.object(native.python_backend,'validate_context'),self.assertRaises(ValueError):
            native.new_native_readiness(ctx,b'owned matrix')

    @contextmanager
    def store(self,folder):
        fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
        try:yield fd
        finally:os.close(fd)

    @contextmanager
    def owned_root_directory(self,path):
        # Substitute absolute Root ancestors only; every leaf and all files are
        # real owned temporary inodes. No real /var/lib or /opt access is used.
        path=Path(path);self.assertTrue(path.is_relative_to(self.root))
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:native.fs.trusted(os.fstat(fd),True);yield fd
        finally:os.close(fd)

    def test_current_cache_requires_receipt_not_revoked_expired_or_changed_matrix(self):
        ctx=self.context();ready=self.readiness(ctx);job='a'*32;control=self.root/'control';control.mkdir()
        matrix=control/('native-owned-'+job);matrix.mkdir();validation=b'owned inert matrix bytes';acceptance=b'owned acceptance bytes'
        (matrix/'validation.json').write_bytes(validation);(matrix/'acceptance.json').write_bytes(acceptance)
        store=self.root/'authority';store.mkdir();ready_name='readiness-'+native.digest(ready)+'.json'
        value={'schema':'paw-s14-native-owned-acceptance-v1','result':'PASS','job':job,'profile':ctx['profile'],
            'context_sha256':native.digest(native.canonical(ctx)),'readiness_sha256':native.digest(ready),
            'matrix_sha256':native.digest(validation),'acceptance_sha256':native.digest(acceptance)}
        name='acceptance-shell-'+value['context_sha256']+'-'+value['readiness_sha256']+'.json'
        for leaf,raw in [(name,native.canonical(value)),(ready_name,ready)]:
            (store/leaf).write_bytes(raw);(store/leaf).chmod(0o400)
        with mock.patch.object(native,'store',lambda:self.store(store)),mock.patch.object(native,'CONTROL',control), \
             mock.patch.object(native.fs,'OWNER_UID',os.getuid()),mock.patch.object(native.python_backend,'validate_context'):
            self.assertTrue(native.accepted_native('shell',ctx))
            (store/ready_name).unlink();self.assertFalse(native.accepted_native('shell',ctx))
            (store/ready_name).write_bytes(ready);(store/ready_name).chmod(0o400)
            with mock.patch.object(native.time,'time',return_value=native.decode(ready)['expires_at']+1):self.assertFalse(native.accepted_native('shell',ctx))
            (matrix/'acceptance.json').write_bytes(b'changed')
            with self.assertRaises(ValueError):native.accepted_native('shell',ctx)

    def test_export_parent_creates_only_fixed_private_leaf_and_never_repairs_wrong_existing_mode(self):
        anchor=self.root/'anchor';anchor.mkdir(mode=0o700);export=anchor/'native-exports'
        with mock.patch.object(native.contract,'EXPORT_ROOT',export),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native,'READER_GID',os.getgid()),mock.patch.object(native.fs,'root_directory',self.owned_root_directory):
            with native.native_export_parent() as fd:
                info=os.fstat(fd);self.assertEqual(info.st_uid,os.getuid());self.assertEqual(info.st_gid,os.getgid());self.assertEqual(info.st_mode&0o777,0o750)
            export.chmod(0o700)
            with self.assertRaises(ValueError):
                with native.native_export_parent():pass
            self.assertEqual(export.stat().st_mode&0o777,0o700)

    def test_fault_gate_uses_only_observed_owner_and_start_admission(self):
        from test_native_adapter import fixture
        _,_,admission,_=fixture();witness={};owner=SimpleNamespace(pid=4321,returncode=-9,kill=mock.Mock(),wait=mock.Mock())
        vm={'node':{'uuid':'00000000-0000-0000-0000-000000000001'},'owner':owner,
            'channel':SimpleNamespace(call=lambda op,**kw:copy.deepcopy(admission),close=mock.Mock())}
        gate=object.__new__(native.owned_native_gate('owner-loss',witness))
        with mock.patch.object(native.NativeGate,'start',return_value=vm), \
             mock.patch('benign_guest_validation.process_identity',return_value='12345'):
            started=gate.start('owned-label');started['channel'].call('start')
            with self.assertRaisesRegex(ValueError,native.FAULTS['owner-loss']):started['channel'].call('poll')
        owner.kill.assert_called_once();self.assertEqual(witness['owner_pid'],4321);self.assertEqual(witness['owner_returncode'],-9)
        self.assertEqual(witness['guest_admission'],admission)

    def stage_environment(self):
        control=self.root/'control';control.mkdir(mode=0o700)
        store=self.root/'authority';store.mkdir(mode=0o700)
        return control,store

    def test_one_stage_runs_only_three_jobs_and_never_installs_readiness(self):
        control,store=self.stage_environment();ctx=self.context();record={};rid='c'*32
        raw=native.canonical({'candidate':{'request_id':rid,'source':{'sha256':'1'*64}}})
        report={'result':'PASS'};client={'result':'PASS','terminal':{'writers_stopped':True}}
        with ExitStack() as stack:
            for target,name,value in [(native,'CONTROL',control),(native.fs,'OWNER_UID',os.getuid())]:
                stack.enter_context(mock.patch.object(target,name,value))
            stack.enter_context(mock.patch.object(native.fs,'root_directory',self.owned_root_directory))
            stack.enter_context(mock.patch.object(native,'store',lambda:self.store(store)))
            for target,name in [(native.common,'stage_client'),(native,'install_policy'),(native,'issue'),
                                (native,'native_owned_assert'),(native,'verify_owned_stage'),(native,'publish_reader_tree')]:
                stack.enter_context(mock.patch.object(target,name))
            stack.enter_context(mock.patch.object(native,'stage_client_call',return_value=client))
            stack.enter_context(mock.patch.object(native,'native_owned_request',return_value=(raw,self.root,{})))
            stack.enter_context(mock.patch.object(native,'make_policy',return_value=b'inert-policy'))
            stack.enter_context(mock.patch.object(native,'capture',return_value=ctx))
            stack.enter_context(mock.patch.object(native,'consume',side_effect=FileExistsError))
            stack.enter_context(mock.patch.object(native.common,'case_inventory',return_value={}))
            execute=stack.enter_context(mock.patch.object(native,'execute_native',side_effect=lambda *a,**kw:
                (kw['_witness'].update(live_busy_lock_refused=True) or report,self.root)))
            stack.enter_context(mock.patch.object(native,'verify_native',return_value={'result':'PASS'}))
            readiness=stack.enter_context(mock.patch.object(native,'install_readiness'))
            value,matrix=native.run_validation_stage('a'*32,'b'*40,'shell',ctx,0,record)
            self.assertEqual([row['slot'] for row in value['validations']],['positive','derived','error'])
            self.assertEqual(execute.call_count,3);readiness.assert_not_called()
            self.assertEqual(len(list(store.iterdir())),1)
            self.assertTrue((matrix/'stage.json').is_file());self.assertFalse((matrix/'acceptance.json').exists())

    def test_incomplete_stage_never_creates_a_resume_pointer(self):
        control,store=self.stage_environment();ctx=self.context()
        with mock.patch.object(native,'CONTROL',control),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native.fs,'root_directory',self.owned_root_directory), \
             mock.patch.object(native.common,'stage_client'),mock.patch.object(native,'stage_client_call',side_effect=ValueError('owned failure')), \
             mock.patch.object(native,'install_readiness') as readiness:
            with self.assertRaisesRegex(ValueError,'owned failure'):
                native.run_validation_stage('a'*32,'b'*40,'shell',ctx,0,{})
            self.assertEqual(list(store.iterdir()),[]);readiness.assert_not_called()
            self.assertFalse((control/('native-owned-stage-'+'a'*32)/'stage.json').exists())

    def test_cached_stage_refuses_changed_bytes_or_gap_and_never_issues_authority(self):
        control,store=self.stage_environment();ctx=self.context();job='a'*32
        matrix=control/('native-owned-stage-'+job);matrix.mkdir(mode=0o700)
        stage=native.canonical({'owned':'inert serialized stage stand-in'})
        leaf=matrix/'stage.json';leaf.write_bytes(stage);leaf.chmod(0o400)
        pointer={'schema':'paw-s14-native-owned-stage-pointer-v1','context_sha256':native.digest(native.canonical(ctx)),
            'profile':'shell','index':0,'job':job,'stage_sha256':native.digest(stage)}
        first=store/native.stage_name('shell',ctx,0);first.write_bytes(native.canonical(pointer));first.chmod(0o400)
        with mock.patch.object(native,'CONTROL',control),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native,'store',lambda:self.store(store)),mock.patch.object(native,'verify_owned_stage',side_effect=lambda v,*args:v) as verify, \
             mock.patch.object(native,'issue') as issue,mock.patch.object(native,'install_readiness') as readiness:
            self.assertEqual(native.completed_owned_stages('shell',ctx),[native.decode(stage)])
            verify.assert_called_once();issue.assert_not_called();readiness.assert_not_called()
            leaf.chmod(0o600);leaf.write_bytes(b'changed');leaf.chmod(0o400)
            with self.assertRaisesRegex(ValueError,'native_stage_digest'):native.completed_owned_stages('shell',ctx)
            first.unlink();pointer['index']=1
            second=store/native.stage_name('shell',ctx,1);second.write_bytes(native.canonical(pointer));second.chmod(0o400)
            with self.assertRaisesRegex(ValueError,'native_stage_gap'):native.completed_owned_stages('shell',ctx)

    def test_stage_rereads_serialized_audit_consumption_and_actual_parent_without_new_authority(self):
        # Reuse the serialized audit fixture with explicit fake VM/hardware
        # observations. Real source/proof inventories, grant hashes, opaque
        # artifacts and parent bytes are still independently read from disk.
        from test_native_evidence import NativeEvidence
        evidence=NativeEvidence();evidence.root=self.root
        audit,report,ctx=evidence.fixture();rid=report['runs'][0]['request_id'];nonce='a'*16;job='b'*32
        raw=(audit/'authority-copy'/rid/'request.json').read_bytes();request=native.decode(raw)
        policy=native.decode((audit/'policy.json').read_bytes())
        policy['owned_manifest_sha256']=native.digest(native.canonical({'nonce':nonce,'slot':'positive',
            'profile':ctx['profile'],'request_sha256':native.digest(raw)}));policy_raw=native.canonical(policy)
        grant=native.decode((audit/'authority-copy'/rid/'grant.json').read_bytes());grant['policy_sha256']=native.digest(policy_raw)
        grant_raw=native.canonical(grant);ledger=report['runs'][0]['consumption']
        ledger.update(policy_sha256=native.digest(policy_raw),grant_sha256=native.digest(grant_raw))
        (audit/'policy.json').write_bytes(policy_raw)
        (audit/'authority-copy'/rid/'grant.json').write_bytes(grant_raw)
        (audit/'authority-copy'/rid/'consumed.json').write_bytes(native.canonical(ledger))
        run=report['runs'][0];run.update(policy_sha256=native.digest(policy_raw),grant_sha256=native.digest(grant_raw))
        marker=('OWNED-NATIVE-SHELL-'+nonce+'\n').encode();out=run['outcome']['records'][0]
        out.update(bytes_hex=marker.hex(),sha256=native.digest(marker))
        item=run['quarantine'][0];item.update(bytes=len(marker),sha256=native.digest(marker))
        (audit/(run['job']['job_id']+'-quarantine')/item['stored_as']).write_bytes(marker)
        (audit/'results.json').write_bytes(native.canonical(report))
        control,store=self.stage_environment();target=control/('native-job-'+rid);audit.rename(target);audit=target
        consumed=store/'consumed';consumed.mkdir(mode=0o700);leaf=consumed/(rid+'.json')
        leaf.write_bytes(native.canonical(ledger));leaf.chmod(0o400)
        readers=self.root/'readers';reader=readers/(job+'-client-source');reader.mkdir(parents=True)
        shutil.copytree(audit/'runtime-snapshot',reader/'runtime-snapshot')
        workspace=self.root/'workspace';workspace.mkdir();slot=workspace/'slots/positive';slot.mkdir(parents=True);(slot/'request.json').write_bytes(raw)
        case_id=request['binding']['case_reference']['case_id']
        original=next(q.parent for q in self.root.rglob('manifest.json') if native.decode(q.read_bytes()).get('case_id')==case_id)
        parent=workspace/'cases'/case_id;parent.parent.mkdir();shutil.copytree(original,parent)
        client={'result':'PASS','fixture_job':job,'fixture_nonce':nonce,
            'terminal':{'writers_stopped':True,'cgroup_removed':True,'main_pid':0}}
        with evidence.hardware():verified=native.verify_native(audit)
        row={'slot':'positive','request_id':rid,'audit':str(audit),'verification':verified,
            'witness':{'live_busy_lock_refused':True},'replay_refused':True,'wrong_parent_and_digest_refused':True,
            'parent_unchanged':True,'parent_inventory_sha256':native.digest(native.canonical(native.common.case_inventory(parent)))}
        value={'schema':'paw-s14-native-owned-stage-v1','result':'PASS','profile':'shell','context':ctx,
            'job':job,'release_sha':'2'*40,'stage_index':0,'nonce':nonce,'validations':[row],
            'clients':[client]*3,'real_samples_executed':0}
        with evidence.hardware(),mock.patch.object(native,'CONTROL',control),mock.patch.object(native.common,'READERS',readers), \
             mock.patch.object(native.fs,'OWNER_UID',os.getuid()),mock.patch.object(native,'store',lambda:self.store(store)), \
             mock.patch.object(native,'validation_batches',return_value=(('positive',),)), \
             mock.patch.object(native.common,'client_command',return_value={'workspace':workspace}), \
             mock.patch.object(native,'issue') as issue,mock.patch.object(native,'install_readiness') as ready:
            # Historical consumed grants may be verified, never refreshed or reused.
            with mock.patch.object(native.time,'time',return_value=request['candidate']['expires_at']+3600):
                self.assertEqual(native.verify_owned_stage(value,'shell',ctx,0),value)
            issue.assert_not_called();ready.assert_not_called()
            leaf.chmod(0o600);leaf.write_bytes(b'changed');leaf.chmod(0o400)
            with self.assertRaisesRegex(ValueError,'native_consumption_changed'):native.verify_owned_stage(value,'shell',ctx,0)
            leaf.chmod(0o600);leaf.write_bytes(native.canonical(ledger));leaf.chmod(0o400)
            (parent/'source.bin').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'native_stage_parent_changed'):native.verify_owned_stage(value,'shell',ctx,0)

    def test_boot_metadata_is_finite_and_never_returns_private_log_lines(self):
        serial=(b'[ 219.250] PRIVATE_KERNEL_TEXT\n'
            b"cloud-init[1]: Cloud-init running 'modules:final' at PRIVATE_DATE. Up 213.75 seconds\n"
            b'[FAILED] Failed to start systemd-networkd-wait-online.service - PRIVATE_TEXT\n'
            b'systemd[1]: paw-gate.service: Main process exited, code=exited, status=1/FAILURE PRIVATE_TEXT\n'
            b'Failed to start paw-gate.service: Unit paw-gate.service not found. PRIVATE_TEXT\n'
            b'Failed to start PRIVATE_UNIT.service - PRIVATE_TEXT\n'
            b'Failed to start PRIVATE-paw-gate.service - PRIVATE_TEXT\n'
            b'native_seed_budget arbitrary_secret PRIVATE_TEXT\n'
            b'CONSOLE_PREFIX {"ready":true,"network_interfaces":["lo"]}\n')
        result=native.native_boot_metadata(serial,{'native_seed_budget'})
        self.assertEqual(result['last_kernel_microseconds'],219250000)
        self.assertEqual(result['cloud_init'],[{'stage':'modules:final','event':'running','up_microseconds':213750000}])
        self.assertEqual(result['guest_error_codes'],['native_seed_budget'])
        self.assertIs(result['ready_frame_observed'],True)
        for raw in [b'{"ready":1,"network_interfaces":["lo"]}',b'{"ready":true,"network_interfaces":["lo","eth0"]}',b'not json']:
            self.assertIs(native.native_boot_metadata(raw,set())['ready_frame_observed'],False)
        self.assertIn({'unit':'paw-gate.service','event':'exited','exit_status':1},result['services'])
        self.assertIn({'unit':'paw-gate.service','event':'missing'},result['services'])
        self.assertNotIn('PRIVATE_',json.dumps(result));self.assertNotIn('arbitrary_secret',json.dumps(result))
        self.assertEqual(len(result['services']),3)
        with self.assertRaises(ValueError):native.native_boot_metadata(b'x'*(1024**2+1),set())
        oversized=b'PRIVATE_TEXT '*1000+b'paw-gate.service failed to start'
        self.assertEqual(native.native_boot_metadata(oversized,set())['services'],[])

    def test_boot_metadata_caps_events_and_ignores_foreign_times(self):
        serial=(b'[99999] unknown\n'+b'systemd[1]: paw-gate.service: Main process exited, status=255/FAILURE\n'*100+
            b"cloud-init running 'modules:final' at PRIVATE_DATE. Up 1.5 seconds\n"*100)
        result=native.native_boot_metadata(serial,set());self.assertIsNone(result['last_kernel_microseconds'])
        self.assertEqual(len(result['services']),32);self.assertEqual(len(result['cloud_init']),16)
        with self.assertRaises(ValueError):native.native_boot_metadata(b'\n'*16385,set())

    def test_boot_metadata_roundtrips_existing_strict_root_result_decoder(self):
        import vm_release_contract as contract
        import vm_operator_host as host
        data=(b'[ 212.593704] owned kernel\n'+
              b"cloud-init running 'modules:final' at DATE. Up 205.06 seconds\n"+
              b'cloud-init finished at DATE. Up 212.58 seconds\n')
        metadata=native.native_boot_metadata(data,set())
        self.assertEqual(metadata['last_kernel_microseconds'],212593704)
        self.assertEqual(metadata['cloud_init'][-1]['up_microseconds'],212580000)
        result={'result':'PASS','runtime':{'previous_owned_native_failure':{'boot_metadata':metadata}}}
        raw=native.storage.canonical(result);self.assertEqual(contract.decode(raw),result)
        # Exercise the same private result consumer with only inode Root identity
        # substituted, not its decoder, canonical/scalar/depth or budget checks.
        path=self.root/'result.json';path.write_bytes(raw);path.chmod(0o600)
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            with mock.patch.object(host,'ROOT_UID',os.getuid()):self.assertEqual(host.private_json(fd,'result.json'),result)
        finally:os.close(fd)
        with self.assertRaisesRegex(ValueError,'operator_proof_scalar'):
            contract.decode(native.storage.canonical({'result':'PASS','runtime':{'up_seconds':212.58}}))

    def test_native_failure_metadata_never_publishes_private_text_or_foreign_locations(self):
        report={'result':'FAIL','scope':native.SCOPE,'real_connections':0,
            'error':'guest_channel_deadline:PRIVATE_GUEST_TEXT:/private/path',
            'verification_error':'unknown_private_value','writers_stopped':True,'host_restored':True,
            'traceback':'  File "/private/root/native_runtime.py", line 50\n  File "/private/foreign.py", line 1\nValueError: PRIVATE_GUEST_TEXT',
            'diagnostic':{'locations':[{'module':'native_guest.py','line':70}]}}
        value=native.native_failure_metadata(report,{'native_runtime.py','native_guest.py'},{'guest_channel_deadline'})
        raw=json.dumps(value);self.assertNotIn('PRIVATE_GUEST_TEXT',raw);self.assertNotIn('/private',raw)
        self.assertNotIn('unknown_private_value',raw);self.assertNotIn('foreign.py',raw)
        self.assertEqual(value['diagnostics']['error']['error_code'],'guest_channel_deadline')
        self.assertEqual(value['diagnostics']['verification_error']['error_code'],'non_code_failure')
        for changed in [dict(report,scope='foreign'),dict(report,real_connections=False),dict(report,error='x'*65537)]:
            with self.assertRaises(ValueError):native.native_failure_metadata(changed,set(),set())

    def test_fixed_historical_native_reader_checks_full_snapshot_owned_bytes_and_revocation(self):
        from test_native_evidence import NativeEvidence
        evidence=NativeEvidence();evidence.root=self.root;audit,report,ctx=evidence.fixture('elf')
        control=self.root/'control';control.mkdir();fixed=control/('native-job-'+native.HISTORICAL_NATIVE_REQUEST);audit.rename(fixed)
        entry=next(r for r in native_fixtures('a'*16,'elf') if r['slot']=='smoke')
        home=self.root/'full-size';home.mkdir();case,graph=forensic_case(home,entry['selected'])
        info=native.contract.prepare(case,graph.root,'elf',home/'request');request=native.decode(Path(info['request']).read_bytes(),native.contract.REQUEST_LIMIT)
        request['candidate']['request_id']=native.HISTORICAL_NATIVE_REQUEST;raw=native.canonical(request)
        old_copy=next((fixed/'authority-copy').iterdir());copy=fixed/'authority-copy'/native.HISTORICAL_NATIVE_REQUEST
        if old_copy!=copy:old_copy.rename(copy)
        (copy/'request.json').write_bytes(raw)
        ready=b'owned revoked readiness stand-in';(fixed/'readiness.json').write_bytes(ready)
        policy=native.decode((fixed/'policy.json').read_bytes());policy.update(mode='explicit-source-analysis',readiness_sha256=native.digest(ready),approved_requests=[
            {'request_sha256':native.digest(raw),'source_sha256':request['candidate']['source']['sha256']}])
        policy_raw=native.canonical(policy);(fixed/'policy.json').write_bytes(policy_raw)
        report.update(result='FAIL',error='guest_channel_deadline:PRIVATE_GUEST_TEXT',traceback='')
        (fixed/'results.json').write_bytes(native.canonical(report))
        (fixed/('native-elf-'+native.HISTORICAL_NATIVE_REQUEST+'-serial.log')).write_bytes(b'Linux version owned\ncloud-init\nPRIVATE_GUEST_TEXT')
        header=(fixed/'runtime-snapshot/release.json').read_bytes()
        state=self.root/'state';folder=state/'jobs'/native.HISTORICAL_NATIVE_JOB;folder.mkdir(parents=True)
        outer={'result':'FAIL','job':native.HISTORICAL_NATIVE_JOB,'recipe':'elf-owned-v1','release_sha':'2'*40,
            'error':'native_owned_smoke_failed','new_readiness_revoked':True,'real_samples_executed':0,'real_source_grants_issued':0}
        (folder/'result.json').write_bytes(native.canonical(outer))
        matrix=control/('native-owned-'+native.HISTORICAL_NATIVE_JOB);matrix.mkdir()
        (matrix/'validation.json').write_bytes(native.canonical({'result':'PASS','profile':native.ELF,'context':ctx,'nonce':'a'*16}))
        authority=self.root/'authority';authority.mkdir(mode=0o700)
        # Only Root/hardware authority is substituted. Snapshot proof/inventory,
        # exact1MiB request/lineage and all fixed file reads are real temporary data.
        with mock.patch.object(native,'root_only'),mock.patch.object(native,'STATE',state),mock.patch.object(native,'CONTROL',control), \
             mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native,'HISTORICAL_NATIVE_RELEASE','2'*40),mock.patch.object(native,'HISTORICAL_NATIVE_MANIFEST',native.digest(header)), \
             mock.patch.object(native,'store',lambda:self.store(authority)), \
             mock.patch.object(native,'issue') as issue,mock.patch.object(native,'install_readiness') as install:
            value=native.previous_owned_native_failure();self.assertIs(value['readiness_revoked'],True)
            self.assertIs(value['vm_started'],False);self.assertEqual(value['real_source_grants_issued'],0)
            self.assertEqual(value['diagnostics']['error']['error_code'],'guest_channel_deadline')
            self.assertNotIn('PRIVATE_GUEST_TEXT',json.dumps(value));issue.assert_not_called();install.assert_not_called()
            leaf=authority/('readiness-'+native.digest(ready)+'.json');leaf.write_bytes(ready);leaf.chmod(0o400)
            with self.assertRaisesRegex(ValueError,'native_historical_readiness_not_revoked'):native.previous_owned_native_failure()
            leaf.unlink();(fixed/'runtime-snapshot/paw/owned.py').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'representation_snapshot_source_changed'):native.previous_owned_native_failure()

    def test_historical_native_reader_refuses_foreign_job_before_reading_backend(self):
        with mock.patch.object(native,'root_only'),mock.patch.object(native,'read',return_value=native.canonical({'result':'FAIL','job':'f'*32})) as read, \
             self.assertRaisesRegex(ValueError,'native_historical_owned_job'):
            native.previous_owned_native_failure()
        self.assertEqual(read.call_count,1)

    def test_final_smoke_backend_failure_preserves_public_diagnostics_and_revokes_readiness(self):
        control,store=self.stage_environment();ctx=self.context();job='a'*32;record={}
        stage={'job':'b'*32,'stage_index':0,'nonce':'c'*16,'clients':[],
            'validations':[{'slot':slot} for slot in NATIVE_CASES['shell']]}
        ready=b'owned readiness stand-in';leaf=store/('readiness-'+native.digest(ready)+'.json');leaf.write_bytes(ready);leaf.chmod(0o400)
        diagnostic={'error_type':'TimeoutError','error_code':'guest_channel_deadline','locations':[]}
        with mock.patch.object(native,'CONTROL',control),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native.fs,'root_directory',self.owned_root_directory),mock.patch.object(native,'store',lambda:self.store(store)), \
             mock.patch.object(native.common,'stage_client'),mock.patch.object(native,'stage_client_call',return_value={}), \
             mock.patch.object(native,'capture',return_value=ctx),mock.patch.object(native,'new_native_readiness',return_value=ready), \
             mock.patch.object(native,'install_readiness'),mock.patch.object(native.common,'run_client'), \
             mock.patch.object(native,'native_owned_request',return_value=(b'owned',self.root,{})), \
             mock.patch.object(native,'make_policy',return_value=b'owned'),mock.patch.object(native,'install_policy'),mock.patch.object(native,'issue'), \
             mock.patch.object(native,'execute_native',return_value=({'result':'FAIL','diagnostic':diagnostic},self.root)):
            with self.assertRaisesRegex(ValueError,'native_owned_smoke_failed'):
                native.finish_owned_native(job,'d'*40,'shell',ctx,[stage],record)
            self.assertEqual(record['backend_diagnostics'],{'diagnostic':diagnostic})
            self.assertIs(record['new_readiness_revoked'],True);self.assertFalse(leaf.exists())

    def test_final_smoke_failure_revokes_new_readiness_and_keeps_stage_evidence(self):
        control,store=self.stage_environment();ctx=self.context();job='a'*32;record={}
        stage={'job':'b'*32,'stage_index':0,'nonce':'c'*16,'clients':[],
            'validations':[{'slot':slot} for slot in NATIVE_CASES['shell']]}
        ready=b'owned readiness stand-in';name='readiness-'+native.digest(ready)+'.json'
        leaf=store/name;leaf.write_bytes(ready);leaf.chmod(0o400)
        with mock.patch.object(native,'CONTROL',control),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native.fs,'root_directory',self.owned_root_directory), \
             mock.patch.object(native,'store',lambda:self.store(store)),mock.patch.object(native.common,'stage_client'), \
             mock.patch.object(native,'stage_client_call',return_value={'owned':'inert nonroot client stand-in'}), \
             mock.patch.object(native,'capture',return_value=ctx),mock.patch.object(native,'new_native_readiness',return_value=ready), \
             mock.patch.object(native,'install_readiness') as install,mock.patch.object(native.common,'run_client'), \
             mock.patch.object(native,'native_owned_request',side_effect=ValueError('owned final smoke failure')):
            with self.assertRaisesRegex(ValueError,'owned final smoke failure'):
                native.finish_owned_native(job,'d'*40,'shell',ctx,[stage],record)
            install.assert_called_once();self.assertIs(record['new_readiness_revoked'],True)
            self.assertFalse(leaf.exists());self.assertEqual(list(store.iterdir()),[])
            self.assertTrue((control/('native-owned-'+job)/'validation.json').exists())
            self.assertFalse((control/('native-owned-'+job)/'acceptance.json').exists())

    def test_pending_stage_cannot_be_treated_as_final_profile_acceptance(self):
        job='a'*32;release='b'*40;state=self.root/'state';folder=state/'jobs'/job;folder.mkdir(parents=True,mode=0o700)
        for path in [state,state/'jobs']:path.chmod(0o700)
        ctx=self.context();record={}
        with mock.patch.object(native,'root_only'),mock.patch.object(native,'HERE',Path('/opt/paw-vm/releases')/release/'lab/s14'), \
             mock.patch.object(native,'STATE',state),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native.fs,'root_directory',self.owned_root_directory),mock.patch.object(native.common,'snapshot_proof'), \
             mock.patch('vm_runtime_revalidation.revalidate',return_value={}),mock.patch.object(native,'initialize'), \
             mock.patch.object(native,'capture',return_value=ctx),mock.patch.object(native,'accepted_native',return_value=False), \
             mock.patch.object(native,'completed_owned_stages',return_value=[{'owned':'earlier fully verified stage'}]), \
             mock.patch.object(native,'run_validation_stage',return_value=({'validations':[1,2,3]},self.root)) as stage, \
             mock.patch.object(native,'finish_owned_native') as finish, \
             mock.patch('vm_operator_host.write_state',side_effect=lambda fd,name,value:record.update(value)):
            native.run_owned_native(job,release,'shell')
            self.assertEqual(stage.call_args.args[4],1);finish.assert_not_called()
        self.assertIs(record['stage_only'],True);self.assertIs(record['i08_installed'],False)
        self.assertEqual(record['stages_complete'],2);self.assertEqual(record['stages_required'],4)
        self.assertNotIn('readiness_sha256',record)

    def test_cached_owned_recipe_runs_no_vm_and_records_existing_fixed_recipe(self):
        job='a'*32;release='b'*40;state=self.root/'state';folder=state/'jobs'/job;folder.mkdir(parents=True,mode=0o700)
        for path in [state,state/'jobs']:path.chmod(0o700)
        record={};ctx=self.context()
        with mock.patch.object(native,'root_only'),mock.patch.object(native,'HERE',Path('/opt/paw-vm/releases')/release/'lab/s14'), \
             mock.patch.object(native,'STATE',state),mock.patch.object(native.fs,'OWNER_UID',os.getuid()), \
             mock.patch.object(native.fs,'root_directory',self.owned_root_directory), \
             mock.patch.object(native.common,'snapshot_proof'),mock.patch('vm_runtime_revalidation.revalidate',return_value={'owned':True}), \
             mock.patch.object(native,'initialize'),mock.patch.object(native,'capture',return_value=ctx), \
             mock.patch.object(native,'accepted_native',return_value=True),mock.patch.object(native,'execute_native') as execute, \
             mock.patch('vm_operator_host.write_state',side_effect=lambda fd,name,value:record.update(value)):
            native.run_owned_native(job,release,'shell');execute.assert_not_called()
        self.assertEqual(record['result'],'PASS');self.assertIs(record['vm_started'],False);self.assertEqual(record['cases'],0)
        self.assertEqual(record['recipe'],'shell-owned-v1');self.assertEqual(record['real_samples_executed'],0)


if __name__=='__main__':unittest.main()
