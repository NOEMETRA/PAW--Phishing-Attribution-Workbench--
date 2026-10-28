"""Finite native producer/recipe tests; no privileged service, VM or payload run."""
import copy
from contextlib import contextmanager
import json
import os
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
