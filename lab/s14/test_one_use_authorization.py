"""Inert actual filesystem/CLI-independent authority and shared lifecycle tests."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import one_use_authorization as auth
import granted_offline_adapter as adapter
from offline_candidate import canonical
from owned_grant_fixtures import SOURCES, CPU_DISABLED


def context():
    names = ['one_use_authorization.py', 'granted_offline_adapter.py', 'i08_context.py', 'owned_grant_fixtures.py'] + ['owned-%d.py' % i for i in range(60)]
    return dict(kernel='owned-kernel', packages={p: 'owned-version' for p in ['qemu-system-x86', 'libvirt-daemon-system', 'intel-microcode']},
                image_sha256=auth.IMAGE_SHA256, guard_fingerprint='a'*64, source_hashes={p:'b'*64 for p in names},
                smt_active='0', apparmor_enabled='Y', slice={'memory.max':'2147483648', 'memory.swap.max':'0', 'pids.max':'128'},
                mitigations={p:'Not affected' for p in ['gather_data_sampling','l1tf','mds','spectre_v1','spectre_v2','meltdown']}, mitigation_cmdline=[])


def frame(identifier='c'*32, source=SOURCES['positive']):
    now=int(time.time())
    return canonical(dict(schema='paw-s14-offline-candidate-v1', profile='linux-python-offline-v1', request_id=identifier,
        case_reference_sha256='d'*64, source={'media_type':'text/x-python','encoding':'utf-8','bytes':len(source),
        'sha256':hashlib.sha256(source).hexdigest(),'data_hex':source.hex()}, provenance={'kind':'operator-supplied','reference':'owned inert fixture'},
        created_at=now, expires_at=now+900, purpose='offline-single-job-review'))


@contextlib.contextmanager
def authority():
    # Actual descriptor-relative filesystem tests under the test user's UID.
    # Only this test context replaces the root entry and owner identity; no
    # production option permits selecting a different trust root or owner.
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory)
        @contextlib.contextmanager
        def opened():
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:auth.trusted(os.fstat(fd),True);yield fd
            finally:os.close(fd)
        with patch.object(auth,'root_directory',opened), patch.object(auth,'OWNER_UID',os.getuid()), patch.object(auth.os,'geteuid',return_value=0):
            ctx=context();policy=canonical(auth.make_policy(ctx))
            with opened() as fd:auth.exclusive(fd,auth.policy_name(policy),policy)
            yield root,ctx,policy


class FakeGate(adapter.GrantedGate):
    def __init__(self, output, fault=None):self.output=output;self.active_vm=None;self.fault=fault;self.starts=0;self.stops=0
    def start(self,label):
        self.starts+=1
        vm={'node':{'uuid':'owned-vm'},'channel':self};self.active_vm=vm
        if self.fault=='startup':raise TimeoutError('owned startup failure')
        return vm
    def call(self,op,**kwargs):
        if op=='start':return {'source_sha256':self.current['job']['source_sha256'],'job_sha256':self.current['job_sha256'],'prior_marker_absent':True}
        if self.fault=='owner-loss':raise ValueError('owned channel loss')
        data=b'owned opaque output';name='../escape' if self.fault=='malformed-output' else 'stdout.bin'
        return dict(done=True,status='completed',records=[dict(name=name,bytes_hex=data.hex(),sha256=hashlib.sha256(data).hexdigest(),scope='opaque')])
    def stop(self,vm):
        self.stops+=1;vm.update(stopped=None if self.fault=='unknown-stop' else True,stop_seconds=.1);self.active_vm=None


class OneUse(unittest.TestCase):
    def test_expired_missing_or_writable_grant_refuses_before_vm_or_consumption(self):
        for mutation in ['expired','missing','writable']:
            with self.subTest(mutation=mutation),authority() as (root,ctx,policy),patch.object(adapter,'capture',return_value=ctx):
                raw=frame();auth.issue(raw,policy,ctx);path=root/'grants'/('c'*32+'.json')
                if mutation=='missing':path.unlink()
                elif mutation=='writable':path.chmod(0o666)
                else:
                    grant=json.loads(path.read_text());grant['expires_at']=int(time.time())-1;path.chmod(0o600);path.write_bytes(canonical(grant));path.chmod(0o400)
                gate=FakeGate(root/'out');gate.output.mkdir()
                with self.assertRaises((ValueError,OSError)):adapter.run_granted(gate,raw,policy)
                self.assertEqual(gate.starts,0);self.assertFalse((root/'consumed').exists())

    def test_global_replay_is_refused_across_different_output_directories(self):
        with authority() as (root,ctx,policy), patch.object(adapter,'capture',return_value=ctx):
            raw=frame();auth.issue(raw,policy,ctx)
            first=FakeGate(root/'out-a');first.output.mkdir()
            result=adapter.run_granted(first,raw,policy)
            self.assertTrue(result['writers_stopped']);self.assertEqual(first.starts,1);self.assertEqual(first.stops,1)
            second=FakeGate(root/'out-b');second.output.mkdir()
            with self.assertRaises(FileExistsError):adapter.run_granted(second,raw,policy)
            self.assertEqual(second.starts,0);self.assertFalse((second.output/'admissions').exists())
            self.assertTrue((root/'consumed'/('c'*32+'.json')).exists())

    def test_simultaneous_consumption_has_exactly_one_winner(self):
        with authority() as (root,ctx,policy):
            raw=frame();auth.issue(raw,policy,ctx);barrier=threading.Barrier(2);wins=[];errors=[]
            def claim():
                barrier.wait()
                try:wins.append(auth.consume(raw,policy,ctx))
                except Exception as error:errors.append(type(error))
            threads=[threading.Thread(target=claim) for _ in range(2)]
            for thread in threads:thread.start()
            for thread in threads:thread.join(5);self.assertFalse(thread.is_alive())
            self.assertEqual(len(wins),1);self.assertEqual(errors,[FileExistsError])

    def test_startup_owner_loss_malformed_output_and_unknown_stop_never_publish(self):
        for fault in ['startup','owner-loss','malformed-output','unknown-stop']:
            with self.subTest(fault=fault), authority() as (root,ctx,policy), patch.object(adapter,'capture',return_value=ctx):
                raw=frame();auth.issue(raw,policy,ctx);gate=FakeGate(root/'out',fault);gate.output.mkdir()
                with self.assertRaises((TimeoutError,ValueError)):adapter.run_granted(gate,raw,policy)
                self.assertEqual(gate.stops,1);self.assertIsNone(gate.active_vm)
                self.assertFalse(any(gate.output.glob('*-quarantine')))
                with self.assertRaises(FileExistsError):auth.consume(raw,policy,ctx)

    def test_policy_change_after_boot_stops_and_burns_authorization(self):
        with authority() as (root,ctx,policy):
            raw=frame();auth.issue(raw,policy,ctx);other=copy.deepcopy(ctx);other['kernel']='changed'
            gate=FakeGate(root/'out');gate.output.mkdir()
            with patch.object(adapter,'capture',side_effect=[ctx,other]),self.assertRaisesRegex(ValueError,'effective_context_changed'):
                adapter.run_granted(gate,raw,policy)
            self.assertEqual(gate.starts,1);self.assertEqual(gate.stops,1)
            with self.assertRaises(FileExistsError):auth.consume(raw,policy,ctx)

    def test_binding_expiry_scope_unknown_source_and_policy_changes_refuse(self):
        with authority() as (root,ctx,policy):
            raw=frame();grant=auth.issue(raw,policy,ctx);now=json.loads(raw)['created_at']
            for key,value in [('request_id','e'*32),('frame_sha256','0'*64),('source_sha256','0'*64),
                              ('case_reference_sha256','0'*64),('candidate_sha256','0'*64),('policy_sha256','0'*64),
                              ('scope','all-samples'),('expires_at',now),('created_at',True)]:
                changed=copy.deepcopy(grant);changed[key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):auth.validate_binding(raw,changed,policy,ctx,now=now)
            with self.assertRaises(ValueError):auth.validate_binding(raw,grant,policy,ctx,now=now+900)
            with self.assertRaisesRegex(ValueError,'owned_synthetic_sources_only'):auth.issue(frame('e'*32,b"print('not reviewed')\n"),policy,ctx)
            with self.assertRaisesRegex(ValueError,'grant_binding:frame_sha256'):auth.validate_binding(json.dumps(json.loads(raw),indent=2).encode(),grant,policy,ctx)

    def test_root_storage_refuses_writable_symlink_fifo_and_oversize_files(self):
        with authority() as (root,ctx,policy):
            path=root/'record';path.write_bytes(b'owned');path.chmod(0o666)
            with auth.root_directory() as fd:
                with self.assertRaisesRegex(ValueError,'untrusted'):auth.read(fd,'record')
                path.unlink();path.symlink_to('/etc/passwd')
                with self.assertRaises(OSError):auth.read(fd,'record')
                path.unlink();os.mkfifo(path,0o600)
                with self.assertRaisesRegex(ValueError,'untrusted'):auth.read(fd,'record')
                path.unlink();path.write_bytes(b'x'*10);path.chmod(0o400)
                with self.assertRaisesRegex(ValueError,'budget'):auth.read(fd,'record',limit=2)

    def test_execution_lock_and_busy_gate_refuse_before_consumption(self):
        with authority() as (root,ctx,policy),patch.object(adapter,'capture',return_value=ctx):
            raw=frame();auth.issue(raw,policy,ctx);gate=FakeGate(root/'out');gate.output.mkdir()
            with auth.execution_lock(),self.assertRaises(BlockingIOError):adapter.run_granted(gate,raw,policy)
            gate.active_vm={'owned':'prior'}
            with self.assertRaisesRegex(ValueError,'gate_busy'):adapter.run_granted(gate,raw,policy)
            self.assertFalse((root/'consumed').exists())

    def test_context_mitigation_image_budget_and_cpu_policy_fail_closed(self):
        ctx=context();policy=auth.make_policy(ctx)
        for key,value in [('smt_active','1'),('apparmor_enabled','N'),('image_sha256','0'*64),('guard_fingerprint',None),
                          ('source_hashes',{}),('mitigations',{}),('slice',{}),('mitigation_cmdline',['mitigations=off'])]:
            changed=copy.deepcopy(ctx);changed[key]=value;p=copy.deepcopy(policy);p['context']=changed
            with self.subTest(key=key),self.assertRaises(ValueError):auth.validate_policy(p,changed)
        gate=adapter.GrantedGate.__new__(adapter.GrantedGate);xml=ET.fromstring('<domain><cpu/></domain>')
        with self.assertRaisesRegex(ValueError,'cpu_features'):gate.validate_runtime(xml)
        for name in CPU_DISABLED:ET.SubElement(xml.find('cpu'),'feature',{'policy':'disable','name':name})
        gate.validate_runtime(xml)


if __name__=='__main__':unittest.main()
