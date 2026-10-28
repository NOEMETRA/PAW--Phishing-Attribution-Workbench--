"""Finite native adapter ABI/media boundaries; no Root, QEMU or source execution."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lab/s14'))
import native_runtime as native
from test_representation_bridge import forensic_case


def fixture():
    source=b'printf owned\n';job={'profile':native.SHELL,'job_id':'native-shell-'+'a'*32,
        'parent_sha256':'1'*64,'source_sha256':native.digest(source),'source_bytes':len(source),
        'operator_authorization':'root-native-grant-v1','created_at':1,'expires_at':901}
    seed=native.native_seed({'job':job,'source':source,'job_sha256':native.digest(native.canonical(job))})
    inspection={**seed,'kernel_release':'6.8.0-147-generic','network_interfaces':['lo'],'prior_marker_absent':True,
        'guest_controller_sha256':native.guest_controller_hash(),'interpreter':'/bin/dash','interpreter_sha256':'2'*64}
    boundary={'uid':65534,'gid':65534,'groups':[],'no_new_privileges':True,'capabilities':'all zero including bounding',
        'pid':123,'pid_identity':'99','stdin':'/dev/null','cgroup':'/paw-synthetic-job','limits':native.GUEST_LIMITS,
        'rlimits':native.CHILD_LIMITS,'session_id':123,'controlling_tty':None,'working_directory':'/tmp/paw-gate-fixture','observed_before_exec':True}
    admission={'started':True,'pid':123,'source_sha256':seed['source_sha256'],'job_sha256':seed['job_sha256'],
        'profile':native.SHELL,'prior_marker_absent':True,'boundary':boundary,'inspection':inspection}
    outcome={'done':True,'status':'completed','returncode':0,'records':[{'name':name+'.bin','bytes_hex':'',
        'sha256':hashlib.sha256(b'').hexdigest(),'scope':'opaque untrusted native output'} for name in ['stdout','stderr']],
        'events':{'memory.events':'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0',
        'memory.peak':'1000','pids.events':'max 0','pids.peak':'1','pids.current':'0'},
        'boundary':boundary,'writers_stopped':True,'file_observation':None}
    return seed,inspection,admission,outcome


class NativeAdapter(unittest.TestCase):
    def setUp(self):self.seed,self.inspection,self.admission,self.outcome=fixture()

    def test_positive_exact_inspection_admission_and_outcome(self):
        native.validate_inspection(self.inspection,self.seed);native.validate_native_admission(self.admission,self.inspection)
        native.validate_native_outcome(self.outcome,self.admission)

    def test_inspection_binds_source_profile_controller_reset_nic_and_interpreter(self):
        for key,value in [('source_sha256','0'*64),('profile','linux-python-offline-v1'),('guest_controller_sha256','0'*64),
                ('prior_marker_absent',False),('network_interfaces',['lo','eth0']),('interpreter','/bin/bash'),('source_bytes',True)]:
            changed=copy.deepcopy(self.inspection);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):native.validate_inspection(changed,self.seed)

    def test_nonroot_caps_nnp_session_and_every_effective_limit_bound(self):
        for key,value in [('uid',0),('gid',0),('groups',[27]),('capabilities','nonzero'),('no_new_privileges',False),
                ('observed_before_exec',False),('session_id',1),('controlling_tty','ttyS0'),('pid',True),('stdin','/dev/ttyS0'),('working_directory','/')]:
            changed=copy.deepcopy(self.admission['boundary']);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):native.validate_boundary(changed)
        for key in native.GUEST_LIMITS:
            changed=copy.deepcopy(self.admission['boundary']);changed['limits'][key]='unlimited'
            with self.subTest(limit=key),self.assertRaises(ValueError):native.validate_boundary(changed)
        changed=copy.deepcopy(self.admission['boundary']);changed['rlimits']['Max core file size']=False
        with self.assertRaises(ValueError):native.validate_boundary(changed)

    def test_wrong_admission_identity_or_post_exec_proof_refuses(self):
        for key,value in [('pid',124),('source_sha256','0'*64),('started',False),('prior_marker_absent',False)]:
            changed=copy.deepcopy(self.admission);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):native.validate_native_admission(changed,self.inspection)

    def test_changed_returncode_boundary_unknown_stop_or_output_stream_refuses(self):
        for key,value in [('returncode',True),('returncode',256),('writers_stopped',False),('done',False),('status','safe')]:
            changed=copy.deepcopy(self.outcome);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):native.validate_native_outcome(changed,self.admission)
        changed=copy.deepcopy(self.outcome);changed['records'][0]['name']='../escape'
        with self.assertRaises(ValueError):native.validate_native_outcome(changed,self.admission)

    def test_oom_status_requires_actual_kernel_event_and_exact_writers_zero(self):
        changed=copy.deepcopy(self.outcome);changed['status']='memory_budget'
        with self.assertRaises(ValueError):native.validate_native_outcome(changed,self.admission)
        changed['events']['memory.events']='oom 1\noom_kill 1';changed['returncode']=-9
        native.validate_native_outcome(changed,self.admission)
        for key,value in [('pids.current','1'),('pids.peak','17'),('pids.events','max 0\nmax 1')]:
            bad=copy.deepcopy(changed);bad['events'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):native.validate_native_outcome(bad,self.admission)

    def test_oversized_regular_file_is_not_a_supported_file_budget_outcome(self):
        changed=copy.deepcopy(self.outcome);changed['file_observation']={'regular':True,'bytes':4097}
        with self.assertRaises(ValueError):native.validate_native_outcome(changed,self.admission)

    def channel(self,outcome=None):
        def call(operation,**kw):return copy.deepcopy({'inspect':self.inspection,'start':self.admission,'poll':outcome if outcome is not None else self.outcome}[operation])
        return native.NativeChannel(SimpleNamespace(call=call,close=lambda:None),self.seed)

    def test_channel_enforces_start_once_and_admission_before_poll(self):
        channel=self.channel()
        with self.assertRaises(ValueError):channel.call('poll')
        channel.call('start');channel.call('poll')
        with self.assertRaises(ValueError):channel.call('start')
        with self.assertRaises(ValueError):channel.call('shell')

    def test_pending_frame_boolean_is_strict_instead_of_integer_coercion(self):
        channel=self.channel({'done':0});channel.call('start')
        with self.assertRaises(ValueError):channel.call('poll')

    def test_channel_close_is_idempotent_for_protocol_fault_then_vm_stop(self):
        channel=self.channel();calls=[]
        def close():
            calls.append(True)
            if len(calls)>1:raise OSError('owned already closed serial descriptor')
        channel.channel.close=close;channel.close();channel.close()
        self.assertEqual(len(calls),1)

    def test_native_seed_preserves_exact_bytes_and_fixed_controller_without_host_execution(self):
        source=b'#!/no/selector\nprintf owned\n'
        current={'job':{'profile':native.SHELL,'job_id':'native-shell-'+'a'*32,'parent_sha256':'1'*64,
            'source_sha256':native.digest(source),'source_bytes':len(source),'operator_authorization':'root-native-grant-v1',
            'created_at':1,'expires_at':901},'source':source,'job_sha256':'3'*64}
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);gate=object.__new__(native.NativeGate);gate.current=current;gate.canary=folder/'canary'
            calls=[]
            def inert_run(argv):
                calls.append(argv)
                target=folder/'seed.iso'
                if target.exists(): target.chmod(0o600)  # Simulate Root's overwrite in this owned fixture only.
                target.write_bytes(b'owned inert media stand-in, never mounted')
            gate.run=inert_run
            gate.seed(folder,'extractor','native-shell-'+'a'*32,'b'*32)
            cloud=json.loads((folder/'user-data').read_text().split('\n',1)[1]);files={v['path']:v for v in cloud['write_files']}
            self.assertEqual(base64.b64decode(files['/opt/paw-input/sample.bin']['content']),source)
            self.assertEqual(files['/opt/paw-input/sample.bin']['permissions'],'0444')
            service=base64.b64decode(files['/etc/systemd/system/paw-gate.service']['content'])
            self.assertIn(b'python3 -I -B -u /usr/local/lib/paw-s14/native_guest.py',service)
            self.assertEqual(json.loads(base64.b64decode(files['/etc/paw-native.json']['content'])),native.native_seed(current))
            self.assertEqual(len(calls),2);self.assertTrue(all(argv[0]=='/usr/bin/genisoimage' for argv in calls))


if __name__=='__main__':unittest.main()
