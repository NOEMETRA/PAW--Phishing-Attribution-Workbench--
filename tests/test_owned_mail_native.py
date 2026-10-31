"""Native/enrolled routing with explicit fake protected state, no Root or VM."""
from contextlib import nullcontext,redirect_stdout
import importlib.util,io,os,subprocess,sys,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from paw.core import owned_mail_channel as c,browser_owned_broker as broker

saved=list(sys.path)
try:
    lab=Path(__file__).resolve().parents[1]/'lab/s14';sys.path.insert(0,str(lab))
    import vm_release_contract as contract
    import vm_operator_install as install
    spec=importlib.util.spec_from_file_location('owned_worker',lab/'vm_operator_worker.py')
    worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
finally:sys.path[:]=saved
J='a'*32;R='b'*40

class Native(unittest.TestCase):
    def host(self,complete=False):
        grant={'schema':'paw-vm-native-test-v1','release_sha':R,'recipe':'browser-owned-v1','token_sha256':'c'*64,
            'owner_pid':1234,'owner_start':'123456','created_at':1,'expires_at':61}
        values={'policy.json':{'anchor_sha':R},'active.json':{'release_sha':R},'enrollment-test.json':grant}
        host=types.SimpleNamespace(private_json=Mock(side_effect=lambda fd,name:values[name]),
            contract=types.SimpleNamespace(policy=Mock(),shape=contract.shape,positive=contract.positive),
            revoked=Mock(return_value=False),enrollment_complete=Mock(return_value=complete),
            enrollment_test_consumed=Mock(return_value=True),active=lambda v:v,native_test_live=Mock())
        return host,values
    def test_completed_enrollment_always_requires_mail_data(self):
        host,_=self.host(complete=True)
        with patch.object(c,'_root',return_value=lambda _:nullcontext(123)),patch.dict(sys.modules,{'vm_operator_host':host}):
            self.assertIs(c.admission_required(J,R),True)
        host.contract.policy.assert_called_once();host.enrollment_test_consumed.assert_not_called();host.native_test_live.assert_not_called()
    def test_only_consumed_live_native_grant_at_exact_current_anchor_can_omit_mail_input(self):
        host,_=self.host()
        with patch.object(c,'_root',return_value=lambda _:nullcontext(123)),patch.dict(sys.modules,{'vm_operator_host':host}):
            self.assertIs(c.admission_required(J,R),False)
        host.native_test_live.assert_called_once();host.enrollment_test_consumed.assert_called_once_with(123)
        for change in ['unconsumed','revoked','current','anchor','recipe','grant_release','pid','clock','dead_or_expired']:
            host,values=self.host()
            if change=='unconsumed':host.enrollment_test_consumed.return_value=False
            elif change=='revoked':host.revoked.return_value=True
            elif change in {'current','anchor'}:values['active.json'if change=='current'else'policy.json']['release_sha'if change=='current'else'anchor_sha']='d'*40
            elif change=='recipe':values['enrollment-test.json']['recipe']='shell-owned-v1'
            elif change=='grant_release':values['enrollment-test.json']['release_sha']='d'*40
            elif change=='pid':values['enrollment-test.json']['owner_pid']=True
            elif change=='clock':values['enrollment-test.json']['created_at']=False
            else:host.native_test_live.side_effect=ValueError('inert native owner or lease lost')
            with self.subTest(change=change),patch.object(c,'_root',return_value=lambda _:nullcontext(123)),patch.dict(sys.modules,{'vm_operator_host':host}),self.assertRaises(ValueError):
                c.admission_required(J,R)
    def test_actual_native_CLIENT_run_finishes_generated_recipe_without_private_log_handoff(self):
        host,_=self.host();records=[];calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if kwargs.get('input'):
                self.assertEqual(kwargs['input'],b'f'*64+b'\n');record={}
                worker.owned_browser_capture(J,R,record,lambda _:self.fail('native progress must not require a handoff'))
                records.append(record);return types.SimpleNamespace(returncode=0)
            return types.SimpleNamespace(returncode=1,stdout='',stderr='operator_native_test_consumed')
        with patch.object(c,'_root',return_value=lambda _:nullcontext(123)),patch.dict(sys.modules,{'vm_operator_host':host}), \
             patch.object(c,'admit')as admit,patch.object(c,'publish')as publish,patch.object(broker,'run_owned',return_value={'result':'PASS'})as probe, \
             patch.object(subprocess,'run',side_effect=run),patch.object(sys,'argv',['native-client','run']), \
             patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(b'f'*64+b'\n'))), \
             patch.object(os,'getuid',return_value=1000),patch.object(os,'geteuid',return_value=1000),redirect_stdout(io.StringIO())as log:
            exec(install.CLIENT,{'__name__':'native_client'})
        self.assertIn('"result": "PASS"',log.getvalue());self.assertEqual(len(calls),2)
        self.assertIs(records[0]['mail_admission_required'],False);self.assertNotIn('owned_mail_capture',records[0])
        admit.assert_not_called();publish.assert_not_called();probe.assert_called_once_with(J,R)
    def test_ordinary_timeout_never_falls_back_to_native_fixtures(self):
        with patch.object(c,'admission_required',return_value=True),patch.object(c,'admit',side_effect=TimeoutError('inert no descriptor')), \
             patch.object(broker,'run_owned')as probe,patch.object(c,'publish')as publish,self.assertRaises(TimeoutError):
            worker.owned_browser_capture(J,R,{},lambda _:None)
        probe.assert_not_called();publish.assert_not_called()
    def test_ordinary_admission_binds_same_job_capture_and_protected_publication(self):
        events=[];admission={'job':J,'release_sha':R};record={}
        with patch.object(c,'admission_required',return_value=True), \
             patch.object(c,'admit',side_effect=lambda *a:events.append('admit')or admission), \
             patch.object(broker,'run_owned',side_effect=lambda *a:events.append('capture')or{'result':'PASS'}), \
             patch.object(c,'publish',side_effect=lambda value:events.append(('publish',value))or{'status':'completed'}):
            worker.owned_browser_capture(J,R,record,lambda _:None)
        self.assertEqual(events,['admit','capture',('publish',admission)]);self.assertIs(record['mail_admission_required'],True)
    def test_UID_cannot_select_native_mode_or_read_protected_grant(self):
        with self.assertRaisesRegex(ValueError,'immutable_root_only'):c.admission_required(J,R)

if __name__=='__main__':unittest.main()
