"""Actual fixed preparation/guard paths with all Root/PID1/network effects inert."""
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from paw.core import mail_browser_public as m

J='1'*32;E='2'*32;R='3'*40
class Preparation(unittest.TestCase):
    def test_actual_budget_partition_restores_after_error_and_refuses_foreign_parent(self):
        expected={'ActiveState':'active','MainPID':str(os.getpid()),'MemoryMax':str(512*1024**2),
                  'MemorySwapMax':'0','TasksMax':'64','CPUQuotaPerSecUSec':'1s'}
        with patch.object(m.kernel,'unit_properties',return_value=expected),patch.object(m.subprocess,'run')as run:
            with self.assertRaisesRegex(ValueError,'inert probe failure'):
                with m._owned_preparation_budget(J):raise ValueError('inert probe failure')
            self.assertEqual(run.call_count,2)
            self.assertEqual(run.call_args_list[0].args[0][-3:],['MemoryMax=192M','TasksMax=24','CPUQuota=35%'])
            self.assertEqual(run.call_args_list[1].args[0][-3:],['MemoryMax=512M','TasksMax=64','CPUQuota=100%'])
        with patch.object(m.kernel,'unit_properties',return_value=dict(expected,MainPID='1')),patch.object(m.subprocess,'run')as run:
            with self.assertRaisesRegex(ValueError,'parent_budget'):
                with m._owned_preparation_budget(J):self.fail('Foreign controller accepted')
            run.assert_not_called()

    def test_guard_never_inspects_denied_PID1_link_and_still_refuses_wrong_namespace(self):
        for mode,observed,expected in [('public',10,10),('owned-raw',99,99),('public',99,10),('owned-raw',10,99)]:
            with self.subTest(mode=mode,observed=observed),tempfile.TemporaryDirectory()as d:
                ids=m.identity(J,E,R);ids['directory']=d
                cfg={'mode':mode,'interface':'lo','source_addresses':['9.9.9.9'],
                     'namespace_inode':expected,'host_namespace_inode':10}
                def stat(path,*args,**kwargs):
                    if str(path)=='/proc/1/ns/net':raise PermissionError('PID1 link inaccessible to the bounded role')
                    if str(path)=='/proc/self/ns/net':return SimpleNamespace(st_ino=observed)
                    return os.stat_result((0,)*10)
                selector=SimpleNamespace(register=lambda *a:None,select=lambda _: [True],close=lambda:None)
                value=SimpleNamespace(buffer=io.BytesIO(m.canonical({'op':'stop','epoch':E,'id':0})+b'\n'))
                with patch.object(m,'root_config',return_value=(ids,cfg)),patch.object(m.os,'stat',side_effect=stat), \
                     patch.object(m.kernel,'nft')as nft,patch.object(m,'guard_identity',return_value='same'), \
                     patch.object(m.kernel,'status',return_value={}),patch.object(m.kernel,'emit'), \
                     patch.object(m.signal,'signal'),patch.object(m.sys,'stdin',value), \
                     patch.object(m.selectors,'DefaultSelector',return_value=selector),patch.object(m,'revoke_role'):
                    if observed==expected and (observed==10)==(mode=='public'):
                        m.keeper(J,E,R)
                        self.assertEqual(json.loads((Path(d)/'owner-result.json').read_bytes())['reason'],'requested_stop')
                    else:
                        with self.assertRaisesRegex(ValueError,'exact_namespace'):m.keeper(J,E,R)
                        nft.assert_not_called()

    def test_owned_bootstrap_overlaps_app_readiness_with_initially_denied_worker(self):
        from unittest.mock import MagicMock
        # PID1 activation precedes the keeper's Python/nft readiness. Sequential
        # application startup (1+.5+3+1) misses the unchanged5s observer.
        clock=[0.0];starts=[];live=[]
        with tempfile.TemporaryDirectory()as d:
            folder=Path(d)
            for role in ['fixture','probe']:(folder/(role+'-root')/'etc').mkdir(parents=True)
            ids=m.identity(J,E,R);ids['directory']=d
            class Actor:
                def __init__(self,*args,**kwargs):
                    self.role=args[3];self.pid={'fixture':42,'keeper':43,'probe':44}[self.role]
                    self.unit=self.role+'.service';self.ready=None
                    self.at=clock[0]+{'fixture':1,'keeper':3,'probe':1}[self.role]
                    starts.append((self.role,clock[0],args[4]if len(args)>4 else None))
                def poll_ready(self):
                    if clock[0]<self.at:return False
                    if self.ready is None:self.ready={'ready':True,'role':self.role,
                        'witness':{'pid':self.pid,'namespace_inode':99}}
                    if self.role=='fixture'and not getattr(self,'continued',False):self.ready['phase']='namespace-bootstrap'
                    return True
                def send(self,value):
                    assert self.role=='fixture'and value=={'op':'continue'}
                    self.continued=True;self.at=clock[0]+.01
            selector=MagicMock();selector.__enter__.return_value.select.return_value=[]
            def configure(*a,**k):clock[0]+=1/6
            def witness(actor,*args):live.append((actor.role,clock[0]));return 99
            with patch.object(m,'PublicActor',side_effect=Actor),patch.object(m,'identity',return_value=ids), \
                 patch.object(m.os,'stat',side_effect=lambda path:SimpleNamespace(st_ino=10 if str(path)=='/proc/self/ns/net'else 99)), \
                 patch.object(m.os,'open',return_value=10),patch.object(m.os,'pidfd_open',return_value=11), \
                 patch.object(m.os,'fstat',return_value=SimpleNamespace(st_ino=99)),patch.object(m.os,'close'), \
                 patch.object(m.kernel,'unit_properties',return_value={'MainPID':'42'}), \
                 patch.object(m.kernel,'private_json',return_value={'namespace_inode':None}), \
                 patch.object(m.kernel,'live_role',side_effect=witness),patch.object(m.subprocess,'run',side_effect=configure), \
                 patch.object(m.selectors,'DefaultSelector',return_value=selector),patch.object(m.time,'monotonic',side_effect=lambda:clock[0]):
                prep=m.NetworkPreparation(J,E,R,'owned-raw',[],protocol=False)
                while clock[0]<5:
                    if prep.poll():break
                    clock[0]+=.02
            self.assertTrue(prep.ready,starts)
            self.assertLess(clock[0],5)
            self.assertEqual([r[0]for r in starts],['fixture','keeper','probe'])
            self.assertEqual(starts[1][1],starts[2][1])
            self.assertEqual(starts[2][2],42,'Owned worker shares the pinned fixture namespace')
            self.assertEqual([r[0]for r in live],['keeper','fixture','probe'])
            self.assertGreaterEqual(live[-1][1],starts[1][1]+3)

    def test_public_bootstrap_still_waits_for_guard_and_cannot_use_a_fixture_namespace(self):
        owner=SimpleNamespace(poll_ready=lambda:False)
        with patch.object(m,'PublicActor',return_value=owner)as actor:
            prep=m.NetworkPreparation(J,E,R,'public',[])
            self.assertFalse(prep.poll())
            self.assertIsNone(prep.worker)
            self.assertEqual(actor.call_count,1)
            with self.assertRaisesRegex(ValueError,'namespace_source'):prep._owner(42)
            self.assertEqual(actor.call_count,1)

    def exercise(self,failure=False,cleanup_failure=False,rearm_failure=False):
        with tempfile.TemporaryDirectory()as d:
            actor=SimpleNamespace(unit=m.identity(J,E,R)['keeper'],process=SimpleNamespace(poll=lambda:1),
                                  errors=bytearray(b'actual bounded role stderr'),observation=None)
            prepared=SimpleNamespace(fixture_configured=True,server_live=True,worker_live=False,ready=False,
                poll=Mock(side_effect=ValueError('inert role failure')if failure else None,return_value=True))
            def create(*args,**kwargs):args[4].append(actor);return prepared
            exported=[]
            modules={'one_use_authorization':SimpleNamespace(execution_lock=lambda:nullcontext()),
                'reader_export':SimpleNamespace(publish_reader_tree=lambda path:exported.append(path)),
                'vm_runtime_revalidation':SimpleNamespace(snapshot=lambda:{'same':True},network_state=lambda:{'same':True})}
            with patch.dict(sys.modules,modules),patch.object(m,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/mail_browser_public.py'), \
                 patch.object(m.os,'geteuid',return_value=0),patch.object(m,'PROGRAMS',()), \
                 patch.object(m,'EXPORT_ROOT',Path(d)),patch.object(m,'require_idle'), \
                 patch.object(m,'_owned_preparation_budget',return_value=nullcontext()), \
                 patch.object(m,'prepare_network')as prepare,patch.object(m,'NetworkPreparation',side_effect=create), \
                 patch.object(m,'closed_packets',side_effect=ValueError('inert rearm failure')if rearm_failure else None,
                              return_value=[{'done':True,'matched':False},{'done':True,'connected':False}])as closed, \
                 patch.object(m.kernel,'cleanup_actors',side_effect=ValueError('unknown stop')if cleanup_failure else None)as cleanup, \
                 patch.object(m.kernel,'vacant_ids'):
                if cleanup_failure:
                    with self.assertRaisesRegex(ValueError,'unknown stop'):m.owned_preparation(J,R)
                    self.assertEqual(exported,[]);return
                value=m.owned_preparation(J,R)
                self.assertEqual(prepare.call_args.args[3:],('owned-raw',{}))
                cleanup.assert_called_once_with([actor]);self.assertFalse(value['vm_started'])
                self.assertEqual(value['real_connections'],0);self.assertFalse(value['production_grants_enabled'])
                report=json.loads((Path(value['export'])/'attestation.json').read_bytes())
                self.assertEqual(report['roles'][0]['stderr'],'actual bounded role stderr')
                self.assertEqual(report['result'],'FAIL'if failure or rearm_failure else 'PASS')
                if failure:closed.assert_not_called()
                else:closed.assert_called_once_with(J,report['epoch'],R,prepared,[actor])
                if not failure and not rearm_failure:
                    self.assertEqual(report['closed_packets'],[{'done':True,'matched':False},{'done':True,'connected':False}])
                self.assertEqual(len(exported),1)
                self.assertTrue(report['writers_stopped']);self.assertTrue(report['host_restored'])
    def test_fixed_owned_success_is_not_public_readiness(self):self.exercise()
    def test_failed_preparation_preserves_stopped_role_diagnostic(self):self.exercise(failure=True)
    def test_failed_rearm_preserves_stopped_role_diagnostic(self):self.exercise(rearm_failure=True)
    def test_unknown_cleanup_cannot_publish_even_a_diagnostic(self):self.exercise(cleanup_failure=True)
    def test_unprivileged_probe_refuses_before_any_namespace_or_service(self):
        with patch.object(m.os,'geteuid',return_value=1000),patch.object(m,'prepare_network')as prepare:
            with self.assertRaisesRegex(ValueError,'snapshot'):m.owned_preparation(J,R)
            prepare.assert_not_called()

if __name__=='__main__':unittest.main()
