"""Inert owned kernel guards: no administrative call or namespace is made."""
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from contextlib import ExitStack, nullcontext
import os
import sys
import threading
import time

from paw.core import owned_kernel_policy as p
from paw.core import owned_kernel_runtime as r
J='a'*32;E='b'*32;R='c'*40


class Policy(unittest.TestCase):
    def test_new_pid1_namespace_and_dependencies_need_no_host_route_or_named_mount(self):
        unit,props,cmd=p.service(J,E,R,'keeper')
        self.assertEqual(props['PrivateNetwork'],'yes');self.assertEqual(props['PrivateMounts'],'yes')
        self.assertEqual(props['RuntimeMaxSec'],'8');self.assertEqual(props['TimeoutStopSec'],'500ms')
        self.assertEqual(props['NotifyAccess'],'none');self.assertEqual(props['Restart'],'no')
        self.assertEqual(props['CapabilityBoundingSet'],'CAP_NET_ADMIN')
        self.assertEqual(props['RestrictAddressFamilies'],'AF_UNIX AF_NETLINK')
        self.assertEqual(props['IPAddressDeny'],'any');self.assertEqual(props['BindsTo'],p.identity(J,E,R)['parent'])
        self.assertFalse(any('/run/netns/'in value for value in props.values()))
        self.assertIn('/opt/paw-vm/releases/'+R+'/',cmd[4])

    def test_network_roles_use_fixed_vacant_nonroot_ids_and_validated_owner_pid(self):
        for role,uid in [('probe',65520),('fixture',65521)]:
            _,props,cmd=p.service(J,E,R,role,12345)
            self.assertEqual(props['User'],'root');self.assertEqual(props['Group'],'root')
            self.assertEqual(props['AmbientCapabilities'],'CAP_SETUID')
            self.assertEqual(props['CapabilityBoundingSet'],
                'CAP_SETUID CAP_SETGID'+(' CAP_NET_BIND_SERVICE'if role=='fixture'else''))
            self.assertEqual(props['SupplementaryGroups'],'')
            self.assertEqual(props['NetworkNamespacePath'],'/proc/12345/ns/net')
            self.assertEqual(props['RootDirectory'],p.identity(J,E,R)['directory']+'/'+role+'-root')
            self.assertEqual(props['SystemCallFilter'],'@system-service')
            self.assertEqual(props['NoNewPrivileges'],'yes');self.assertEqual(props['MemorySwapMax'],'0')
            self.assertNotIn('/home/',repr(props));self.assertNotIn('/var/lib/paw-s14',repr(props))
            self.assertEqual(cmd[4],'/opt/paw-code/owned_kernel_runtime.py')

    def test_budget_partition_preserves_root_aggregate_and_existing_qemu_ceiling(self):
        specs=[p.service(J,E,R,role,12345)[1] for role in ['keeper','fixture','probe']]
        self.assertEqual(256+sum(int(x['MemoryMax'][:-1])for x in specs),512)
        self.assertEqual(32+sum(int(x['TasksMax'])for x in specs),64)
        self.assertEqual(50+sum(int(x['CPUQuota'][:-1])for x in specs),100)
        self.assertEqual(1536+512,2048)

    def test_no_caller_paths_commands_properties_or_unknown_identities_are_accepted(self):
        for args in [('../job',E,R,'keeper',None),(J,True,R,'keeper',None),
                     (J,E,'/tmp/code','probe',123),(J,E,R,[],123),(J,E,R,'shell',123),
                     (J,E,R,'fixture',True),(J,E,R,'probe',None)]:
            with self.subTest(args=args),self.assertRaises(ValueError):p.service(*args)

    def test_both_default_drop_guards_match_expiring_tuples_in_both_directions(self):
        text=p.rules();self.assertEqual(text.count('policy drop;'),4)
        self.assertEqual(text.count('flags timeout; timeout 5s; size 1;'),4)
        self.assertEqual(text.count('meta nfproto ipv6 drop'),2)
        self.assertEqual(text.count('ip saddr . tcp sport @targets4 ct state established accept'),2)
        self.assertNotIn('ct state established accept\n',text.replace('ip saddr . tcp sport @targets4 ct state established accept\n','').replace('ip saddr . udp sport @dns4 ct state established accept\n',''))
        for value in ['127.0.0.0/8','169.254.0.0/16','192.168.0.0/16','100.64.0.0/10']:
            self.assertEqual(text.count(value),4)

    def test_one_sequential_tuple_and_revoke_before_next_dns_or_tcp(self):
        for kind,address,port in [('dns','9.9.9.9',53),('http','93.184.216.34',80),('https','93.184.216.34',443)]:
            raw=p.lease(kind,500);self.assertEqual(raw.count('flush set'),4)
            self.assertEqual(raw.count(address+' . '+str(port)),2);self.assertEqual(raw.count('timeout 500ms'),2)
        for kind,ms in [('dns',True),('dns',0),('dns',5001),([],1),('arbitrary',1)]:
            with self.assertRaises(ValueError):p.lease(kind,ms)


class Boundaries(unittest.TestCase):
    def test_ordinary_uid_cannot_start_root_manager_owner_or_fixture_probe(self):
        with patch.object(subprocess,'Popen',side_effect=AssertionError('administrative call')), \
             patch.object(socket,'socket',side_effect=AssertionError('socket')):
            for call in [lambda:r.Managed(J,E,R,'keeper'),lambda:r.root_entry(J,E,R),
                         lambda:r.owned_validation(J,R),lambda:r.role_entry(J,E,R,'fixture'),
                         lambda:r.role_entry(J,E,R,'probe')]:
                with self.assertRaises(ValueError):call()

    def test_root_from_mutable_workspace_still_refuses_before_commands(self):
        with patch.object(r.os,'geteuid',return_value=0), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('administrative call')):
            for call in [lambda:r.root_entry(J,E,R),lambda:r.owned_validation(J,R),lambda:r.Managed(J,E,R,'keeper')]:
                with self.assertRaises(ValueError):call()

    def test_duplicate_nonfinite_nonobject_and_oversized_control_refuse(self):
        for raw in [b'{"op":1,"op":2}',b'{"x":NaN}',b'[]',b'x'*4097]:
            with self.assertRaises(ValueError):r.decode(raw)

    def test_control_sequence_epoch_exact_shape_and_no_arbitrary_nft_text(self):
        good={'op':'lease','epoch':E,'id':0,'kind':'dns','milliseconds':500}
        op,text=r.keeper_action(good,E,0);self.assertEqual(op,'lease');self.assertEqual(text,p.lease('dns',500))
        for change in [{'id':True},{'id':1},{'epoch':'d'*32},{'command':'flush ruleset'},
                       {'milliseconds':6000},{'kind':'dns\nflush ruleset'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):r.keeper_action({**good,**change},E,0)
        for op in ['delete_one','delete_both','stop','revoke']:
            action,text=r.keeper_action({'op':op,'epoch':E,'id':0},E,0);self.assertEqual(action,op)
            if text is not None:self.assertNotIn('paw_s14',text)

    def test_relative_and_traversal_config_never_open_files(self):
        with patch.object(r.os,'open',side_effect=AssertionError('file open')):
            for path in [Path('relative.json'),Path('/tmp/../etc/config')]:
                with self.assertRaises(ValueError):r.private_json(path)


class Credentials(unittest.TestCase):
    def test_observed_systemd259_setuid_drop_is_prevented_only_for_fixed_bootstrap(self):
        # Actual protected147 witness: every predicate except capabilities
        # passed;0x4c0 configured ->0x440 observed. v259 exec-invoke.c drops
        # SETUID during keep_seccomp_privileges unless it is ambient.
        observed=0x440;configured=0x4c0;uid_bit=1<<7
        self.assertEqual(configured&~uid_bit,observed)
        for role in ['fixture','probe']:
            _,props,_=p.service(J,E,R,role,12345)
            self.assertEqual(props['AmbientCapabilities'],'CAP_SETUID')
            self.assertEqual(props['NoNewPrivileges'],'yes')
            self.assertEqual(props['SystemCallFilter'],'@system-service')
            self.assertNotIn('CAP_SYS_ADMIN',props['CapabilityBoundingSet'])

    def test_refusal_diagnostic_names_failed_predicate_without_dropping_or_opening(self):
        before={'interfaces':['lo','owned-wrong-view'],'nnp':'1','seccomp':'2','groups':[0],
            'cap_eff':'c0','cap_prm':'c0','cap_inh':'0','cap_amb':'0','namespace_inode':123,
            'credential':'must never be included'}
        with patch.object(r.os,'getresuid',return_value=(0,)*3),patch.object(r.os,'getresgid',return_value=(0,)*3), \
             patch.object(r,'status',return_value=before),patch.object(r.os,'setgroups')as groups, \
             patch.object(r.socket,'socket',side_effect=AssertionError('no socket')):
            with self.assertRaisesRegex(ValueError,'bootstrap_confinement')as caught:r.drop_credentials('probe')
            groups.assert_not_called()
        payload=r.decode(str(caught.exception).split(':',1)[1].encode())
        self.assertFalse(payload['checks']['interfaces'])
        self.assertTrue(all(value for key,value in payload['checks'].items()if key!='interfaces'))
        self.assertNotIn('credential',payload['observed']);self.assertNotIn('must never',str(caught.exception))

    def test_actual_unprivileged_capset_abi_cannot_add_a_capability(self):
        if os.geteuid()==0:self.skipTest('Root credential changes require immutable owned acceptance')
        # Clear only a disposable child's inherited bits, never the runner's.
        code="""import sys,os
sys.path.insert(0,sys.argv[1])
from paw.core import owned_kernel_runtime as r
assert os.geteuid()!=0
uid=os.getuid();r.capabilities(0)
try:r.capabilities(1024)
except ValueError as e:assert str(e)=='owned_kernel_capset_failed'
else:raise AssertionError('unprivileged gain accepted')
assert os.getuid()==uid
assert all(int(r.status()[k],16)==0 for k in ['cap_eff','cap_prm','cap_inh','cap_amb'])
"""
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(r.HERE.parents[2])],
            capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_each_role_drops_all_ids_and_groups_before_returning(self):
        from unittest.mock import Mock
        for role,uid in [('probe',65520),('fixture',65521)]:
            state={'uids':(0,0,0),'gids':(0,0,0),'groups':[0]};events=[]
            witness={'interfaces':['lo'],'nnp':'1','seccomp':'2','groups':[0],
                'cap_eff':hex(192+(1024 if role=='fixture'else 0))}
            libc=Mock();libc.prctl.return_value=0
            def groups(value):state['groups']=value;events.append('groups')
            def gid(*value):state['gids']=value;events.append('gid')
            def uids(*value):state['uids']=value;events.append('uid')
            def caps(value):
                self.assertEqual(state['uids'],(uid,)*3);self.assertEqual(state['gids'],(uid,)*3)
                self.assertEqual(state['groups'],[]);events.append(('caps',value))
            with patch.object(r.os,'getresuid',side_effect=lambda:state['uids']), \
                 patch.object(r.os,'getresgid',side_effect=lambda:state['gids']), \
                 patch.object(r.os,'getgroups',side_effect=lambda:state['groups']), \
                 patch.object(r.os,'setgroups',side_effect=groups),patch.object(r.os,'setresgid',side_effect=gid), \
                 patch.object(r.os,'setresuid',side_effect=uids),patch.object(r,'status',return_value=witness), \
                 patch.object(r.ctypes,'CDLL',return_value=libc),patch.object(r,'capabilities',side_effect=caps):
                r.drop_credentials(role)
            self.assertEqual(events,['groups','gid','uid',('caps',1024 if role=='fixture'else 0)])
            self.assertEqual(state['uids'],(uid,)*3)
            self.assertEqual(libc.prctl.call_count,2 if role=='fixture'else 0)

    def test_configuration_is_bound_before_credential_bootstrap(self):
        with patch.object(r,'HERE',Path('/opt/paw-code/owned_kernel_runtime.py')), \
             patch.object(r.os,'geteuid',return_value=0),patch.object(r,'private_json',return_value={}), \
             patch.object(r,'drop_credentials')as drop:
            with self.assertRaisesRegex(ValueError,'private_root_config'):r.role_entry(J,E,R,'fixture')
            drop.assert_not_called()

    def test_unprivileged_or_excessive_bootstrap_never_calls_identity_syscalls(self):
        from unittest.mock import Mock
        with patch.object(r.os,'getresuid',return_value=(1000,)*3),patch.object(r.os,'setresuid')as uid:
            with self.assertRaisesRegex(ValueError,'credential_bootstrap'):r.drop_credentials('fixture')
            uid.assert_not_called()
        with patch.object(r.os,'getresuid',return_value=(0,)*3),patch.object(r.os,'getresgid',return_value=(0,)*3), \
             patch.object(r,'status',return_value={'interfaces':['lo'],'nnp':'1','seccomp':'2','groups':[0],'cap_eff':'ffffffff'}), \
             patch.object(r.os,'setgroups')as groups:
            with self.assertRaisesRegex(ValueError,'bootstrap_confinement'):r.drop_credentials('probe')
            groups.assert_not_called()

    def test_fixture_sockets_are_created_after_bootstrap_and_all_caps_end_before_ready(self):
        from unittest.mock import Mock
        events=[];witness={'cap_eff':'0','cap_prm':'0','cap_inh':'0','cap_amb':'0'}
        def bootstrap(*args):events.append('bootstrap');return None,witness
        def create(*args):events.append('socket');return Mock()
        def emitted(value):
            self.assertEqual(events,['bootstrap','socket','socket',('caps',0)])
            raise StopIteration('readiness reached inertly')
        with patch.object(r,'role_entry',side_effect=bootstrap),patch.object(r.socket,'socket',side_effect=create), \
             patch.object(r.selectors,'DefaultSelector',return_value=Mock()),patch.object(r,'status',return_value=witness), \
             patch.object(r,'capabilities',side_effect=lambda mask:events.append(('caps',mask))), \
             patch.object(r.os,'getresuid',return_value=(65521,)*3),patch.object(r.os,'getresgid',return_value=(65521,)*3), \
             patch.object(r.os,'getgroups',return_value=[]),patch.object(r,'emit',side_effect=emitted):
            with self.assertRaisesRegex(StopIteration,'readiness reached'):r.fixture(J,E,R)


class Lifecycle(unittest.TestCase):
    def test_deferred_readiness_keeps_arrival_deadline_and_registered_cleanup(self):
        import io
        from unittest.mock import Mock
        for late in [False,True]:
            with self.subTest(late=late):
                read,write=os.pipe();stream=os.fdopen(read,'rb');registry=[]
                process=Mock(stdin=io.BytesIO(),stdout=stream,stderr=io.BytesIO())
                process.poll.return_value=None
                try:
                    with patch.object(r,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'), \
                         patch.object(r.os,'geteuid',return_value=0),patch.object(r.subprocess,'Popen',return_value=process), \
                         patch.object(r.subprocess,'run',return_value=SimpleNamespace(returncode=0)), \
                         patch.object(r,'unit_properties',return_value={'MainPID':'0','ActiveState':'inactive'}):
                        actor=r.Managed(J,E,R,'keeper',registry=registry,defer_ready=True)
                        self.assertIsNone(actor.ready);self.assertFalse(actor.poll_ready())
                        arrival=actor._ready_deadline+(1 if late else -1)
                        with patch.object(r.time,'monotonic',return_value=arrival):
                            os.write(write,b'{"ready":true,"witness":{"pid":12345}}\n');os.close(write);write=None
                            actor.threads[0].join(timeout=1)
                            self.assertFalse(actor.threads[0].is_alive())
                        # Polling later may consume an on-time header, but must
                        # never turn a late arrival into accepted readiness.
                        with patch.object(r.time,'monotonic',return_value=actor._ready_deadline+2):
                            if late:
                                with self.assertRaisesRegex(ValueError,'deadline'):actor.poll_ready()
                            else:self.assertTrue(actor.poll_ready());self.assertEqual(actor.pid,12345)
                        r.cleanup_actors(registry)
                        self.assertFalse(any(t.is_alive()for t in actor.threads))
                finally:
                    if write is not None:os.close(write)
                    stream.close()

    def test_keeper_ready_after_two_seconds_is_observed_inside_unchanged_hard_ceiling(self):
        import io
        from unittest.mock import Mock
        read,write=os.pipe();stream=os.fdopen(read,'rb');registry=[]
        process=Mock(stdin=io.BytesIO(),stdout=stream,stderr=io.BytesIO())
        process.poll.return_value=None
        def delayed():
            time.sleep(2.05)
            try:os.write(write,b'{"ready":true,"witness":{"pid":12345}}\n')
            finally:os.close(write)
        writer=threading.Thread(target=delayed);writer.start()
        try:
            with patch.object(r,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'), \
                 patch.object(r.os,'geteuid',return_value=0),patch.object(r.subprocess,'Popen',return_value=process), \
                 patch.object(r.subprocess,'run',return_value=SimpleNamespace(returncode=0)), \
                 patch.object(r,'unit_properties',return_value={'MainPID':'0','ActiveState':'inactive'}):
                try:actor=r.Managed(J,E,R,'keeper',registry=registry)
                finally:r.cleanup_actors(registry)
                self.assertTrue(actor.ready['ready'])
                _,props,_=p.service(J,E,R,'keeper')
                self.assertEqual(props['RuntimeMaxSec'],'8');self.assertEqual(props['TimeoutStopSec'],'500ms')
        finally:
            writer.join(timeout=3);stream.close()
        self.assertFalse(writer.is_alive())

    def test_stop_error_requires_independent_inactive_zero_mainpid_readback(self):
        from unittest.mock import Mock
        actor=SimpleNamespace(unit='owned.service',threads=[],errors=b'',process=Mock())
        with patch.object(r.subprocess,'run',return_value=SimpleNamespace(returncode=5))as stop:
            with patch.object(r,'unit_properties',return_value={'ActiveState':'inactive','MainPID':'0'}):
                r.Managed.stop(actor)
            stop.assert_called_once();actor.process.wait.assert_called_once()
            for state in [{'ActiveState':'active','MainPID':'12345'}, {'ActiveState':'failed','MainPID':'12345'}]:
                with patch.object(r,'unit_properties',return_value=state),self.assertRaisesRegex(ValueError,'stop_failed'):
                    r.Managed.stop(actor)

    def test_exited_launcher_still_stops_its_independently_live_unit(self):
        stopped=[];state={'ActiveState':'active','MainPID':'12345'}
        def stop():stopped.append('service');state.update(ActiveState='inactive',MainPID='0')
        actor=SimpleNamespace(unit='owned.service',pidfd=None,threads=[],errors=b'',stop=stop,
            process=SimpleNamespace(poll=lambda:1,wait=lambda **kw:1))
        with patch.object(r,'unit_properties',side_effect=lambda unit:dict(state)):
            r.cleanup_actors([actor])
        self.assertEqual(stopped,['service'])

    def actor(self, name, fail=False):
        process=SimpleNamespace(poll=lambda:None,wait=lambda **kw:None)
        actor=SimpleNamespace(unit=name,process=process,threads=[],errors=b'',pidfd=None)
        def stop():
            self.stops.append(name)
            if fail:raise ValueError('injected stop failure')
        actor.stop=stop
        return actor

    def test_cleanup_attempts_every_actor_after_stop_and_readback_failure(self):
        self.stops=[];actors=[self.actor('first'),self.actor('second',True)]
        with patch.object(r,'unit_properties',side_effect=[ValueError('readback'),{'MainPID':'0','ActiveState':'inactive'}]), \
             self.assertRaisesRegex(ValueError,'cleanup_failed'):
            r.cleanup_actors(actors)
        self.assertEqual(self.stops,['second','first'])

    def test_partial_readiness_constructor_is_registered_and_stopped(self):
        import io
        from unittest.mock import Mock
        registry=[];process=Mock(stdin=io.BytesIO(),stdout=io.BytesIO(b'{"ready":false}\n'),stderr=io.BytesIO())
        process.poll.return_value=None
        with patch.object(r,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'), \
             patch.object(r.os,'geteuid',return_value=0),patch.object(r.subprocess,'Popen',return_value=process), \
             patch.object(r.subprocess,'run',return_value=SimpleNamespace(returncode=0)), \
             patch.object(r,'unit_properties',return_value={'MainPID':'0','ActiveState':'inactive'}):
            with self.assertRaisesRegex(ValueError,'not_ready'):r.Managed(J,E,R,'keeper',registry=registry)
            self.assertEqual(len(registry),1)
            r.cleanup_actors(registry)
        process.wait.assert_called_once()

    def exercise(self, failure=None):
        actors=[];limits=[];rows=[];epochs={};probe_counts={}
        parent='paw-vm-owned-'+J+'.service'
        original_stat=os.stat
        class Actor:
            def __init__(self,job,epoch,release,role,keeper_pid=None,registry=None,serial=0):
                self.role=role;self.epoch=epoch;self.unit=p.service(job,epoch,release,role,keeper_pid,serial)[0]
                if role=='keeper':epochs[epoch]=len(epochs)
                self.case=epochs[epoch];self.pid=12345;self.pidfd=None;self.threads=[];self.errors=b'';self.sent={}
                self.alive=True;self.process=SimpleNamespace(poll=lambda:None if self.alive else 0,wait=self.wait)
                actors.append(self);registry.append(self)
                if failure in {'readiness','stop'} and role=='fixture':raise ValueError('injected readiness')
            def wait(self,**kw):self.alive=False;return 0
            def stop(self):
                self.alive=False
                if failure=='stop':raise ValueError('injected stop')
            def send(self,value):self.sent=value
            def receive(self,*args):
                if self.role=='keeper':return {'id':self.sent['id'],'accepted':True}
                if self.role=='fixture':return {'counts':{}}
                op=self.sent['op']
                if op=='stream':return {'progress':True,'matched':True,'bytes':43,'last_byte_ns':1}
                n=probe_counts.get(self.epoch,0);probe_counts[self.epoch]=n+1
                matched=(self.case==1 and op=='udp')or(self.case==2 and n==0)
                if failure=='packet' and self.case==0:matched=True
                return {'done':True,'matched':matched,'connected':matched,'bytes':43 if matched else 0,'error':None}
        def properties(unit):
            if unit==parent:return {'ActiveState':'active','MainPID':str(os.getpid()),'MemoryMax':str(512*1024**2),
                'MemorySwapMax':'0','TasksMax':'64'}
            return {'ActiveState':'inactive','MainPID':'0'}
        def command(argv,**kwargs):
            limits.append(argv[-3:])
            if failure=='limit' and len(limits)==1:raise ValueError('injected limit')
            return SimpleNamespace(returncode=0)
        with ExitStack()as stack:
            for target,name,value in [(r,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'),
                (r.os,'geteuid',lambda:0),(r,'vacant_ids',lambda:None),(r,'unit_properties',properties),
                (r,'prepare_case',lambda *args:None),(r,'Managed',Actor),
                (r,'private_json',lambda path:{'reason':'guard_changed' if epochs[path.parent.name]==4 else 'requested_stop'}),
                (r,'live_role',lambda *args:original_stat('/proc/self/ns/net').st_ino+1),
                (r.subprocess,'run',command),(r.signal,'pidfd_send_signal',lambda *args:None),
                (r.time,'sleep',lambda n:None),(Path,'mkdir',lambda *args,**kw:None),
                (Path,'write_bytes',lambda path,raw:rows.append(r.decode(raw)))]:
                stack.enter_context(patch.object(target,name,value))
            try:result=r._owned_validation(J,R)
            except ValueError as error:result=error
        return result,actors,limits,rows

    def test_all_five_coordinator_cases_close_actors_and_restore_partition(self):
        result,actors,limits,rows=self.exercise()
        self.assertEqual(result['result'],'PASS');self.assertEqual(len(result['cases']),5)
        self.assertEqual(len(rows),5);self.assertTrue(all(not a.alive for a in actors))
        self.assertEqual(limits[-1],['MemoryMax=512M','TasksMax=64','CPUQuota=100%'])
        self.assertEqual(len({a.unit for a in actors}),len(actors))

    def test_partial_start_packet_failure_stop_failure_and_limit_failure_restore(self):
        for failure in ['readiness','packet','stop','limit']:
            with self.subTest(failure=failure):
                result,actors,limits,_=self.exercise(failure)
                self.assertIsInstance(result,ValueError)
                self.assertTrue(all(not a.alive for a in actors))
                self.assertEqual(limits[-1],['MemoryMax=512M','TasksMax=64','CPUQuota=100%'])

    def test_terminal_diagnostic_requires_stopped_writers_and_unchanged_host(self):
        writes=[]
        fs=SimpleNamespace(execution_lock=nullcontext,root_directory=lambda p:nullcontext(1),
            exclusive=lambda fd,name,raw:writes.append(r.decode(raw)))
        modules={'one_use_authorization':fs,'reader_export':SimpleNamespace(publish_reader_tree=lambda p:None),
            'vm_runtime_revalidation':SimpleNamespace(snapshot=lambda:{'guard':'same'},network_state=lambda:{'routes':'same'})}
        with patch.dict(sys.modules,modules),patch.object(r.os,'geteuid',return_value=0), \
             patch.object(r,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'), \
             patch.object(r,'vacant_ids'),patch.object(r,'_owned_validation',side_effect=ValueError('injected failure')), \
             patch.object(r,'unit_properties',return_value={'MemoryMax':str(512*1024**2),'TasksMax':'64','CPUQuotaPerSecUSec':'1s'}), \
             patch.object(r.subprocess,'check_output',return_value=''),patch.object(Path,'exists',return_value=False), \
             patch.object(Path,'read_bytes',return_value=b'fixed code'),patch.object(Path,'mkdir'):
            with self.assertRaisesRegex(ValueError,'component_failed'):r.owned_validation(J,R)
            self.assertEqual(writes[-1]['result'],'FAIL');self.assertTrue(writes[-1]['writers_stopped'])
            writes.clear()
            with patch.object(r.subprocess,'check_output',return_value='leftover.service'),self.assertRaisesRegex(ValueError,'still_active'):
                r.owned_validation(J,R)
            self.assertEqual(writes,[])


if __name__=='__main__':unittest.main()
