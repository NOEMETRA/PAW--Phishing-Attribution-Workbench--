"""Inert public adapter boundaries; no Root, remote URL, DNS or socket work."""
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import os
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from paw.core import mail_browser_public as m
from paw.core import owned_kernel_policy as old
from paw.core import browser_broker_wire as wire

J='1'*32; E='2'*32; R='3'*40
SEEDS=['https://one.invalid/', 'http://two.invalid/', 'https://three.invalid/']

class PublicBoundary(unittest.TestCase):
    def test_revocation_proof_is_written_only_after_both_guard_sets_are_flushed(self):
        with tempfile.TemporaryDirectory()as d:
            folder=Path(d);(folder/'guard-created').touch();ids=m.identity(J,E,R);ids['directory']=d
            for failure in [None,'absent','flush']:
                with self.subTest(failure=failure),patch.object(m,'root_config',return_value=(ids,{})), \
                     patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=1 if failure=='absent'else 0)), \
                     patch.object(m.kernel,'nft',side_effect=ValueError('inert flush failure')if failure=='flush'else None)as nft:
                    if failure=='flush':
                        with self.assertRaisesRegex(ValueError,'inert flush failure'):m.revoke_role(J,E,R)
                    else:
                        self.assertIs(m.revoke_role(J,E,R),failure is None)
                        self.assertEqual(nft.call_count,2 if failure is None else 0)

    def test_stale_name_cannot_hide_a_later_foreign_selector_that_then_heals(self):
        group='/system.slice/'+m.identity(J,E,R)['probe'];inode=12345
        def dump(rights):
            return json.dumps({'nftables':sum(([{'table':{'family':'inet','name':table}},
                {'rule':{'family':'inet','table':table,'chain':'input','expr':[
                    {'match':{'op':'==','left':{'socket':{'key':'cgroupv2'}},'right':right}},
                    {'jump':{'target':'ingress'}}]}}]for table,right in zip(m.TABLES,rights)),[])})
        first=dump([group[1:],str(inode+1)]);healed=dump([str(inode),str(inode)])
        with patch.object(m.Path,'stat',side_effect=FileNotFoundError):
            with patch.object(m.kernel,'nft',return_value=healed):expected=m.guard_identity((group,inode))
            with patch.object(m.kernel,'nft',side_effect=[first,healed])as nft:
                with self.assertRaisesRegex(ValueError,'cgroup_id_changed'):
                    m.guard_identity((group,inode),expected=expected)
                self.assertEqual(nft.call_count,1)
            changed=json.loads(dump([group[1:],group[1:]]))
            changed['nftables'][3]['rule']['expr'][1]['jump']['target']='foreign'
            with patch.object(m.kernel,'nft',side_effect=[json.dumps(changed),healed])as nft:
                with self.assertRaisesRegex(ValueError,'guard_snapshot_changed'):
                    m.guard_identity((group,inode),expected=expected)
                self.assertEqual(nft.call_count,1,'Observed structural changes cannot heal on a retry')

    def test_guard_requeries_only_stale_rendering_and_never_accepts_a_foreign_ID(self):
        group='/system.slice/'+m.identity(J,E,R)['probe'];inode=12345
        def dump(right):
            return json.dumps({'nftables':sum(([{'table':{'family':'inet','name':table}},
                {'rule':{'family':'inet','table':table,'chain':'input','expr':[
                    {'match':{'op':'==','left':{'socket':{'key':'cgroupv2'}},'right':right}},
                    {'jump':{'target':'ingress'}}]}}]for table in m.TABLES),[])})
        with patch.object(m.Path,'stat',side_effect=FileNotFoundError), \
             patch.object(m.kernel,'nft',return_value=dump(str(inode))):
            expected=m.guard_identity((group,inode))
        # nft can render a live name, then PID1 removes it before our stat.
        # Require a fresh numeric kernel read, never trust the vanished name.
        with patch.object(m.Path,'stat',side_effect=FileNotFoundError):
            with patch.object(m.kernel,'nft',side_effect=[dump(group[1:]),dump(str(inode))])as nft:
                self.assertEqual(m.guard_identity((group,inode),expected=expected),expected)
                self.assertEqual(nft.call_count,2)
            for second in [dump(str(inode+1)),dump(group[1:]),json.dumps({'nftables':[]})]:
                with self.subTest(second=second), \
                     patch.object(m.kernel,'nft',side_effect=[dump(group[1:]),second])as nft:
                    with self.assertRaises(ValueError):m.guard_identity((group,inode),expected=expected)
                    self.assertEqual(nft.call_count,2)
            for bad in [dump(str(inode+1)),json.dumps({'nftables':[]})]:
                with patch.object(m.kernel,'nft',return_value=bad)as nft:
                    with self.assertRaises(ValueError):m.guard_identity((group,inode))
                    self.assertEqual(nft.call_count,1,'A real guard change is not retried')

    def test_guard_identity_pins_cgroup_ID_across_unit_collection_without_masking_changes(self):
        group='/system.slice/'+m.identity(J,E,R)['probe']; inode=12345
        def dump(right):
            return {'nftables':sum(([{'table':{'family':'inet','name':table}},
                {'rule':{'family':'inet','table':table,'chain':'input','expr':[
                    {'match':{'op':'==','left':{'socket':{'key':'cgroupv2'}},'right':right}},
                    {'jump':{'target':'ingress'}}]}}] for table in m.TABLES),[])}
        named=dump(group.lstrip('/')); numeric=dump(str(inode)); binding=(group,inode)
        with patch.object(m.kernel,'nft',return_value=json.dumps(named)), \
             patch.object(m.Path,'stat',return_value=SimpleNamespace(st_ino=inode)):
            expected=m.guard_identity(binding)
            with self.assertRaisesRegex(ValueError,'unarmed_cgroup'):m.guard_identity()
        with patch.object(m.Path,'stat',side_effect=FileNotFoundError):
            for right in [str(inode),inode]:
                with patch.object(m.kernel,'nft',return_value=json.dumps(dump(right))):
                    self.assertEqual(m.guard_identity(binding),expected)
            with patch.object(m.kernel,'nft',return_value=json.dumps(named)):
                with self.assertRaisesRegex(ValueError,'path_not_live'):m.guard_identity(binding)
            for right in [True,inode+1,str(inode+1),'0'+str(inode),'other/path']:
                with self.subTest(right=right),patch.object(m.kernel,'nft',return_value=json.dumps(dump(right))):
                    with self.assertRaises(ValueError):m.guard_identity(binding)
            changed=copy.deepcopy(numeric);changed['nftables'][1]['rule']['expr'][1]['jump']['target']='other'
            with patch.object(m.kernel,'nft',return_value=json.dumps(changed)):
                self.assertNotEqual(m.guard_identity(binding),expected)
            for change in ['table','selector','operator']:
                changed=copy.deepcopy(numeric)
                if change=='table':changed['nftables'].pop(0)
                elif change=='selector':changed['nftables'][1]['rule']['expr'].pop(0)
                else:changed['nftables'][1]['rule']['expr'][0]['match']['op']='!='
                with self.subTest(change=change),patch.object(m.kernel,'nft',return_value=json.dumps(changed)):
                    with self.assertRaises(ValueError):m.guard_identity(binding)
        with patch.object(m.kernel,'nft',return_value=json.dumps(numeric)), \
             patch.object(m.Path,'stat',return_value=SimpleNamespace(st_ino=inode+1)):
            with self.assertRaisesRegex(ValueError,'cgroup_replaced'):m.guard_identity(binding)

    def test_closed_owned_probe_rearms_second_actor_without_lease_or_public_scope(self):
        from unittest.mock import Mock
        owner=Mock(pid=42);owner.process.wait.return_value=0
        owner.receive.side_effect=[{'accepted':True,'id':v} for v in range(3)]
        first=Mock(unit='first.service');first.receive.return_value={'done':True,'matched':False}
        second=Mock(unit='second.service');second.receive.return_value={'done':True,'connected':False}
        prep=SimpleNamespace(mode='owned-raw',ready=True,owner=owner,worker=first,inode=99)
        roles=[]
        with patch.object(m,'PublicActor',return_value=second) as new, \
             patch.object(m.kernel,'live_role') as live,patch.object(m.subprocess,'run') as run:
            self.assertEqual(len(m.closed_packets(J,E,R,prep,roles)),2)
        new.assert_called_once_with(J,E,R,'probe',42,registry=roles,serial=1)
        live.assert_called_once_with(second,'probe',99)
        self.assertEqual([c.args[0]['op'] for c in owner.send.call_args_list],['arm','arm','stop'])
        self.assertEqual([c.args[0]['serial'] for c in owner.send.call_args_list[:2]],[0,1])
        first.send.assert_called_once_with({'op':'udp'});second.send.assert_called_once_with({'op':'tcp'})
        self.assertEqual(run.call_count,2)
        prep.mode='public'
        with self.assertRaisesRegex(ValueError,'closed_owned_only'):m.closed_packets(J,E,R,prep,roles)

    def test_failed_second_arm_retains_first_measured_owned_packet(self):
        from unittest.mock import Mock
        owner=Mock(pid=42);owner.receive.side_effect=[{'accepted':True,'id':0},ValueError('inert lost arm')]
        first=Mock(unit='first.service');first.receive.return_value={'done':True,'matched':False}
        second=Mock(unit='second.service');observations=[]
        prep=SimpleNamespace(mode='owned-raw',ready=True,owner=owner,worker=first,inode=99)
        with patch.object(m,'PublicActor',return_value=second),patch.object(m.kernel,'live_role'), \
             patch.object(m.subprocess,'run'):
            with self.assertRaisesRegex(ValueError,'inert lost arm'):
                m.closed_packets(J,E,R,prep,[],observations=observations)
        self.assertEqual(observations,[{'done':True,'matched':False}])
        second.send.assert_not_called()

    def test_successful_packet_frames_cannot_hide_a_guard_launcher_failure(self):
        from unittest.mock import Mock
        owner=Mock(pid=42);owner.receive.side_effect=[{'accepted':True,'id':v}for v in range(3)]
        owner.process.wait.return_value=1
        first=Mock(unit='first.service');first.receive.return_value={'done':True,'matched':False}
        second=Mock(unit='second.service');second.receive.return_value={'done':True,'connected':False}
        prep=SimpleNamespace(mode='owned-raw',ready=True,owner=owner,worker=first,inode=99)
        with patch.object(m,'PublicActor',return_value=second),patch.object(m.kernel,'live_role'), \
             patch.object(m.subprocess,'run'):
            with self.assertRaisesRegex(ValueError,'raw_guard_exit'):m.closed_packets(J,E,R,prep,[])

    def test_owned_alias_commands_use_pinned_namespace_FD_and_close_it_on_failure(self):
        from unittest.mock import Mock,MagicMock
        for failure in [None,'dead','pidfd','host']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as d:
                folder=Path(d)
                for role in ['fixture','probe']:(folder/(role+'-root')/'etc').mkdir(parents=True)
                cfg={'mode':'owned-browser','namespace_inode':None}
                ids=m.identity(J,E,R);ids['directory']=d
                server=SimpleNamespace(pid=42,unit='inert-fixture.service',poll_ready=lambda:True,ready={
                    'phase':'namespace-bootstrap','witness':{'namespace_inode':99}},send=Mock())
                obj=object.__new__(m.NetworkPreparation)
                obj.job=J;obj.epoch=E;obj.release=R;obj.actors=[];obj.mode='owned-browser';obj.protocol=True
                obj.ready=False;obj.fixture_configured=False;obj.server=server;obj.inode=None
                obj.owner=SimpleNamespace(poll_ready=lambda:False,unit='inert-keeper.service')
                obj.worker=None;obj._owner=lambda _:None
                selector=MagicMock();selector.__enter__.return_value.select.return_value=[True] if failure=='dead' else []
                stats=lambda path:SimpleNamespace(st_ino=1 if str(path)=='/proc/self/ns/net' else 99)
                with patch.object(m.os,'stat',side_effect=stats),patch.object(m.os,'open',return_value=10), \
                     patch.object(m.os,'pidfd_open',side_effect=OSError('inert dead') if failure=='pidfd' else None,return_value=11), \
                     patch.object(m.os,'fstat',return_value=SimpleNamespace(st_ino=1 if failure=='host' else 99)), \
                     patch.object(m.os,'close') as close,patch.object(m.kernel,'unit_properties',return_value={'MainPID':'42','ActiveState':'activating'}), \
                     patch.object(m.selectors,'DefaultSelector',return_value=selector),patch.object(m.subprocess,'run') as run, \
                     patch.object(m,'identity',return_value=ids),patch.object(m.kernel,'private_json',return_value=cfg):
                    if failure:
                        with self.assertRaises((ValueError,OSError)):obj.poll()
                        run.assert_not_called();server.send.assert_not_called()
                    else:
                        self.assertFalse(obj.poll());self.assertEqual(run.call_count,3)
                        for call in run.call_args_list:
                            self.assertIn('--net=/proc/self/fd/10',call.args[0]);self.assertEqual(call.kwargs['pass_fds'],(10,))
                        self.assertEqual(json.loads((folder/'public.json').read_bytes())['namespace_inode'],99)
                        server.send.assert_called_once_with({'op':'continue'})
                    closed={call.args[0] for call in close.call_args_list}
                    self.assertIn(10,closed)
                    if failure!='pidfd':self.assertIn(11,closed)

    def test_actual_preparation_resets_readiness_before_releasing_fast_pipe_fixture(self):
        from unittest.mock import Mock,MagicMock
        read,write=os.pipe();actors=[];test=self
        class Input:
            def write(self,raw):
                test.assertEqual(json.loads(raw),{'op':'continue'})
                os.write(write,b'{"ready":true,"role":"fixture","witness":{"pid":123,"namespace_inode":99}}\n')
                until=time.monotonic()+1
                while actors[0].output.empty() and time.monotonic()<until:time.sleep(.001)
                test.assertFalse(actors[0].output.empty(),'Actual second header queues before send returns')
                return len(raw)
            def flush(self):pass
        process=Mock(stdin=Input(),stdout=os.fdopen(read,'rb'),stderr=io.BytesIO())
        process.wait.return_value=0
        os.write(write,b'{"ready":true,"phase":"namespace-bootstrap","witness":{"pid":123,"namespace_inode":99}}\n')
        try:
            with patch.object(m.kernel,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/owned_kernel_runtime.py'), \
                 patch.object(m.kernel.os,'geteuid',return_value=0), \
                 patch.object(m.kernel.subprocess,'Popen',return_value=process):
                actor=m.kernel.Managed(J,E,R,'fixture',42);actors.append(actor)
            with tempfile.TemporaryDirectory() as d:
                folder=Path(d)
                for role in ['fixture','probe']:(folder/(role+'-root')/'etc').mkdir(parents=True)
                ids=m.identity(J,E,R);ids['directory']=d
                obj=object.__new__(m.NetworkPreparation)
                for name,value in {'job':J,'epoch':E,'release':R,'mode':'owned-raw','actors':actors,
                    'protocol':False,'server':actor,'owner':SimpleNamespace(poll_ready=lambda:False,unit='inert-keeper.service'),
                    'worker':None,'inode':None,'ready':False,'fixture_configured':False}.items():setattr(obj,name,value)
                obj._owner=lambda _:None
                selector=MagicMock();selector.__enter__.return_value.select.return_value=[]
                stats=lambda path:SimpleNamespace(st_ino=1 if str(path)=='/proc/self/ns/net' else 99)
                with patch.object(m.os,'stat',side_effect=stats),patch.object(m.os,'open',return_value=42), \
                     patch.object(m.os,'pidfd_open',return_value=43),patch.object(m.os,'fstat',return_value=SimpleNamespace(st_ino=99)), \
                     patch.object(m.os,'close'),patch.object(m.kernel,'unit_properties',return_value={'MainPID':'123','ActiveState':'activating'}), \
                     patch.object(m.selectors,'DefaultSelector',return_value=selector),patch.object(m.subprocess,'run'), \
                     patch.object(m,'identity',return_value=ids),patch.object(m.kernel,'private_json',return_value={'namespace_inode':None}):
                    self.assertFalse(obj.poll())
                self.assertTrue(actor.poll_ready())
                self.assertEqual(actor.ready['role'],'fixture')
                self.assertIsNotNone(actor._ready_received_at)
                self.assertLessEqual(actor._ready_received_at,actor._ready_deadline)
        finally:
            os.close(write)
            for actor in actors:
                for thread in actor.threads:thread.join(2)
                self.assertFalse(any(thread.is_alive() for thread in actor.threads))
            process.stdout.close()

    def test_actual_keeper_loop_records_deleted_guard_as_loss_then_revokes(self):
        with tempfile.TemporaryDirectory() as d:
            ids=m.identity(J,E,R);ids['directory']=d
            cfg={'mode':'public','interface':'owned0','source_addresses':['192.168.1.137'],
                 'namespace_inode':10,'host_namespace_inode':10}
            packet=m.canonical({'op':'delete_one','epoch':E,'id':0})+b'\n'
            selector=SimpleNamespace(register=lambda *a:None,select=lambda _: [True],close=lambda:None)
            with patch.object(m,'root_config',return_value=(ids,cfg)), \
                 patch.object(m.os,'stat',return_value=SimpleNamespace(st_ino=10)), \
                 patch.object(m.kernel,'nft',return_value=''),patch.object(m.kernel,'status',return_value={}), \
                 patch.object(m.kernel,'emit'),patch.object(m.signal,'signal'), \
                 patch.object(m.selectors,'DefaultSelector',return_value=selector), \
                 patch.object(m.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(packet))), \
                 patch.object(m,'guard_identity',side_effect=['same','same',ValueError('mail_public_guard_missing')]), \
                 patch.object(m,'revoke_role') as revoke:
                m.keeper(J,E,R)
            result=json.loads((Path(d)/'owner-result.json').read_bytes())
            self.assertEqual(result['reason'],'guard_changed')
            self.assertEqual(result['check_error'],'mail_public_guard_missing')
            self.assertFalse((Path(d)/'revoked-complete').exists())
            revoke.assert_called_once_with(J,E,R)
    def test_kernel_relative_timeout_is_recomputed_after_BPF_commit_latency(self):
        from paw.core import browser_owned_broker as existing
        obj=object.__new__(m.Mediation);obj.uplink=None;obj.approval=None;obj._existing=existing
        obj.worker=SimpleNamespace(unit='inert.service');events=[];obj.control=lambda *a,**k:events.append((a,k))
        with patch.object(m.subprocess,'run'),patch.object(m.time,'monotonic_ns',return_value=3*10**9):
            obj.allow('https','93.184.216.34',3000,plan={'expires_ns':6*10**9})
        self.assertEqual(events[0][1]['milliseconds'],1000)
        events.clear()
        with patch.object(m.subprocess,'run'),patch.object(m.time,'monotonic_ns',return_value=5*10**9):
            with self.assertRaisesRegex(ValueError,'expired_kernel_lease'):
                obj.allow('https','93.184.216.34',3000,plan={'expires_ns':6*10**9})
        self.assertFalse(events)
    def test_actual_shared_controller_denies_download_before_any_navigation(self):
        runtime=m.PublicRuntime();runtime.seed=SEEDS[0];runtime.nonce=E
        sent=[];runtime._send=sent.append;runtime._request=lambda _:self.fail('premature network')
        driver=runtime._make_controller();driver.start()
        self.assertEqual(driver.stage,'configuring')
        self.assertEqual(sent[0]['method'],'Browser.setDownloadBehavior')
        self.assertEqual(sent[0]['params']['behavior'],'deny')
        driver.accept({'id':sent[0]['id'],'result':{}})
        self.assertEqual(sent[-1]['method'],'Browser.grantPermissions')
        self.assertFalse(any(v['method']=='Page.navigate' for v in sent))
        with self.assertRaises(ValueError):driver.start()
        runtime.selector.close()
    def test_batch_counts_persist_across_three_serial_children(self):
        previous=None
        for slot in range(3):
            b=m.BatchBudget(SEEDS,previous)
            b.hostname('resource'+str(slot)+'.invalid')
            for _ in range(m.CASE_REQUESTS):
                b.request(slot)
            with self.assertRaises(ValueError): b.request(slot)
            b.reserve(slot); b.uncertain(slot)
            with self.assertRaises(ValueError): b.reserve(slot)
            previous=b.facts()
        self.assertEqual(previous['request_slots'],[10,10,10])
        self.assertEqual(sum(previous['response_bytes_or_unrecoverable_reservations']),4194303)
        self.assertEqual(len(previous['hostname_slots']),6)
        b=m.BatchBudget(SEEDS,previous)
        b.hostname('extra.invalid'); b.hostname('last.invalid')
        with self.assertRaises(ValueError): b.hostname('ninth.invalid')
        self.assertEqual(b.facts()['request_slots'],[10,10,10])

    def test_reservation_is_consumed_on_unknown_transport_and_never_lost_in_handoff(self):
        b=m.BatchBudget(SEEDS); b.reserve(0)
        self.assertEqual(m.BatchBudget(SEEDS,b.facts()).bytes[0],m.CASE_BYTES)
        b.complete(0,100); self.assertEqual(b.reserve(0),m.CASE_BYTES-100)
        b.uncertain(0)
        with self.assertRaises(ValueError): b.complete(0,0)
        with self.assertRaises(ValueError): b.uncertain(0)
        for slot in [True,-1,3,'0']:
            for method,args in [(b.request,()),(b.reserve,()),(b.complete,(0,)),(b.uncertain,())]:
                with self.subTest(slot=slot,method=method),self.assertRaises(ValueError):method(slot,*args)

    def test_handoff_cannot_replace_fixed_contract_or_initial_hosts(self):
        facts=m.BatchBudget(SEEDS).facts()
        for key,value in [('request_slots',[True,0,0]),('hostname_slots',['other.invalid']),
                          ('effective_per_case_requests',32),('batch_response_ceiling',2**30),
                          ('response_bytes_or_unrecoverable_reservations',[0,-1,0])]:
            bad=copy.deepcopy(facts);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.BatchBudget(SEEDS,bad)
        for bad in ['UPPER.invalid','127.0.0.1','bad.invalid/x','a.invalid:80']:
            with self.subTest(host=bad),self.assertRaises(ValueError):m.BatchBudget(SEEDS).hostname(bad)

    def test_packet_rules_bind_exact_service_interface_source_and_live_sets_both_ways(self):
        group='/system.slice/'+m.identity(J,E,R,7)['probe']
        script=m.rules(group,'wlp4s0',['192.168.1.137'])
        self.assertEqual(script.count('socket cgroupv2 level 2'),2)
        self.assertEqual(script.count('meta skuid 65520 jump egress'),2)
        self.assertEqual(script.count('ct state established accept'),4)
        self.assertIn('priority 0',script);self.assertIn('priority 10',script)
        self.assertNotIn('mark',script);self.assertNotIn('forward',script)
        for line in script.splitlines():
            if 'ct state established accept' in line:self.assertRegex(line,r'@(tcp4|udp4)')
        self.assertNotIn('socket cgroupv2',m.rules(None,'lo',['9.9.9.9','93.184.216.34']))
        for bad in [group+'; accept', '/user.slice/'+group.split('/')[-1],
                    group.replace('-probe-7','-probe-8')]:
            with self.assertRaises(ValueError):m.rules(bad,'lo',['9.9.9.9'])
        for bad in ['lo" accept','x'*16,'lo\n']:
            with self.assertRaises(ValueError):m.rules(group,bad,['9.9.9.9'])

    def test_leases_refuse_private_unbounded_and_foreign_resolver(self):
        for kind,address,ms in [('http','127.0.0.1',1000),('dns','93.184.216.34',1000),
                                ('https','93.184.216.34',3001),('http','93.184.216.34',True),
                                ('ftp','93.184.216.34',1000),('http','192.168.1.1',1)]:
            with self.subTest(kind=kind,address=address),self.assertRaises(ValueError):m.lease(kind,address,ms)
        script=m.lease('http','93.184.216.34',3000)
        self.assertEqual(script.count('flush set'),4)
        self.assertEqual(script.count('timeout 3000ms'),2)

    def test_fixed_profiles_and_old_defaults_preserved(self):
        base=old.service(J,E,R,'probe',42,protocol=True)
        cfg={'mode':'public'}
        with patch.object(m.kernel,'private_json',return_value=cfg):
            unit,p,c=m.service(J,E,R,'probe',42,3,protocol=True)
            self.assertEqual(p['IPAddressDeny'],'any');self.assertEqual(p['IPAddressAllow'],'')
            self.assertEqual(p['NetworkNamespacePath'],'/proc/42/ns/net')
            self.assertEqual(p['MemoryMax'],'128M');self.assertEqual(p['TasksMax'],'16')
            self.assertEqual(p['CPUQuota'],'25%');self.assertEqual(p['RuntimeMaxSec'],'10')
            self.assertIn('-mail-probe-3.service',unit);self.assertEqual(c[-1],'wire')
            _,p,_=m.service(J,E,R,'keeper')
            self.assertEqual(p['PrivateNetwork'],'no');self.assertNotIn('NetworkNamespacePath',p)
            self.assertEqual(p['CapabilityBoundingSet'],'CAP_NET_ADMIN')
            self.assertEqual(p['RestrictAddressFamilies'],'AF_UNIX AF_NETLINK')
            self.assertEqual(p['TimeoutStopSec'],'500ms')
            directory=m.identity(J,E,R)['directory']
            self.assertEqual(p['ExecStopPost'],"/bin/sh -c 'test -f "+directory+
                '/revoked-complete || exec /usr/sbin/nft -f '+directory+"/revoke.nft'")
            with self.assertRaises(ValueError):m.service(J,E,R,'fixture',42)
        self.assertEqual(base,old.service(J,E,R,'probe',42,protocol=True))

    def session(self):
        dns=lambda *_:b'\0'*12
        http=lambda plan,remaining:({'body_bytes':1,'body_sha256':m.sha(b'x')},b'x')
        return m.PublicTransport(E,time.monotonic_ns()+8*10**9,dns,http)

    def test_transport_replay_and_fault_close_before_any_network_callback(self):
        cases=[('f'*32,0,'stop',{},b''),(E,True,'stop',{},b''),(E,0,'shell',{},b''),
               (E,0,'stop',{},b'input'),(E,0,'dns',{'host':'127.0.0.1','ident':1,
                 'deadline_ns':time.monotonic_ns()+10**9},b'')]
        for args in cases:
            s=self.session()
            with patch.object(s,'dns',side_effect=AssertionError('DNS called')), \
                 patch.object(s,'http',side_effect=AssertionError('HTTP called')):
                with self.assertRaises(ValueError):s.dispatch(*args)
            self.assertTrue(s.closed)
            with self.assertRaises(ValueError):s.dispatch(E,0,'stop',{},b'')

    def test_valid_empty_http_body_and_private_wire_survive_actual_codec(self):
        s=self.session();s.http=lambda *_:({'body_bytes':0,'body_sha256':m.sha(b'')},b'')
        plan={'url':SEEDS[0],'nonce':E,'expires_ns':time.monotonic_ns()+10**9,
              'all_ipv4':['93.184.216.34'],'peer_ipv4':'93.184.216.34'}
        fields,body=s.dispatch(E,0,'http',{'plan':plan,'remaining_bytes':m.CASE_BYTES},b'')
        decoder=wire.Decoder(E)
        frames=decoder.feed(wire.frame(E,0,'reply',fields,body));decoder.eof()
        self.assertEqual(frames[0][1],b'')
        s.dispatch(E,1,'stop',{},b'')
        with self.assertRaises(ValueError):s.dispatch(E,2,'stop',{},b'')

if __name__=='__main__':unittest.main()
