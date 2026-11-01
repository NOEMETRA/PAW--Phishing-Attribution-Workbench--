"""Inert regression for the captured DNS-only third-worker guard expiry.

No fixture here claims actual packet filtering: immutable acceptance must still
observe private packets, fresh positive leases, receiver counts and stopped roles.
"""
import io
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch
from paw.core import mail_browser_public as m
J='1'*32;E='2'*32;R='3'*40

class DNSProbe(unittest.TestCase):
    def test_form_and_profile_cannot_be_public_or_wire_or_noninitial(self):
        for mode in ['public','owned-browser']:
            with patch.object(m,'private_role',return_value=({}, {'mode':mode})),patch.object(m.kernel,'role_entry')as entry:
                with self.assertRaisesRegex(ValueError,'probe_form'):m.probe_main(J,E,R,'dns-matrix')
                entry.assert_not_called()
        for mode,protocol in [('public',False),('owned-browser',False),('owned-raw',True)]:
            with self.assertRaisesRegex(ValueError,'private_only'):m.NetworkPreparation(J,E,R,mode,[],protocol=protocol,dns_probe=True)
        obj=object.__new__(m.OwnedDNSProbe)
        with patch.object(m.kernel,'private_json',return_value={'mode':'owned-raw'}):
            unit,props,cmd=obj._service(J,E,R,'probe',42,0,protocol=False)
            oldunit,oldprops,oldcmd=m.service(J,E,R,'probe',42,0,protocol=False)
        self.assertEqual((unit,props,cmd[:-1]),(oldunit,oldprops,oldcmd[:-1]))
        self.assertEqual(cmd[-1],'dns-matrix')
        for role,serial,protocol in [('fixture',0,False),('probe',1,False),('probe',0,True)]:
            with self.assertRaisesRegex(ValueError,'probe_profile'):obj._service(J,E,R,role,42,serial,protocol=protocol)

    def test_ready_guard_fallback_keeps_the_fixed_private_probe(self):
        obj=object.__new__(m.NetworkPreparation)
        obj.job=J;obj.epoch=E;obj.release=R;obj.mode='owned-raw';obj.protocol=False;obj.dns_probe=True
        obj.actors=[];obj.server=None;obj.fixture_configured=True;obj.server_live=True
        obj.inode=None;obj.ready=False;obj.worker_live=False;obj.worker=None
        obj.owner=NS(pid=42,poll_ready=lambda:True)
        worker=NS(poll_ready=lambda:True)
        with patch.object(obj,'_start_owned_worker'),patch.object(m.kernel,'live_role',return_value=99), \
             patch.object(m.os,'stat',return_value=NS(st_ino=10)), \
             patch.object(m,'OwnedDNSProbe',return_value=worker)as pair,patch.object(m,'PublicActor')as public:
            self.assertTrue(obj.poll());pair.assert_called_once();public.assert_not_called()

    def probe(self,commands):
        output=[];sockets=[]
        def sock(*a):
            v=Mock();v.__enter__=Mock(return_value=v);v.__exit__=Mock(return_value=False)
            v.recv.return_value=('PAW-'+('UDP'if a[1]==m.socket.SOCK_DGRAM else'TCP')+'-'+E).encode();sockets.append(v);return v
        with patch.object(m,'private_role',return_value=({}, {'mode':'owned-raw'})), \
             patch.object(m.kernel,'role_entry',return_value=({}, {'interfaces':['lo']}))as entry, \
             patch.object(m.kernel,'emit',side_effect=output.append),patch.object(m.socket,'socket',side_effect=sock), \
             patch.object(m.sys,'stdin',NS(buffer=io.BytesIO(b'\n'.join(m.canonical(c)for c in commands)+b'\n'))):
            error=None
            try:m.probe_main(J,E,R,'dns-matrix')
            except ValueError as e:error=str(e)
            entry.assert_called_once_with(J,E,R,'probe')
        return output,sockets,error

    def test_three_fresh_sockets_fixed_alias_payloads_and_no_fourth_operation(self):
        commands=[{'op':'dns-matrix','epoch':E,'id':n}for n in range(3)]
        output,sockets,error=self.probe(commands+[{'op':'arbitrary','id':3}])
        self.assertIsNone(error);self.assertEqual(len(sockets),3)
        self.assertEqual([v['done']for v in output[1:]],[False,False,True])
        for phase,s in enumerate(sockets):
            s.connect.assert_called_once_with(('9.9.9.9',53)if phase<2 else('93.184.216.34',80))
            s.settimeout.assert_called_once_with(.35)
            s.sendall.assert_called_once_with(('OWNED-'+('UDP'if phase<2 else'TCP')+' '+E).encode())
            s.recv.assert_called_once_with(128)
    def test_wrong_epoch_phase_bool_and_extra_payload_refuse_before_socket(self):
        valid={'op':'dns-matrix','epoch':E,'id':0}
        for changes in [{'epoch':'4'*32},{'id':1},{'id':False},{'op':'tcp'},{'address':'127.0.0.1'}]:
            with self.subTest(changes=changes):
                output,sockets,error=self.probe([{**valid,**changes}])
                self.assertIn('probe_operation',error);self.assertFalse(sockets)

    def test_only_private_dns_ack_stamps_before_the_nft_transaction(self):
        import tempfile
        from pathlib import Path
        for mode in ['owned-raw','owned-browser','public']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as d:
                ids=m.identity(J,E,R);ids['directory']=d
                inode=10 if mode=='public'else 99
                cfg={'mode':mode,'interface':'lo','source_addresses':['9.9.9.9'],
                     'namespace_inode':inode,'host_namespace_inode':10}
                commands=[{'op':'arm','epoch':E,'id':0,'serial':0},
                          {'op':'lease','epoch':E,'id':1,'kind':'dns','address':'9.9.9.9','milliseconds':1000},
                          {'op':'stop','epoch':E,'id':2}]
                raw=b''.join(m.canonical(v)+b'\n'for v in commands);clock=[100];nft=[];out=[]
                def transaction(*a,**kw):nft.append((kw['text'],clock[0]));clock[0]+=10
                selector=NS(register=lambda *a:None,select=lambda *_:[True],close=lambda:None)
                props={'ActiveState':'active','MainPID':'42','ControlGroup':'/system.slice/'+ids['probe']}
                with patch.object(m,'root_config',return_value=(ids,cfg)),patch.object(m.kernel,'nft',side_effect=transaction), \
                     patch.object(m,'guard_identity',return_value='fixed'),patch.object(m.kernel,'unit_properties',return_value=props), \
                     patch.object(m.os,'stat',return_value=NS(st_ino=inode)),patch.object(m.signal,'signal'), \
                     patch.object(m.selectors,'DefaultSelector',return_value=selector),patch.object(m,'revoke_role',return_value=True), \
                     patch.object(m.kernel,'status',return_value={}),patch.object(m.kernel,'emit',side_effect=lambda v:out.append(dict(v))), \
                     patch.object(m.time,'monotonic_ns',side_effect=lambda:clock[0]),patch.object(m.sys,'stdin',NS(buffer=io.BytesIO(raw))):
                    m.keeper(J,E,R)
                ack=next(v for v in out if v.get('op')=='lease')
                if mode=='owned-raw':
                    stamp=ack['lease_not_before_ns'];self.assertIs(type(stamp),int)
                    self.assertEqual(stamp,next(t for text,t in nft if 'add element'in text))
                    self.assertLess(stamp,clock[0])
                else:self.assertEqual(set(ack),{'accepted','id','op'})
                self.assertTrue((Path(d)/'revoked-complete').exists())

    def gate(self,*,late=False,tcp_late=False,exitcode=0,guardexit=0,badcount=None,
             tcp_connected=False,received=False,stamp='valid',producer=None):
        clock=[100_000_000];events=[];sent=[];lease=[None]
        def send(v):
            sent.append(v)
            if v['op']=='lease':
                clock[0]+=1_000_000_000;lease[0]=clock[0];clock[0]+=100_000_000
        def ack():
            v={'accepted':True,'id':sent[-1]['id']}
            if sent[-1]['op']=='lease'and stamp!='missing':
                v['lease_not_before_ns']={'valid':lease[0],'future':clock[0]+1,'boolean':True,'old':0}[stamp]
            return v
        owner=NS(pid=42,send=send,receive=ack,process=NS(wait=lambda **kw:guardexit))
        def reply():
            n=events[-1]['id']
            if n==1 and late or n==2 and tcp_late:clock[0]+=2_000_000_000
            start=clock[0];clock[0]+=350_000_000 if n==2 else 1_000_000
            return {'phase':n,'done':n==2,'connected':n<2 or tcp_connected,
                    'matched':n==0 or n==1 and received,'bytes':40 if n==0 or n==1 and received else 0,
                    'error':None if n==0 else 'PermissionError'if n==1 else'TimeoutError',
                    'started_ns':start,'finished_ns':clock[0]}
        worker=NS(unit='fixed-probe',send=lambda v:events.append(v),receive=reply,process=NS(wait=lambda **kw:exitcode))
        count={'tcp':0,'udp':1,'stream_bytes':0}if badcount is None else badcount
        fixture=NS(send=lambda v:None,receive=lambda:{'counts':count},process=NS(wait=lambda **kw:0))
        prep=NS(mode='owned-raw',ready=True,dns_probe=True,owner=owner,server=fixture,worker=worker,inode=99)
        def bpf(*a,**kw):clock[0]+=50_000_000
        values=[]
        with patch.object(m,'PublicActor')as create,patch.object(m.kernel,'live_role')as live, \
             patch.object(m.subprocess,'run',side_effect=bpf)as run,patch.object(m,'require_revoked')as revoked, \
             patch.object(m.time,'monotonic_ns',side_effect=lambda:clock[0]):
            error=None
            try:(producer or m.dns_only_packets)(J,E,R,prep,[],observations=values)
            except ValueError as e:error=str(e)
            live.assert_not_called()
        return error,values,sent,create,run,revoked,prep

    def test_positive_dns_bpf_denial_and_tcp_denial_share_the_proved_live_lease(self):
        error,values,sent,create,run,revoked,prep=self.gate()
        self.assertIsNone(error);self.assertEqual(len(values),3);create.assert_not_called()
        self.assertEqual([v['op']for v in sent],['arm','lease','stop'])
        self.assertEqual([v['id']for v in sent],list(range(3)));self.assertEqual(sent[1]['milliseconds'],1000)
        self.assertEqual(run.call_count,3)
        self.assertEqual(run.call_args_list[1].args[0][-1],'IPAddressAllow=')
        self.assertEqual(run.call_args_list[2].args[0][-1],'IPAddressAllow=93.184.216.34/32 9.9.9.9/32')
        self.assertEqual(prep.dns_fixture_counts,{'tcp':0,'udp':1,'stream_bytes':0})
        win=prep.bpf_lease_window;self.assertGreater(win['issued_ns']-win['requested_ns'],0)
        self.assertLess(win['finished_ns'],win['issued_ns']+10**9);self.assertLess(values[2]['started_ns'],win['issued_ns']+10**9)
        revoked.assert_called_once_with(J,E,R)

    def test_expiry_or_received_bytes_cannot_masquerade_as_bpf_denial(self):
        for kwargs,reason,size in [(dict(late=True),'BPF_lease_window',2),(dict(received=True),'BPF_lease_window',2),
                                   (dict(tcp_late=True),'actual_dns_only',3)]:
            with self.subTest(kwargs=kwargs):
                error,values,sent,create,run,revoked,prep=self.gate(**kwargs)
                self.assertIn(reason,error);self.assertEqual(len(values),size)
                self.assertIsNotNone(prep.bpf_lease_window);create.assert_not_called();revoked.assert_not_called()

    def test_lease_clock_must_be_typed_and_between_request_and_ack(self):
        for stamp in ['missing','future','boolean','old']:
            with self.subTest(stamp=stamp):
                error,values,sent,create,run,revoked,prep=self.gate(stamp=stamp)
                self.assertIn('lease_clock',error);self.assertEqual(values,[]);revoked.assert_not_called()

    def test_bad_receiver_counts_or_nonzero_exits_are_not_passes(self):
        for changes,reason in [({'badcount':{'tcp':0,'udp':2,'stream_bytes':0}},'packet_reached'),
                               ({'badcount':{'tcp':False,'udp':1,'stream_bytes':0}},'packet_reached'),
                               ({'exitcode':1},'probe_exit'),({'guardexit':1},'guard_exit'),({'tcp_connected':True},'actual_dns_only')]:
            with self.subTest(changes=changes):
                error,*rest=self.gate(**changes);self.assertIn(reason,error);rest[-2].assert_not_called()

if __name__=='__main__':unittest.main()
