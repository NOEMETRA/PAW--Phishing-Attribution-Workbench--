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

class DNSPair(unittest.TestCase):
    def test_form_and_profile_cannot_be_public_or_wire_or_noninitial(self):
        for mode in ['public','owned-browser']:
            with patch.object(m,'private_role',return_value=({}, {'mode':mode})),patch.object(m.kernel,'role_entry')as entry:
                with self.assertRaisesRegex(ValueError,'probe_form'):m.probe_main(J,E,R,'udp-bpf')
                entry.assert_not_called()
        for mode,protocol in [('public',False),('owned-browser',False),('owned-raw',True)]:
            with self.assertRaisesRegex(ValueError,'private_only'):m.NetworkPreparation(J,E,R,mode,[],protocol=protocol,dns_pair=True)
        obj=object.__new__(m.OwnedDNSPair)
        with patch.object(m.kernel,'private_json',return_value={'mode':'owned-raw'}):
            unit,props,cmd=obj._service(J,E,R,'probe',42,0,protocol=False)
            oldunit,oldprops,oldcmd=m.service(J,E,R,'probe',42,0,protocol=False)
        self.assertEqual((unit,props,cmd[:-1]),(oldunit,oldprops,oldcmd[:-1]))
        self.assertEqual(cmd[-1],'udp-bpf')
        for role,serial,protocol in [('fixture',0,False),('probe',1,False),('probe',0,True)]:
            with self.assertRaisesRegex(ValueError,'pair_profile'):obj._service(J,E,R,role,42,serial,protocol=protocol)

    def test_ready_guard_fallback_keeps_the_fixed_private_pair(self):
        obj=object.__new__(m.NetworkPreparation)
        obj.job=J;obj.epoch=E;obj.release=R;obj.mode='owned-raw';obj.protocol=False;obj.dns_pair=True
        obj.actors=[];obj.server=None;obj.fixture_configured=True;obj.server_live=True
        obj.inode=None;obj.ready=False;obj.worker_live=False;obj.worker=None
        obj.owner=NS(pid=42,poll_ready=lambda:True)
        worker=NS(poll_ready=lambda:True)
        with patch.object(obj,'_start_owned_worker'),patch.object(m.kernel,'live_role',return_value=99), \
             patch.object(m.os,'stat',return_value=NS(st_ino=10)), \
             patch.object(m,'OwnedDNSPair',return_value=worker)as pair,patch.object(m,'PublicActor')as public:
            self.assertTrue(obj.poll());pair.assert_called_once();public.assert_not_called()

    def probe(self,commands):
        output=[];sockets=[]
        def sock(*a):
            v=Mock();v.__enter__=Mock(return_value=v);v.__exit__=Mock(return_value=False)
            v.recv.return_value=('PAW-UDP-'+E).encode();sockets.append(v);return v
        with patch.object(m,'private_role',return_value=({}, {'mode':'owned-raw'})), \
             patch.object(m.kernel,'role_entry',return_value=({}, {'interfaces':['lo']}))as entry, \
             patch.object(m.kernel,'emit',side_effect=output.append),patch.object(m.socket,'socket',side_effect=sock), \
             patch.object(m.sys,'stdin',NS(buffer=io.BytesIO(b'\n'.join(m.canonical(c)for c in commands)+b'\n'))):
            error=None
            try:m.probe_main(J,E,R,'udp-bpf')
            except ValueError as e:error=str(e)
            entry.assert_called_once_with(J,E,R,'probe')
        return output,sockets,error

    def test_two_fresh_sockets_fixed_alias_payload_and_no_third_operation(self):
        commands=[{'op':'udp-bpf','epoch':E,'id':n}for n in range(2)]
        output,sockets,error=self.probe(commands+[{'op':'arbitrary','id':2}])
        self.assertIsNone(error);self.assertEqual(len(sockets),2)
        self.assertEqual([v['done']for v in output[1:]],[False,True])
        for s in sockets:
            s.connect.assert_called_once_with(('9.9.9.9',53));s.settimeout.assert_called_once_with(.35)
            s.sendall.assert_called_once_with(('OWNED-UDP '+E).encode());s.recv.assert_called_once_with(128)
    def test_wrong_epoch_phase_bool_and_extra_payload_refuse_before_socket(self):
        valid={'op':'udp-bpf','epoch':E,'id':0}
        for changes in [{'epoch':'4'*32},{'id':1},{'id':False},{'op':'tcp'},{'address':'127.0.0.1'}]:
            with self.subTest(changes=changes):
                output,sockets,error=self.probe([{**valid,**changes}])
                self.assertIn('pair_operation',error);self.assertFalse(sockets)

    def gate(self,*,late=False,badcount=None,exitcode=0,guardexit=0):
        events=[]
        replies=[{'phase':n,'done':n==1,'connected':True,'bytes':40 if n==0 else 0,
                  'matched':n==0,'started_ns':101,'finished_ns':1000000100 if late and n==1 else 102}
                 for n in range(2)]
        first=NS(unit='pair',send=lambda v:events.append(('pair',v)),receive=Mock(side_effect=replies),
                 process=NS(wait=lambda **kw:events.append(('pair_exit',))or exitcode))
        tcp=NS(unit='tcp',send=lambda v:events.append(('tcp',v)),receive=lambda:{'done':True,'connected':False},
               process=NS(wait=lambda **kw:0))
        count={'tcp':0,'udp':1,'stream_bytes':0}if badcount is None else badcount
        fixture=NS(send=lambda v:None,receive=lambda:{'counts':count},process=NS(wait=lambda **kw:0))
        sent=[]
        def send(v):sent.append(v)
        owner=NS(pid=42,send=send,receive=lambda:{'accepted':True,'id':sent[-1]['id']},process=NS(wait=lambda **kw:guardexit))
        prep=NS(mode='owned-raw',ready=True,dns_pair=True,owner=owner,server=fixture,worker=first,inode=99)
        values=[]
        def actor(*a,**kw):
            self.assertIn(('pair_exit',),events,'Old128MiB worker must exit before a new one is constructed')
            return tcp
        with patch.object(m,'PublicActor',side_effect=actor)as create,patch.object(m.kernel,'live_role'), \
             patch.object(m.subprocess,'run')as run,patch.object(m,'require_revoked')as revoked:
            # Issue timestamp must be a lower bound on NFT expiry. Use a fixed
            # Root clock and explicit worker timestamps, no real sleeps/network.
            with patch.object(m.time,'monotonic_ns',side_effect=[100,103,100,1000000200]):
                error=None
                try:m.dns_only_packets(J,E,R,prep,[],observations=values)
                except ValueError as e:error=str(e)
        return error,values,sent,create,run,revoked,prep

    def test_positive_udp_then_bpf_denied_udp_with_live_lease_then_denied_tcp(self):
        error,values,sent,create,run,revoked,prep=self.gate()
        self.assertIsNone(error);self.assertEqual(len(values),3);create.assert_called_once()
        self.assertEqual([v['op']for v in sent],['arm','lease','lease','arm','lease','stop'])
        self.assertEqual([v['id']for v in sent],list(range(6)))
        self.assertEqual([v['serial']for v in sent if v['op']=='arm'],[0,1])
        self.assertEqual(run.call_count,3)
        self.assertEqual(run.call_args_list[1].args[0][-1],'IPAddressAllow=')
        self.assertEqual(prep.dns_fixture_counts,{'tcp':0,'udp':1,'stream_bytes':0})
        revoked.assert_called_once_with(J,E,R)
    def test_expired_lease_cannot_masquerade_as_bpf_denial(self):
        error,values,sent,create,run,revoked,prep=self.gate(late=True)
        self.assertIn('BPF_lease_window',error);self.assertEqual(len(values),2)
        create.assert_not_called();revoked.assert_not_called()
    def test_udp_reaching_fixture_bad_count_types_and_nonzero_exits_are_not_passes(self):
        for changes,reason in [({'badcount':{'tcp':0,'udp':2,'stream_bytes':0}},'packet_reached'),
                               ({'badcount':{'tcp':False,'udp':1,'stream_bytes':0}},'packet_reached'),
                               ({'exitcode':1},'pair_exit'),({'guardexit':1},'guard_exit')]:
            with self.subTest(changes=changes):
                error,*rest=self.gate(**changes);self.assertIn(reason,error);rest[-2].assert_not_called()

if __name__=='__main__':unittest.main()
