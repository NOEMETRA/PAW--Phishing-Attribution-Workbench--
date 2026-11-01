"""Inert fixed-clock expiry regression; actual filter acceptance stays mandatory."""
import io
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch
from paw.core import mail_browser_public as m
J='1'*32;E='2'*32;R='3'*40

class Expiry(unittest.TestCase):
    def test_private_fixed_form_keeps_profile_and_default_probe_unchanged(self):
        for mode in ['public','owned-browser']:
            with patch.object(m,'private_role',return_value=({}, {'mode':mode})),patch.object(m.kernel,'probe')as probe:
                with self.assertRaisesRegex(ValueError,'probe_form'):m.probe_main(J,E,R,'raw-expiry')
                probe.assert_not_called()
        for mode,protocol,dns in [('public',False,False),('owned-browser',False,False),('owned-raw',True,False),('owned-raw',False,True)]:
            with self.assertRaisesRegex(ValueError,'private_only'):
                m.NetworkPreparation(J,E,R,mode,[],protocol=protocol,dns_probe=dns,expiry_probe=True)
        obj=object.__new__(m.OwnedExpiryProbe)
        with patch.object(m.kernel,'private_json',return_value={'mode':'owned-raw'}):
            unit,props,cmd=obj._service(J,E,R,'probe',42,0,protocol=False)
            oldunit,oldprops,oldcmd=m.service(J,E,R,'probe',42,0,protocol=False)
        self.assertEqual((unit,props,cmd[:-1]),(oldunit,oldprops,oldcmd[:-1]));self.assertEqual(cmd[-1],'raw-expiry')
        for role,serial,protocol in [('fixture',0,False),('probe',1,False),('probe',0,True)]:
            with self.assertRaisesRegex(ValueError,'probe_profile'):obj._service(J,E,R,role,42,serial,protocol=protocol)
        for form,kwargs in [('raw',{}),('raw-expiry',{'stream_seconds':2})]:
            with patch.object(m,'private_role',return_value=({}, {'mode':'owned-raw'})),patch.object(m.kernel,'probe')as probe:
                m.probe_main(J,E,R,form);probe.assert_called_once_with(J,E,R,**kwargs)

    def test_stream_observes_full_window_instead_of_first_timeout_and_default_stays_three(self):
        k=m.kernel
        for seconds in [2,3]:
            clock=[10.];out=[];s=Mock();s.__enter__=Mock(return_value=s);s.__exit__=Mock(return_value=False)
            def receive(_):
                clock[0]+=.35
                if clock[0]<10.8:return ('PAW-STREAM-'+E).encode()
                raise k.socket.timeout()
            s.recv.side_effect=receive
            with patch.object(k,'role_entry',return_value=({},{})),patch.object(k,'emit',side_effect=lambda v:out.append(dict(v))), \
                 patch.object(k.sys,'stdin',NS(buffer=io.BytesIO(b'{"op":"stream"}\n'))),patch.object(k.socket,'socket',return_value=s), \
                 patch.object(k.time,'monotonic',side_effect=lambda:clock[0]),patch.object(k.time,'monotonic_ns',side_effect=lambda:int(clock[0]*10**9)):
                k.probe(J,E,R,**({'stream_seconds':seconds}if seconds==2 else {}))
            final=out[-1];self.assertGreater(final['bytes'],0);self.assertTrue(final['matched'])
            self.assertGreaterEqual(clock[0]-10,seconds);self.assertLess(clock[0]-10,seconds+.36)
            if seconds==2:
                self.assertGreaterEqual(final['observation_finished_ns']-final['observation_started_ns'],2*10**9)
                self.assertGreater(final['timeouts_after_data'],1)
            else:self.assertEqual(set(final),{'done','connected','bytes','matched','error'})
        for duration in [True,0,1,4,2.0]:
            with patch.object(k,'role_entry')as role:
                with self.assertRaisesRegex(ValueError,'duration'):k.probe(J,E,R,stream_seconds=duration)
                role.assert_not_called()
        with patch.object(k,'role_entry',return_value=({},{})),patch.object(k,'emit'), \
             patch.object(k.sys,'stdin',NS(buffer=io.BytesIO(b'{"op":"udp"}\n'))),patch.object(k.socket,'socket')as sock:
            with self.assertRaisesRegex(ValueError,'expiry_operation'):k.probe(J,E,R,stream_seconds=2)
            sock.assert_not_called()

    def gate(self,changes=None,counts=None,workerexit=0,serverexit=0,guardexit=0,badack=False):
        progress=[{'progress':True,'bytes':40,'matched':True,'last_byte_ns':1_100_000_000},
                  {'progress':True,'bytes':80,'matched':True,'last_byte_ns':1_800_000_000}]
        final={'done':True,'connected':True,'matched':True,'error':None,'bytes':80,
               'observation_started_ns':1_000_000_000,'observation_finished_ns':3_100_000_000,'timeouts_after_data':3}
        final.update(changes or {})
        owner=Mock();owner.receive.side_effect=[{'accepted':True,'id':True if badack else n}for n in range(3)]
        owner.process.wait.return_value=guardexit
        worker=Mock(unit='fixed-probe');worker.receive.side_effect=progress+[final];worker.process.wait.return_value=workerexit
        server=Mock();server.receive.return_value={'counts':counts or {'tcp':1,'udp':0,'stream_bytes':160}}
        server.process.wait.return_value=serverexit
        prep=NS(mode='owned-raw',ready=True,expiry_probe=True,owner=owner,worker=worker,server=server)
        observations=[];error=None
        with patch.object(m.time,'monotonic_ns',side_effect=[500_000_000,900_000_000,3_200_000_000]), \
             patch.object(m.subprocess,'run'),patch.object(m,'require_revoked')as proof,patch.object(m,'PublicActor')as actor:
            try:m.expiry_packets(J,E,R,prep,[],observations=observations)
            except ValueError as e:error=str(e)
        return error,prep,observations,proof,actor

    def test_expiry_requires_positive_then_silence_receiver_counts_stop_and_private_proof(self):
        error,prep,observations,proof,actor=self.gate();self.assertIsNone(error)
        self.assertEqual(len(observations),3);actor.assert_not_called();proof.assert_called_once_with(J,E,R)
        self.assertEqual([c.args[0]['op']for c in prep.owner.send.call_args_list],['arm','lease','stop'])
        self.assertEqual(prep.owner.send.call_args_list[1].args[0]['milliseconds'],1000)
        self.assertEqual(prep.server.send.call_args.args[0],{'op':'stop'})
        self.assertEqual(prep.expiry_window['finished_ns'],3_100_000_000)
        # Late replies, short observation, no negative socket evidence, no data,
        # guessed/boolean timestamps, receiver stopped sending, bad exits/ACK:
        # none may become PASS, even after earlier positive progress.
        for kwargs in [dict(changes={'observation_finished_ns':2_900_000_000}),
                       dict(changes={'observation_started_ns':2_800_000_000}),
                       dict(changes={'timeouts_after_data':0}),dict(changes={'bytes':0}),
                       dict(changes={'observation_started_ns':True}),dict(changes={'error':'TimeoutError'}),
                       dict(counts={'tcp':1,'udp':0,'stream_bytes':80}),dict(counts={'tcp':True,'udp':0,'stream_bytes':160}),
                       dict(workerexit=1),dict(serverexit=1),dict(guardexit=1),dict(badack=True)]:
            with self.subTest(kwargs=kwargs):
                error,prep,observations,proof,actor=self.gate(**kwargs)
                self.assertIsNotNone(error);proof.assert_not_called();actor.assert_not_called()
                if not kwargs.get('badack'):self.assertEqual(len(observations),3,'Preserve partial evidence')

if __name__=='__main__':unittest.main()
