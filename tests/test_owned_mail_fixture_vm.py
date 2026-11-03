"""Inert selection of the exact private preparation during an owned VM run."""
import hashlib, socket, tempfile, time, types, unittest
from pathlib import Path
from unittest.mock import Mock, patch
from paw.core import browser_owned_broker as broker, mail_browser_public as public
from paw.core import browser_broker_wire as wire, browser_owned_protocol as protocol

J, E, R = 'a'*32, 'b'*32, 'c'*40


class MailFixtureVM(unittest.TestCase):
    def test_mediation_legacy_and_invalid_selections_do_not_arm_mail_roles(self):
        prep=types.SimpleNamespace(owner=Mock(),worker=Mock())
        with patch.object(broker,'Mediation')as legacy,patch.object(public,'Mediation')as mail:
            for kwargs in [{},{'mail_fixture':False}]:
                broker.fixture_mediation(prep,E,123,Path('/unused'),**kwargs)
            self.assertEqual(legacy.call_count,2);mail.assert_not_called()
            for value in ['public',1,None]:
                with self.assertRaisesRegex(ValueError,'fixture_selection'):
                    broker.fixture_mediation(prep,E,123,Path('/unused'),mail_fixture=value)
            mail.assert_not_called();self.assertEqual(legacy.call_count,2)

    def test_selected_mail_mediation_reaches_actual_first_request_protocol_without_network(self):
        controls=[];responses=[];ids=public.identity(J,E,R)
        class Owner:
            unit='keeper.service';pid=42
            process=types.SimpleNamespace(wait=lambda timeout:0)
            def send(self,value):
                public.keeper_action(value,E,len(controls),ids)
                controls.append(value)
            def receive(self):return {'accepted':True,'id':controls[-1]['id']}
        class Worker:
            unit='probe.service';pid=43
            process=types.SimpleNamespace(stdin=types.SimpleNamespace(fileno=lambda:99),wait=lambda timeout:0)
            def receive(self,seconds):return responses.pop(0)
        prep=types.SimpleNamespace(owner=Owner(),worker=Worker())
        began=time.monotonic_ns();decoder=wire.Decoder(E)
        def http(plan,remaining):
            body=('PAW-OWNED-'+E).encode()
            return {'http_status':200,'headers':[],'peer_ipv4':'93.184.216.34',
                'tls_verified_by_broker':plan['scheme']=='https','body_bytes':len(body),
                'body_sha256':hashlib.sha256(body).hexdigest()},body
        transport=public.PublicTransport(E,began+9*10**9,
            lambda host,ident,deadline:protocol.dns_response(public.dns.question(host,ident)),http)
        def send(fd,raw,deadline):
            self.assertEqual(fd,99)
            [(header,body)]=decoder.feed(raw)
            fields,payload=transport.dispatch(E,header['sequence'],header['kind'],header['fields'],body)
            responses.append({'wire':{'kind':'reply','nonce':E,'sequence':header['sequence'],'fields':fields},'body':payload})
        with tempfile.TemporaryDirectory()as d,patch.object(socket,'socket',side_effect=AssertionError('no sockets')), \
             patch.object(broker,'write_private',side_effect=send),patch.object(public.subprocess,'run')as properties:
            mediation=broker.fixture_mediation(prep,E,began,Path(d),mail_fixture=True)
            request={'nonce':E,'seq':0,'url':broker.SEED,'method':'GET','resource':'Document'}
            metadata,body=mediation.response(request)
            self.assertEqual(metadata['http_status'],200);self.assertEqual(body,('PAW-OWNED-'+E).encode())
            self.assertFalse(mediation.ledger.closed)
            self.assertEqual(controls[0],{'op':'arm','epoch':E,'id':0,'serial':0})
            leases=[v for v in controls if v['op']=='lease']
            self.assertEqual([(v['kind'],v['address'])for v in leases],[('dns','9.9.9.9'),('https','93.184.216.34')])
            self.assertEqual([v.args[0][-2:]for v in properties.call_args_list],
                [['IPAddressAllow=','IPAddressAllow=9.9.9.9/32'],['IPAddressAllow=','IPAddressAllow=93.184.216.34/32']])
            self.assertEqual(mediation.budget.facts()['request_slots'],[1,0,0])
            self.assertEqual([v['operation']for v in mediation.observations],['dns','http'])
            self.assertEqual({v.name for v in Path(d).iterdir()},{'dns-00.bin','body-00.bin'})

    def test_mail_fixture_uses_exact_private_native_preparation_without_public_mode(self):
        actors = []
        with patch.object(public, 'NetworkPreparation') as prepare, \
             patch.object(broker, 'NetworkPreparation') as legacy:
            value = broker.fixture_preparation(J, E, R, actors, mail_fixture=True)
        prepare.assert_called_once_with(J, E, R, 'owned-browser', actors, protocol=True)
        legacy.assert_not_called()
        self.assertIs(value, prepare.return_value)

    def test_default_and_explicit_legacy_path_still_use_original_preparation(self):
        for kwargs in [{}, {'mail_fixture':False}]:
            with patch.object(public, 'NetworkPreparation') as mail, \
                 patch.object(broker, 'NetworkPreparation') as legacy:
                broker.fixture_preparation(J, E, R, [], **kwargs)
            mail.assert_not_called(); legacy.assert_called_once_with(J, E, R, [])

    def test_only_fixed_boolean_selection_exists(self):
        for value in ['public', 'owned-browser', 1, None, {}, Mock()]:
            with self.subTest(value=value), patch.object(public, 'NetworkPreparation') as prepare, \
                 self.assertRaisesRegex(ValueError, 'fixture_selection'):
                broker.fixture_preparation(J, E, R, [], mail_fixture=value)
            prepare.assert_not_called()

    def test_native_coordinator_partition_and_original_restore_keep_fixed_limits(self):
        with patch.object(broker.subprocess, 'run') as run:
            broker.partition('fixed-parent', mail_fixture=True)
            self.assertEqual(run.call_args.args[0][-3:], ['MemoryMax=192M','TasksMax=24','CPUQuota=35%'])
            broker.partition('fixed-parent', restore=True)
            self.assertEqual(run.call_args.args[0][-3:], ['MemoryMax=512M','TasksMax=64','CPUQuota=100%'])

    def test_legacy_partition_and_restore_are_unchanged(self):
        with patch.object(broker.subprocess, 'run') as run:
            broker.partition('fixed-parent')
            self.assertEqual(run.call_args.args[0][-3:], ['MemoryMax=256M','TasksMax=32','CPUQuota=50%'])

    def test_unprivileged_entry_refuses_before_any_fixture_selection(self):
        with patch.object(broker.kernel, 'owned_validation') as privileged, \
             self.assertRaisesRegex(ValueError, 'immutable_root_only'):
            broker.run_owned(J, R, mail_fixture=True)
        privileged.assert_not_called()


if __name__ == '__main__':
    unittest.main()
