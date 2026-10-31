import hashlib
import time
import unittest
import json
import sys
from paw.core import browser_cdp as cdp
from paw.core import browser_owned_broker_guest as g

N='a'*32
def request(seq=0):return {'nonce':N,'seq':seq,'url':'https://paw-owned.invalid/',
                          'method':'GET','resource':'Document'}
def metadata(body,slot=0):return {'status':'response','slot':slot,'http_status':200,'headers':[],
    'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()}

class Driver:
    def __init__(self):self.stage='running';self.responses=[];self.refusals=0;self.after=None
    def response(self,meta,body):
        self.responses.append((meta,body))
        if self.after:self.after()
    def refused(self):
        self.refusals+=1
        if self.after:self.after()

class AsyncOwned(unittest.TestCase):
    def setUp(self):
        self.runtime=g.Runtime();self.addCleanup(self.runtime.selector.close)
        self.runtime.nonce=N;self.runtime.driver=Driver();self.runtime.started=time.monotonic();self.runtime._request(request())
    def transfer(self,body,meta=None):
        r=self.runtime;meta=metadata(body) if meta is None else meta;raw=cdp.canonical(meta)
        r.network({'kind':'begin','nonce':N,'seq':0,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
        for section,payload in [('metadata',raw),('body',body)]:
            for row in cdp.response_chunks(N,0,payload):
                r.network({'kind':'part','nonce':N,'seq':0,'section':section,'row':row})

    def test_initial_fetch_remains_paused_until_both_typed_transfers_complete(self):
        r=self.runtime;self.assertEqual(r.driver.responses,[]);self.assertEqual(r.requests,1)
        body=b'owned-data'*65536;self.transfer(body)
        self.assertEqual(r.driver.responses,[(metadata(body),body)]);self.assertIsNone(r.network_pending)
        self.assertEqual(r.network_bytes,len(body))

    def test_empty_body_uses_explicit_end_and_correct_digest(self):
        self.transfer(b'');self.assertEqual(self.runtime.driver.responses[0][1],b'')

    def test_refusal_is_finite_without_headers_body_or_live_continue(self):
        r=self.runtime;r.network({'kind':'refusal','nonce':N,'seq':0})
        self.assertEqual(r.refused,1);self.assertEqual(r.driver.refusals,1)
        self.assertEqual(r.driver.responses,[]);self.assertIsNone(r.network_pending)

    def test_next_queued_request_survives_completion_callback(self):
        r=self.runtime;r.driver.after=lambda:r._request(request(1));self.transfer(b'owned')
        self.assertEqual(r.network_pending['request']['seq'],1)
        self.assertEqual(r.network_pending['phase'],'await_begin');self.assertEqual(r.requests,2)

    def test_wrong_nonce_sequence_phase_and_replay_permanently_close(self):
        bad=[{'kind':'refusal','nonce':'b'*32,'seq':0},
             {'kind':'refusal','nonce':N,'seq':True},
             {'kind':'part','nonce':N,'seq':0,'section':'body','row':{}},
             {'kind':'begin','nonce':N,'seq':0,'bytes':True,'sha256':'a'*64}]
        for message in bad:
            r=g.Runtime();self.addCleanup(r.selector.close);r.nonce=N;r.driver=Driver();r.started=time.monotonic();r._request(request())
            with self.subTest(message=message),self.assertRaises(ValueError):r.network(message)
            self.assertTrue(r.transfer_failed);self.assertEqual(r.driver.stage,'failed')
            with self.assertRaises(ValueError):r.network({'kind':'refusal','nonce':N,'seq':0})

    def test_wrong_metadata_declared_body_and_full_request_budgets_refuse(self):
        for mutate in [lambda v:v.update(slot=1),lambda v:v.update(body_bytes=cdp.MAX_BODY+1),
                       lambda v:v.update(unexpected=True)]:
            r=g.Runtime();self.addCleanup(r.selector.close);r.nonce=N;r.driver=Driver();r.started=time.monotonic();r._request(request())
            value=metadata(b'owned');mutate(value);raw=cdp.canonical(value)
            r.network({'kind':'begin','nonce':N,'seq':0,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
            with self.assertRaises(ValueError):
                for row in cdp.response_chunks(N,0,raw):
                    r.network({'kind':'part','nonce':N,'seq':0,'section':'metadata','row':row})
            self.assertEqual(r.driver.responses,[])
        r=self.runtime
        with self.assertRaises(ValueError):r._request(request(1))

    def test_network_transfer_cannot_bypass_fifteen_second_timer_between_polls(self):
        r=self.runtime;r.started=time.monotonic()-20
        with self.assertRaises(ValueError):
            r.network({'kind':'begin','nonce':N,'seq':0,'bytes':2,'sha256':hashlib.sha256(b'{}').hexdigest()})
        self.assertTrue(r.transfer_failed);self.assertEqual(r.driver.stage,'failed')

    def test_snapshot_boundary_latches_quiescence_and_does_not_permit_another_response(self):
        from unittest.mock import patch
        runtime=self.runtime;runtime.network_pending=None;runtime.driver.stage='snapshot'
        with patch.object(g.fixed.Runtime,'tick',return_value={'done':False,'stage':'snapshot'}):
            value=runtime.tick()
        self.assertIs(value['network_quiescent'],True)
        with patch.object(g.fixed.Runtime,'tick',return_value={'done':True,'writers_stopped':True}):
            self.assertIs(runtime.tick()['network_quiescent'],True)
        with self.assertRaises(ValueError):runtime.network({'kind':'refusal','nonce':N,'seq':0})

    def test_actual_maximum_console_fragment_reaches_typed_assembler(self):
        from paw.core import browser_broker_console as channel
        runtime=self.runtime;session=g.ConsoleSession(runtime);body=b'x'*32768
        raw=cdp.canonical(metadata(body));identifier=1
        reply=session.command(channel.encode(identifier,{'kind':'begin','nonce':N,'seq':0,
            'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
        self.assertTrue(reply['ok'])
        for section,payload in [('metadata',raw),('body',body)]:
            for row in cdp.response_chunks(N,0,payload):
                identifier+=1
                session.command(channel.encode(identifier,{'kind':'part','nonce':N,'seq':0,'section':section,'row':row}))
        self.assertEqual(runtime.driver.responses,[(metadata(body),body)])

    def test_console_sequence_duplicates_unknown_ops_and_shape_close_session(self):
        for raw in [b'{"id":1,"id":1,"op":"poll"}',b'{"id":true,"op":"poll"}',
            b'{"id":2,"op":"poll"}',b'{"id":1,"op":"shell"}',
            b'{"id":1,"op":"inspect","config":{}}',b'x'*60000]:
            session=g.ConsoleSession(self.runtime)
            with self.subTest(raw=raw[:80]),self.assertRaises(ValueError):session.command(raw)
            self.assertTrue(session.closed)
            with self.assertRaises(ValueError):session.command(b'{"id":1,"op":"inspect"}')

    def test_console_protocol_failure_stops_an_existing_renderer_before_refusing(self):
        from unittest.mock import Mock
        runtime=Mock(process=object());session=g.ConsoleSession(runtime)
        with self.assertRaises(ValueError):session.command(b'{"id":2,"op":"poll"}')
        runtime.finish.assert_called_once_with('failed','owned_console_protocol_lost')

class GuestLoop(unittest.TestCase):
    def test_actual_inert_eof_and_partial_line_close_existing_renderer(self):
        import io
        from unittest.mock import Mock
        for raw in [b'',b'{"id":1,"op":"poll"}']:
            runtime=Mock(process=object(),done=None)
            if raw:
                with self.assertRaises(ValueError):g.serve(runtime,io.BytesIO(raw),lambda _:None)
            else:g.serve(runtime,io.BytesIO(raw),lambda _:None)
            runtime.finish.assert_called_once_with('failed','owned_console_owner_lost')

    def test_fixed_flat_seed_import_under_isolated_python_has_no_entry_effect(self):
        import pathlib,subprocess,tempfile,shutil
        with tempfile.TemporaryDirectory()as folder:
            target=pathlib.Path(folder)
            for name in ['browser_cdp.py','browser_owned_cdp_guest.py']:
                shutil.copyfile(pathlib.Path(cdp.__file__).with_name(name),target/name)
            shutil.copyfile(g.__file__,target/'browser_owned_broker_guest.py')
            result=subprocess.run([sys.executable,'-I','-B','-c',
                'import runpy,sys;v=runpy.run_path(sys.argv[1]);assert callable(v["main"])',
                str(target/'browser_owned_broker_guest.py')],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
