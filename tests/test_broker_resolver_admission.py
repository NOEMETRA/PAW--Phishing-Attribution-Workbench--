from pathlib import Path
import time
import unittest

from paw.core import browser_mediator as b
URL='https://owned.invalid/';N='a'*32
def frame(seq=0,url=URL):return {'nonce':N,'seq':seq,'url':url,'method':'GET','resource':'Document'}
def ledger(dynamic=False):return b.BrowserRequestLedger(URL,N,time.monotonic_ns(),allow_dynamic_public_hosts=dynamic)
def facts():return {'answers':['93.184.216.34'],'observed_ns':time.monotonic_ns(),'ttl_ns':30*10**9}

class ResolverAdmission(unittest.TestCase):
    def test_slot_is_consumed_before_resolver_and_failure_does_not_restore_it(self):
        l=ledger();calls=[]
        def failed(host,deadline):calls.append((host,l.used));raise TimeoutError('owned synthetic DNS timeout')
        for i in range(32):
            with self.assertRaises(TimeoutError):l.admit_resolved(frame(seq=i),failed)
        self.assertEqual([x[1] for x in calls],list(range(1,33)))
        with self.assertRaises(ValueError):l.admit_resolved(frame(seq=32),failed)
        self.assertEqual(len(calls),32);self.assertTrue(l.closed)
    def test_bad_envelope_method_or_seed_never_calls_resolver(self):
        def forbidden(*args):raise AssertionError('must not resolve')
        bad=[{**frame(),'extra':1},{**frame(),'method':'POST'},frame(url='https://other.invalid/')]
        for f in bad:
            with self.subTest(frame=f),self.assertRaises(ValueError):ledger().admit_resolved(f,forbidden)
    def test_actual_timestamps_bind_after_resolution_and_rebinding_still_refuses(self):
        l=ledger();p=l.admit_resolved(frame(),lambda *_:facts())
        self.assertEqual(p['slot'],0);self.assertEqual(l.used,1)
        l.complete(p,200,[],b'',p['peer_ipv4'],True,time.monotonic_ns())
        with self.assertRaisesRegex(ValueError,'rebinding'):
            l.admit_resolved(frame(seq=1),lambda *_:{**facts(),'answers':['8.8.8.8']})
    def test_reentrant_resolution_closes_session_and_cannot_return_a_lease(self):
        l=ledger()
        def nested(*args):
            with self.assertRaises(ValueError):l.admit_resolved(frame(seq=1),lambda *_:facts())
            return facts()
        with self.assertRaisesRegex(ValueError,'closed'):l.admit_resolved(frame(),nested)
        self.assertTrue(l.closed);self.assertIsNone(l._pending)
    def test_dns_name_ceiling_applies_even_to_rejected_answers(self):
        l=ledger(True);calls=[]
        # First admit the seed so subsequent different hosts can be considered.
        p=l.admit_resolved(frame(),lambda *_:facts());l.complete(p,200,[],b'',p['peer_ipv4'],True,time.monotonic_ns())
        def private(host,*_):calls.append(host);return {**facts(),'answers':['127.0.0.1']}
        for i in range(1,8):
            with self.assertRaises(ValueError):l.admit_resolved(frame(seq=i,url=f'https://owned{i}.invalid/'),private)
        with self.assertRaisesRegex(ValueError,'dns_name_budget'):l.admit_resolved(frame(seq=8,url='https://ninth.invalid/'),private)
        self.assertEqual(len(calls),7)

    def test_future_stale_or_malformed_resolver_facts_never_return_lease(self):
        for data in [None,{}, {**facts(),'observed_ns':True},
                     {**facts(),'observed_ns':time.monotonic_ns()+10**9},
                     {**facts(),'observed_ns':time.monotonic_ns()-11*10**9},
                     {**facts(),'ttl_ns':True}]:
            l=ledger()
            with self.subTest(data=data),self.assertRaises(ValueError):
                l.admit_resolved(frame(),lambda *_:data)
            self.assertIsNone(l._pending);self.assertEqual(l.used,1)

    def test_close_preserves_existing_statistics_shape(self):
        self.assertEqual(set(ledger().close()),{'requests_consumed','response_bytes',
            'redirect_responses','public_hosts','network_stopped'})

if __name__=='__main__':unittest.main()

