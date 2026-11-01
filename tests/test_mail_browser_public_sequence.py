"""Finite batch ordering and local descriptor checks, no Root/PID1/network."""
from contextlib import nullcontext
import copy
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace,ModuleType
import unittest
from unittest.mock import patch,Mock
from paw.core import mail_browser_public as p,mail_browser_native as n

B='a'*32;R='b'*40
SEEDS=['https://one.invalid/','http://two.invalid/','https://three.invalid/']

class Sequence(unittest.TestCase):
    def simulate(self,*,bad_gate=None,bad_ack=False,accounting_regression=False):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);calls=[];ack=[]
            approval={'batch_id':B,'release_sha':R,'selections':[{'url':v} for v in SEEDS]}
            def write(path,raw,**kw):
                path.write_bytes(raw)
            def launch(approval,kind,case,slot='owned',previous=None):
                calls.append((kind,case,slot))
                if case==bad_gate:raise ValueError('inert owned gate failed')
                if kind=='kernel':return {'result':'PASS'}
                if slot=='owned':return {'status':'completed','slot':'owned'}
                self.assertTrue(ack);self.assertTrue((directory/'real-batch-consumed').exists())
                budget=p.BatchBudget(SEEDS,previous);budget.request(slot);budget.reserve(slot);budget.complete(slot,1)
                result=budget.facts()
                if accounting_regression and slot==1:result['request_slots'][0]=0
                return {'status':'failed','slot':slot,'budget':result}
            def receive(approval):
                self.assertEqual(calls[-1],('capture','browser','owned'))
                self.assertFalse((directory/'real-batch-consumed').exists())
                if bad_ack:raise ValueError('inert changed ZIP')
                ack.append(True);return {'actual_custody_verified':True}
            runtime=ModuleType('vm_runtime_revalidation');runtime.snapshot=lambda:{'stopped':True}
            runtime.network_state=lambda:{'unchanged':True}
            with patch.dict(sys.modules,{'vm_runtime_revalidation':runtime}), \
                 patch.object(n,'private_batch',return_value=directory),patch.object(n,'atomic',side_effect=write), \
                 patch.object(p,'launch_child',side_effect=launch),patch.object(p,'receive_owned_ack',side_effect=receive), \
                 patch.object(p,'publish_status'):
                if bad_gate or bad_ack or accounting_regression:
                    with self.assertRaises(ValueError):p.native_sequence(approval)
                else:
                    result=p.native_sequence(approval)
                    self.assertEqual([v['slot'] for v in result['results']],[0,1,2])
                    self.assertEqual(result['budget']['request_slots'],[1,1,1])
                    self.assertEqual(result['status'],'collected','Unavailable websites are outcomes, not invented success')
            if bad_gate or bad_ack:
                self.assertFalse((directory/'real-batch-consumed').exists())
                self.assertFalse(any(type(row[2]) is int for row in calls))
            return calls
    def test_new_owned_gates_and_exact_installed_ack_precede_every_real_slot(self):
        calls=self.simulate()
        self.assertEqual([v[1] for v in calls[:5]],list(n.OWNED_CASES[:5]))
        self.assertEqual(calls[5],('capture','browser','owned'))
    def test_failed_owned_gate_never_calls_ack_or_real_capture(self):self.simulate(bad_gate='http-expiry')
    def test_wrong_owned_zip_never_consumes_real_batch_marker(self):self.simulate(bad_ack=True)
    def test_accounting_cannot_lose_a_previous_email_request_slot(self):self.simulate(accounting_regression=True)

class Descriptors(unittest.TestCase):
    def test_only_stable_readonly_single_link_owner_0400_data_descriptor(self):
        with tempfile.TemporaryDirectory() as d:
            real_fstat=os.fstat
            def enrolled_metadata(fd):
                info=real_fstat(fd)
                fields={k:getattr(info,k) for k in ['st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns',
                    'st_mode','st_uid','st_nlink']};fields['st_uid']=1000
                return SimpleNamespace(**fields)
            def read_enrolled(fd):
                # Ownership is an explicit inert seam on CI runners whose UID
                # differs from this deployment's fixed1000. All descriptor,
                # mode, link count and stable-byte checks use actual files.
                with patch.object(p.os,'fstat',side_effect=enrolled_metadata):return p.ack_descriptor(fd)
            path=Path(d)/'data';path.write_bytes(b'not an authority');path.chmod(0o400)
            fd=os.open(path,os.O_RDONLY)
            try:self.assertEqual(read_enrolled(fd),path.read_bytes())
            finally:os.close(fd)
            path.chmod(0o600);fd=os.open(path,os.O_RDWR)
            try:
                with self.assertRaisesRegex(ValueError,'ack_descriptor'):read_enrolled(fd)
            finally:os.close(fd)
            path.chmod(0o400)
            os.link(path,Path(d)/'second');fd=os.open(path,os.O_RDONLY)
            try:
                with self.assertRaisesRegex(ValueError,'ack_descriptor'):read_enrolled(fd)
            finally:os.close(fd)
    def test_scope_requires_live_controller_identity_operator_and_expiry(self):
        approval={'schema':'paw-mail-native-single-batch-v1','batch_id':B,'release_sha':R,
                  'policy':dict(n.POLICY),'expires_at':1000,'controller_pid':321,'controller_identity':'456'}
        identity=ModuleType('benign_guest_validation');identity.process_identity=lambda _: '456'
        host=SimpleNamespace(trusted_directory=lambda _:nullcontext(123),private_json=lambda *_:{},
            contract=SimpleNamespace(policy=Mock()),enrollment_complete=lambda _:True,revoked=lambda _:False)
        for mode in ['valid','dead','reused','expired','revoked','policy_expired']:
            value=copy.deepcopy(approval)
            props=b'MainPID=321\nActiveState=active\n'
            if mode=='dead':props=b'MainPID=0\nActiveState=inactive\n'
            if mode=='expired':value['expires_at']=99
            with patch.object(n,'root'),patch.object(n,'protected',return_value=n.canonical(value)), \
                 patch.object(n.time,'time',return_value=100),patch.object(n,'installed_host',return_value=host), \
                 patch.dict(sys.modules,{'benign_guest_validation':identity}),patch.object(sys,'path',list(sys.path)), \
                 patch.object(n.subprocess,'check_output',return_value=props.decode()), \
                 patch.object(identity,'process_identity',return_value='other' if mode=='reused' else '456'), \
                 patch.object(host,'revoked',return_value=mode=='revoked'), \
                 patch.object(host.contract,'policy',side_effect=ValueError('expired policy') if mode=='policy_expired' else None):
                if mode=='valid':self.assertEqual(n.scope(R,B),approval)
                else:
                    with self.subTest(mode=mode),self.assertRaises(ValueError):n.scope(R,B)

if __name__=='__main__':unittest.main()
