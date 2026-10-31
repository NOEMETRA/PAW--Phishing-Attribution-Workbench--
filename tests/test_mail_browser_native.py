"""Native controller data boundaries and exact custody bytes, never HostRoot."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch
import blake3
from paw.core import mail_browser_native as n, mail_browser_public as p
from paw.core import mail_browser_custody as custody
from paw.core import mail_browser_owned as owned
from paw.core.evidence import EXCLUDED
from test_mail_browser_owned import owned_case
from test_synthetic_bridge import inventory

B='a'*32;R='b'*40;J='c'*32;E='d'*32

def hashed(raw):return blake3.blake3(raw).hexdigest()
def b64(raw):return base64.b64encode(raw).decode('ascii')

class NativeData(unittest.TestCase):
    def test_native_master_requires_actual_deadline_no_inet_and_exact_resource_unit(self):
        valid={'MainPID':'321',**n.MASTER_PROPERTIES};n.validate_master_unit(valid,321)
        for change in [{'MainPID':'0'},{'RuntimeMaxUSec':'infinity'},{'NoNewPrivileges':'no'},
            {'RestrictAddressFamilies':'AF_INET AF_NETLINK AF_UNIX'},{'Type':'simple'},
            {'KillMode':'process'},{'MemoryMax':str(512*1024**2)},{'TasksMax':'64'},
            {'RuntimeRandomizedExtraUSec':'1s'},{'ActiveState':'inactive'},{'extra':'allowed'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):n.validate_master_unit({**valid,**change},321)
    def test_existing_owned_baseline_keeps_its_legacy_newline_context_digest(self):
        from paw.core import browser_owned_broker as existing,browser_bridge
        context={'inert':'owned context'}
        value={'schema':'paw-owned-brokered-browser-v1','result':'PASS','release_sha':R,'job':J,
            'context_sha256':p.sha(browser_bridge.canonical(context)),'writers_stopped':True,'host_restored':True,
            'stop_ns':1,'kernel_component':{'result':'PASS'},'guest':{'status':'completed',
                'sandbox':{k:True for k in owned.SANDBOX}},
            'programs':{name:p.sha(p.HERE.with_name(name).read_bytes()) for name in existing.PROGRAMS}}
        raw=p.canonical(value)
        with patch.object(n,'protected',return_value=raw):
            self.assertEqual(p.verify_baseline(J,R,{'browser':context}),p.sha(raw))
    def bundle(self):
        assets={k:('inert fixed asset '+k).encode() for k in n.ASSETS}
        value={'schema':'paw-mail-native-bundle-v1','state':'NATIVE_CONDITIONAL_APPROVAL_REQUESTED',
            'release_sha':R,'created_at':100,'expires_at':1000,'owner_uid':1000,'batch_id':B,
            'batch_expires_at':2000,'policy':dict(n.POLICY),'requests_b64':[b64(b'no authority')]*3,
            'assets_b64':{k:b64(v) for k,v in assets.items()},'uplink':{k:'inert' for k in [
                'interface','mac','host_ipv4','next_hop','connection_uuid','bssid']},
            'owned_request_b64':b64(b'no authority'),'baseline_job':J}
        return value,{k:(len(v),n.sha(v)) for k,v in assets.items()}
    def test_native_data_verifies_exact_assets_but_creates_no_authority_or_network(self):
        value,assets=self.bundle();raw=n.canonical(value)
        with patch.object(n,'ASSETS',assets),patch('socket.socket',side_effect=AssertionError('network forbidden')):
            parsed,decoded,requests=n.validate_bundle(raw,n.sha(raw),now=100)
        self.assertEqual(parsed,value);self.assertEqual(len(decoded),3);self.assertEqual(requests,[b'no authority']*3)
    def test_bool_expiry_policy_asset_and_extra_fields_refuse(self):
        value,assets=self.bundle()
        for change in [{'created_at':True},{'owner_uid':True},{'expires_at':100},
                       {'batch_expires_at':100000},{'policy':{**n.POLICY,'public_hosts_batch':9}},
                       {'requests_b64':['eA==']*4},{'assets_b64':{}},{'extra':'approved'}]:
            raw=n.canonical({**value,**change})
            with self.subTest(change=change),patch.object(n,'ASSETS',assets),self.assertRaises(ValueError):
                n.validate_bundle(raw,n.sha(raw),now=100)
        raw=n.canonical(value)
        with patch.object(n,'ASSETS',assets):
            for bad in [raw+b'\n',b'{"x":1,"x":2}']:
                with self.assertRaises(ValueError):n.validate_bundle(bad,n.sha(bad),now=100)
            with self.assertRaises(ValueError):n.validate_bundle(raw,'0'*64,now=100)
    def test_workspace_cannot_enter_root_or_load_host_hash_extension(self):
        with self.assertRaisesRegex(ValueError,'immutable_root_only'):n.root(R)
        with self.assertRaisesRegex(ValueError,'hash_root_ABI'):n.load_hasher()
    def test_source_selection_cannot_change_when_clock_and_nonce_regenerate(self):
        with tempfile.TemporaryDirectory() as d:
            case=owned_case(Path(d));raw=custody.prepare(case,0);request=json.loads(raw)
            approval={'owned_request_b64':b64(raw),'owned_selection':custody.selection(request)}
            with patch.object(n,'load_hasher',return_value=hashed):
                a=n.materialize(approval,'owned');b=n.materialize(approval,'owned')
                self.assertNotEqual(a['request_id'],b['request_id'])
                self.assertEqual(custody.selection(a),custody.selection(b))
                approval['owned_selection']['source_sha256']='0'*64
                with self.assertRaisesRegex(ValueError,'protected_authority'):n.materialize(approval,'owned')
                for slot in [True,3,-1,'other']:
                    with self.assertRaises(ValueError):n.materialize(approval,slot)

class ExactCustody(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.case=owned_case(self.root);self.before=inventory(self.case)
        self.request=json.loads(custody.prepare(self.case,0))
    def tearDown(self):self.tmp.cleanup()
    def receipt(self,status='completed'):
        now=int(time.time())
        artifacts={'dom.html':b'harmless DOM','screenshot.png':b'opaque harmless PNG fixture','network.json':b'{}',
                   'body-00.bin':b''}
        value={'schema':'paw-real-mail-browser-result-v1','profile':custody.PROFILE,
            'producer_kind':'local-root-native-single-batch','batch_id':B,'slot':'owned','job':J,'nonce':E,
            'request_sha256':p.sha(p.canonical(self.request)),'source_sha256':self.request['source_sha256'],
            'snapshot_sha256':self.request['snapshot_sha256'],'case_reference':self.request['case_reference'],
            'status':status,'runtime':{'context_sha256':'1'*64,'image_sha256':'2'*64,'chrome_binary_sha256':'3'*64,
                'raw_attestation_sha256':p.sha(artifacts['network.json']),'release_sha':R,
                'vm_uuid':'00000000-0000-4000-8000-000000000001','admitted_at':now,'completed_at':now,
                'stop_ns':1,'writers_stopped':True,'host_restored':True,'network_stopped_before_capture':True,
                'mode':'owned-browser','sandbox':{k:True for k in owned.SANDBOX}},
            'artifacts':[{'name':k,'bytes':len(v),'sha256':p.sha(v)} for k,v in artifacts.items()]}
        return value,artifacts
    def payload(self,files):
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as out:
            for name,raw in files.items():out.writestr('result/'+name,raw)
        return {'schema':'paw-mail-native-owned-custody-ack-v1','batch_id':B,
                'sidecar_b64':{k:b64(v) for k,v in files.items()},'zip_b64':b64(archive.getvalue())}
    def sealed(self):
        receipt,artifacts=self.receipt()
        expected={'request.json':p.canonical(self.request),'receipt.json':p.canonical(receipt),
                  'result.json':p.sidecar_result(self.request,receipt),**artifacts}
        output=self.root/'sidecar';key=(self.case.stat().st_dev,self.case.stat().st_ino)
        with owned._output(output,self.case) as (fd,key):
            pending=owned._new_directory(fd,'pending',key)
            try:
                for name,raw in expected.items():owned._write(pending,name,raw,key)
                owned._seal_fd(pending,expected,key);owned._publish(fd,pending)
            finally:os.close(pending)
        files={q.relative_to(output/'result').as_posix():q.read_bytes()
               for q in (output/'result').rglob('*') if q.is_file()}
        return expected,files
    def test_actual_seal_and_zip_bytes_match_root_independent_reader(self):
        expected,files=self.sealed();raw=p.canonical(self.payload(files))
        result=p.validate_ack(raw,B,expected,hashed)
        self.assertEqual(result['sidecar_files'],len(files));self.assertEqual(inventory(self.case),self.before)
    def test_self_consistent_changed_sidecar_is_not_the_protected_expected_capture(self):
        expected,files=self.sealed()
        files['dom.html']=b'x'*len(files['dom.html'])
        index={k:hashed(v) for k,v in sorted(files.items()) if k not in {
            'evidence/merkle_index.json','evidence/merkle_root.bin'}}
        files['evidence/merkle_index.json']=json.dumps(index,indent=2).encode()
        files['evidence/merkle_root.bin']=hashed(''.join(index.values()).encode()).encode()
        with self.assertRaisesRegex(ValueError,'sidecar_changed'):
            p.validate_ack(p.canonical(self.payload(files)),B,expected,hashed)
    def test_wrong_root_zip_added_file_wrong_batch_boolean_receipt_and_unknown_stop_refuse(self):
        expected,files=self.sealed()
        for mutate in ['root','zip','extra','batch']:
            changed=dict(files);value=self.payload(changed)
            if mutate=='root':value['sidecar_b64']['evidence/merkle_root.bin']=b64(b'0'*64)
            if mutate=='zip':
                altered={**files,'dom.html':b'wrong'};value['zip_b64']=self.payload(altered)['zip_b64']
            if mutate=='extra':value['sidecar_b64']['outside']=b64(b'x')
            if mutate=='batch':value['batch_id']='f'*32
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):
                p.validate_ack(p.canonical(value),B,expected,hashed)
        value,_=self.receipt()
        p.validate_receipt(p.canonical(value),self.request,B,'owned')
        for changed in [{**value,'slot':True},{**value,'status':'safe'},
                        {**value,'runtime':{**value['runtime'],'stop_ns':True}},
                        {**value,'runtime':{**value['runtime'],'writers_stopped':False}},
                        {**value,'runtime':{**value['runtime'],'network_stopped_before_capture':False}}]:
            with self.assertRaises(ValueError):p.validate_receipt(p.canonical(changed),self.request,B,'owned')
    def test_real_client_prepare_is_offline_and_never_launches_or_changes_parent(self):
        with patch('socket.socket',side_effect=AssertionError('network forbidden')):
            value=p.client_prepare(self.case,0,self.root/'prepared')
        self.assertFalse(value['execution_authorized']);self.assertEqual(inventory(self.case),self.before)
        raw=Path(value['request']).read_bytes();custody.validate(raw,hashed)
    def test_compiled_refusals_are_explicitly_inert(self):
        for case in n.OWNED_CASES[5:-1]:
            with patch('socket.socket',side_effect=AssertionError('network forbidden')):
                result=p.run_contract(case)
            self.assertEqual(result['result'],'PASS');self.assertIn('Inert',result['scope'])

if __name__=='__main__':unittest.main()
