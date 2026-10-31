"""Fixed-owned data custody; no Root, VM, capture, sample URL or resolver."""
import base64
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import uuid

import blake3
from paw.core import mail_browser_owned as m
from paw.core.evidence import seal_case
from paw.core.network_policy import EgressDenied
from paw.core.verify import verify_case
from test_synthetic_bridge import make_case,inventory


def owned_case(root):
    case=make_case(root);(case/'original.eml').unlink();(case/'input.eml').write_bytes(m.SOURCE)
    manifest=json.loads((case/'manifest.json').read_bytes());manifest.update(case_id='ownedfixture',
        inputs=[{'path':'input.eml','size':len(m.SOURCE),'blake3':blake3.blake3(m.SOURCE).hexdigest()}])
    (case/'manifest.json').write_text(json.dumps(manifest));(case/'execution.json').write_text('{"status":"completed","no_egress":true}')
    (case/'url_evidence.json').write_text(json.dumps([{'url':m.SEED,'network_target':True}]))
    (case/'score.json').write_text('{"verdict":"Inconclusive","score":0.05}')
    seal_case(case);return case


def receipt(request,artifacts):
    return {'schema':'paw-owned-mail-browser-result-v1','profile':m.PROFILE,
        'producer_kind':'local-root-fixed-owned-browser','parent_validation':m.PARENT_SCOPE,
        'request_id':request['request_id'],'request_sha256':m.digest(m.canonical(request)),
        'source_sha256':m.digest(m.SOURCE),'snapshot_sha256':request['snapshot_sha256'],
        'status':'completed','fixture_nonce':'e'*32,
        'runtime':{'release_sha':'a'*40,'job':'b'*32,'vm_uuid':str(uuid.uuid4()),
            'context_sha256':'1'*64,'image_sha256':'2'*64,'chrome_binary_sha256':'3'*64,
            'raw_attestation_sha256':'4'*64,'admitted_at':request['created_at'],
            'completed_at':request['created_at'],'stop_ns':1234,'writers_stopped':True,
            'host_restored':True,'real_connections':0,'sandbox':{k:True for k in m.SANDBOX}},
        'artifacts':[{'name':n,'bytes':len(b),'sha256':m.digest(b)}for n,b in artifacts.items()]}


class OwnedMail(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.case=owned_case(self.root)
        self.before=inventory(self.case)
    def tearDown(self):self.tmp.cleanup()
    def request(self):
        info=m.prepare(self.case,self.root/'request');raw=Path(info['request']).read_bytes()
        return m.validate_request(raw),raw,info
    def test_actual_sealed_parent_exact_source_and_url_with_no_authority(self):
        v,raw,info=self.request();self.assertFalse(info['execution_authorized']);self.assertEqual(v['execution_authority'],'none')
        self.assertEqual(base64.b64decode(v['source_b64']),m.SOURCE);self.assertEqual(v['url'],m.SEED)
        self.assertEqual(inventory(self.case),self.before);self.assertEqual(Path(info['request']).stat().st_mode&0o777,0o400)
    def test_foreign_source_or_seed_refuses_even_if_resealed(self):
        for name,body in [('input.eml',b'From: real@other.invalid\r\n\r\nother'),('url_evidence.json',b'[{"url":"https://other.invalid/","network_target":true}]')]:
            with tempfile.TemporaryDirectory()as d:
                case=owned_case(Path(d));(case/name).write_bytes(body);seal_case(case)
                with self.assertRaises(ValueError):m.prepare(case,Path(d)/'output')
                self.assertFalse((Path(d)/'output').exists())
    def test_bounded_request_rejects_changed_fields_parent_pieces_and_clock(self):
        v,raw,_=self.request()
        changes=[{'execution_authority':'approved'},{'request_id':'../x'},{'url_index':True},
            {'created_at':True},{'expires_at':v['created_at']+901},{'limits':{**m.LIMITS,'browser_seconds':True}},
            {'source_sha256':'0'*64},{'source_b64':base64.b64encode(b'other').decode()},
            {'case_reference':{**v['case_reference'],'manifest_sha256':'0'*64}},
            {'pieces_b64':{**v['pieces_b64'],'manifest.json':'AA=='}}]
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_request(m.canonical({**v,**change}))
        for raw in [b'{"schema":1,"schema":2}',b'x'*(m.REQUEST_MAX+1)]:
            with self.assertRaises(ValueError):m.validate_request(raw)
    def test_live_parent_changed_seal_and_inside_output_refuse(self):
        with self.assertRaises(ValueError):m.prepare(self.case,self.case/'output')
        supervisor=self.root/'jobs/analysis_ownedfixture/supervisor.json';supervisor.write_text('{"tree_stopped":false}')
        with self.assertRaises(RuntimeError):m.prepare(self.case,self.root/'output')
        supervisor.write_text('{"tree_stopped":true}');(self.case/'score.json').write_text('changed')
        with self.assertRaises(ValueError):m.prepare(self.case,self.root/'output')
    def test_completed_requires_all_artifacts_known_stop_and_strict_scope(self):
        v,_,_=self.request();artifacts={'dom.html':b'owned dom','screenshot.png':b'owned png','network.json':b'{}'}
        good=receipt(v,artifacts);self.assertEqual(m.validate_receipt(m.canonical(good),v)['status'],'completed')
        for key,value in [('writers_stopped',False),('host_restored',False),('stop_ns',True),('stop_ns',12*10**9),
            ('real_connections',True),('real_connections',1),('release_sha','a'*7),('sandbox',{k:False for k in m.SANDBOX})]:
            bad=copy.deepcopy(good);bad['runtime'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):m.validate_receipt(m.canonical(bad),v)
        for change in [{'request_sha256':'0'*64},{'profile':'public'},{'parent_validation':'Root verified BLAKE3'},
            {'artifacts':good['artifacts'][:1]},{'artifacts':[good['artifacts'][0]]*3},
            {'artifacts':[{'name':'../x','bytes':1,'sha256':'0'*64}]}]:
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_receipt(m.canonical({**good,**change}),v)
    def test_partial_known_terminal_results_are_preserved_without_success_claim(self):
        v,_,_=self.request()
        for status in ['failed','timeout','cancelled','refused']:
            value=receipt(v,{'dom.html':b'partial'});value['status']=status;value['runtime']['sandbox']={k:False for k in m.SANDBOX}
            self.assertEqual(m.validate_receipt(m.canonical(value),v)['status'],status)
    def test_unprotected_user_export_cannot_claim_Root_receipt(self):
        v,_,info=self.request();prefix=self.root/'exports';(prefix/('mail-browser-owned-'+v['request_id'])).mkdir(parents=True)
        with patch.object(m,'EXPORT_ROOT',prefix),self.assertRaises(ValueError):m.import_result(self.case,info['request'],self.root/'out')
        self.assertFalse((self.root/'out').exists())
    def test_import_actual_seal_and_unchanged_parent_with_only_producer_trust_boundary_substituted(self):
        v,raw,info=self.request();folder=self.root/'inert-export';folder.mkdir()
        bodies={'dom.html':b'<p>owned</p>','screenshot.png':b'uninterpreted PNG fixture','network.json':b'{"scope":"inert"}'}
        value=receipt(v,bodies)
        for n,b in {**bodies,'request.json':raw,'receipt.json':m.canonical(value)}.items():(folder/n).write_bytes(b)
        @contextmanager
        def trusted(_):
            fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
            try:yield fd
            finally:os.close(fd)
        actual_read=m.shared._read_regular
        def read(*args,**kwargs):kwargs.pop('root_owned',None);return actual_read(*args,**kwargs)
        with patch.object(m,'trusted_export',trusted),patch.object(m.shared,'_read_regular',side_effect=read):
            result=m.import_result(self.case,info['request'],self.root/'out')
        sidecar=Path(result['result']);self.assertTrue(verify_case(sidecar));self.assertEqual(inventory(self.case),self.before)
        self.assertEqual((sidecar/'dom.html').read_bytes(),bodies['dom.html'])
        with self.assertRaises(ValueError):m.import_result(self.case,info['request'],self.root/'out')
    def test_prepare_and_import_apply_application_no_egress_policy(self):
        with patch.object(m,'_case_snapshot',side_effect=lambda *_:socket.socket()):
            for call in [lambda:m.prepare(self.case,self.root/'out'),lambda:m.import_result(self.case,'request',self.root/'out')]:
                with self.assertRaises(EgressDenied):call()

if __name__=='__main__':unittest.main()
