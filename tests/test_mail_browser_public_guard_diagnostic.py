"""Inert guard-read failure classification; no Root, sockets, PID1 or nft."""
import base64
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace as NS
import tempfile
import unittest
from unittest.mock import patch
from paw.core import mail_browser_public as m
J='1'*32;E='2'*32;R='3'*40

class GuardDiagnostic(unittest.TestCase):
    def test_actual_nft_wrapper_keeps_failure_and_bounded_stderr_without_retry(self):
        raw='inert read failure\n'+'x'*10000
        with patch.object(m.kernel.subprocess,'run',return_value=NS(returncode=1,stderr=raw,stdout='partial'))as run:
            with self.assertRaisesRegex(m.kernel.NftFailure,'^owned_kernel_nft_failed$')as caught:
                m.kernel.nft('-j','list','ruleset')
            self.assertEqual(run.call_count,1)
            self.assertEqual(run.call_args.args[0],['/usr/sbin/nft','-j','list','ruleset'])
        d=caught.exception.detail
        self.assertIsInstance(caught.exception,ValueError)
        self.assertEqual(d['stderr_bytes'],len(raw))
        self.assertEqual(d['stderr_sha256'],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(base64.b64decode(d['stderr_prefix_b64']),raw.encode()[:512])
        self.assertLess(len(m.canonical(d)),1000)
        with patch.object(m.kernel.subprocess,'run',return_value=NS(returncode=0,stderr='',stdout='same')):
            self.assertEqual(m.kernel.nft('-j','list','ruleset'),'same')

    def exercise(self,mode,error):
        with tempfile.TemporaryDirectory()as folder:
            ids=m.identity(J,E,R);ids['directory']=folder
            inode=99 if mode=='owned-raw'else 10
            cfg={'mode':mode,'interface':'lo','source_addresses':['9.9.9.9'],
                 'namespace_inode':inode,'host_namespace_inode':10}
            selector=NS(register=lambda *a:None,select=lambda _: [True],close=lambda:None)
            with patch.object(m,'root_config',return_value=(ids,cfg)), \
                 patch.object(m.os,'stat',return_value=NS(st_ino=inode)), \
                 patch.object(m.kernel,'nft',return_value=''),patch.object(m.kernel,'status',return_value={}), \
                 patch.object(m.kernel,'emit'),patch.object(m.signal,'signal'), \
                 patch.object(m.selectors,'DefaultSelector',return_value=selector), \
                 patch.object(m.sys,'stdin',NS(buffer=io.BytesIO())), \
                 patch.object(m,'guard_identity',side_effect=['same',error])as check, \
                 patch.object(m,'revoke_role',return_value=True)as revoke:
                m.keeper(J,E,R)
            check.assert_called();self.assertEqual(check.call_count,2,'No retry or continued control after unreadable rules')
            revoke.assert_called_once_with(J,E,R)
            self.assertTrue((Path(folder)/'revoked-complete').exists())
            return json.loads((Path(folder)/'owner-result.json').read_bytes())
    def test_nft_failure_is_loss_with_private_only_detail_not_a_changed_rule_assertion(self):
        e=m.kernel.NftFailure(NS(returncode=-31,stderr='inert SIGSYS',stdout=''))
        for mode in ['owned-raw','public']:
            with self.subTest(mode=mode):
                value=self.exercise(mode,e)
                self.assertEqual(value['reason'],'guard_changed');self.assertEqual(value['check_error'],'guard_nft_failed')
                if mode=='owned-raw':self.assertEqual(value['check_detail'],e.detail)
                else:self.assertNotIn('check_detail',value)
    def test_invalid_json_is_separate_from_unavailable_nft_or_changed_identity(self):
        for mode in ['owned-raw','public']:
            value=self.exercise(mode,json.JSONDecodeError('inert malformed reply','{',1))
            self.assertEqual(value['check_error'],'guard_json_invalid')
            if mode=='public':self.assertNotIn('check_detail',value)
            else:
                detail=value['check_detail']
                self.assertEqual(detail['position'],1);self.assertEqual(detail['json_bytes'],1)
                self.assertEqual(detail['json_sha256'],hashlib.sha256(b'{').hexdigest())
                self.assertEqual(base64.b64decode(detail['json_prefix_b64']),b'{')

if __name__=='__main__':unittest.main()
