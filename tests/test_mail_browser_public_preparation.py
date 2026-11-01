"""Actual fixed preparation/guard paths with all Root/PID1/network effects inert."""
from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from paw.core import mail_browser_public as m

J='1'*32;E='2'*32;R='3'*40
class Preparation(unittest.TestCase):
    def test_guard_never_inspects_denied_PID1_link_and_still_refuses_wrong_namespace(self):
        for mode,observed,expected in [('public',10,10),('owned-raw',99,99),('public',99,10),('owned-raw',10,99)]:
            with self.subTest(mode=mode,observed=observed),tempfile.TemporaryDirectory()as d:
                ids=m.identity(J,E,R);ids['directory']=d
                cfg={'mode':mode,'interface':'lo','source_addresses':['9.9.9.9'],
                     'namespace_inode':expected,'host_namespace_inode':10}
                def stat(path,*args,**kwargs):
                    if str(path)=='/proc/1/ns/net':raise PermissionError('PID1 link inaccessible to the bounded role')
                    if str(path)=='/proc/self/ns/net':return SimpleNamespace(st_ino=observed)
                    return os.stat_result((0,)*10)
                selector=SimpleNamespace(register=lambda *a:None,select=lambda _: [True],close=lambda:None)
                value=SimpleNamespace(buffer=io.BytesIO(m.canonical({'op':'stop','epoch':E,'id':0})+b'\n'))
                with patch.object(m,'root_config',return_value=(ids,cfg)),patch.object(m.os,'stat',side_effect=stat), \
                     patch.object(m.kernel,'nft')as nft,patch.object(m,'guard_identity',return_value='same'), \
                     patch.object(m.kernel,'status',return_value={}),patch.object(m.kernel,'emit'), \
                     patch.object(m.signal,'signal'),patch.object(m.sys,'stdin',value), \
                     patch.object(m.selectors,'DefaultSelector',return_value=selector),patch.object(m,'revoke_role'):
                    if observed==expected and (observed==10)==(mode=='public'):
                        m.keeper(J,E,R)
                        self.assertEqual(json.loads((Path(d)/'owner-result.json').read_bytes())['reason'],'requested_stop')
                    else:
                        with self.assertRaisesRegex(ValueError,'exact_namespace'):m.keeper(J,E,R)
                        nft.assert_not_called()

    def exercise(self,failure=False,cleanup_failure=False):
        with tempfile.TemporaryDirectory()as d:
            actor=SimpleNamespace(unit=m.identity(J,E,R)['keeper'],process=SimpleNamespace(poll=lambda:1),
                                  errors=bytearray(b'actual bounded role stderr'),observation=None)
            prepared=SimpleNamespace(fixture_configured=True,server_live=True,worker_live=False,ready=False,
                poll=Mock(side_effect=ValueError('inert role failure')if failure else None,return_value=True))
            def create(*args,**kwargs):args[4].append(actor);return prepared
            exported=[]
            modules={'one_use_authorization':SimpleNamespace(execution_lock=lambda:nullcontext()),
                'reader_export':SimpleNamespace(publish_reader_tree=lambda path:exported.append(path)),
                'vm_runtime_revalidation':SimpleNamespace(snapshot=lambda:{'same':True},network_state=lambda:{'same':True})}
            with patch.dict(sys.modules,modules),patch.object(m,'HERE',Path('/opt/paw-vm/releases')/R/'paw/core/mail_browser_public.py'), \
                 patch.object(m.os,'geteuid',return_value=0),patch.object(m,'PROGRAMS',()), \
                 patch.object(m,'EXPORT_ROOT',Path(d)),patch.object(m,'require_idle'), \
                 patch.object(m,'prepare_network')as prepare,patch.object(m,'NetworkPreparation',side_effect=create), \
                 patch.object(m.kernel,'cleanup_actors',side_effect=ValueError('unknown stop')if cleanup_failure else None)as cleanup, \
                 patch.object(m.kernel,'vacant_ids'):
                if cleanup_failure:
                    with self.assertRaisesRegex(ValueError,'unknown stop'):m.owned_preparation(J,R)
                    self.assertEqual(exported,[]);return
                value=m.owned_preparation(J,R)
                self.assertEqual(prepare.call_args.args[3:],('owned-raw',{}))
                cleanup.assert_called_once_with([actor]);self.assertFalse(value['vm_started'])
                self.assertEqual(value['real_connections'],0);self.assertFalse(value['production_grants_enabled'])
                report=json.loads((Path(value['export'])/'attestation.json').read_bytes())
                self.assertEqual(report['roles'][0]['stderr'],'actual bounded role stderr')
                self.assertEqual(report['result'],'FAIL'if failure else 'PASS')
                self.assertEqual(len(exported),1)
                self.assertTrue(report['writers_stopped']);self.assertTrue(report['host_restored'])
    def test_fixed_owned_success_is_not_public_readiness(self):self.exercise()
    def test_failed_preparation_preserves_stopped_role_diagnostic(self):self.exercise(failure=True)
    def test_unknown_cleanup_cannot_publish_even_a_diagnostic(self):self.exercise(cleanup_failure=True)
    def test_unprivileged_probe_refuses_before_any_namespace_or_service(self):
        with patch.object(m.os,'geteuid',return_value=1000),patch.object(m,'prepare_network')as prepare:
            with self.assertRaisesRegex(ValueError,'snapshot'):m.owned_preparation(J,R)
            prepare.assert_not_called()

if __name__=='__main__':unittest.main()
