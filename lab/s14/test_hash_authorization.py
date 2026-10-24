"""Inert generic hash grants: no privileged guest or sample execution."""
import contextlib
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import hash_authorization as auth
import hash_offline_adapter as adapter
from offline_candidate import canonical
from test_one_use_authorization import context as old_context,frame,FakeGate
from owned_grant_fixtures import SOURCES


def context():
    host=old_context();host['packages']['qemu-system-x86']=auth.VERSION
    host['source_hashes'].update({name:'b'*64 for name in ['hash_authorization.py','hash_offline_adapter.py','hash_offline_matrix.py','verify_hash_offline.py']})
    return {'host':host,'qemu_binary_sha256':'c'*64,'ksm_run':'1','dpkg_inventory_sha256':'d'*64,
            'qemu_components':{n:auth.VERSION for n in auth.COMPONENTS},'host_identity_sha256':'e'*64,
            'cpu_signature':{k:'owned' for k in ['vendor_id','cpu family','model','stepping','microcode']}}


def maintenance(ctx):
    return canonical({'schema':'paw-s14-maintenance-v2','packages':ctx['host']['packages'],'kernel':ctx['host']['kernel'],
       'image_sha256':auth.fs.IMAGE_SHA256,'qemu_binary_sha256':ctx['qemu_binary_sha256'],
       'dpkg_inventory_sha256':ctx['dpkg_inventory_sha256'],'qemu_components':ctx['qemu_components'],
       'host_identity_sha256':ctx['host_identity_sha256'],'cpu_signature':ctx['cpu_signature'],
       'vendor_manifest_sha256':'6cd96c00a9a7f3b77233af758968d94e83f9cec396a1b5035ccd8688a26aa804',
       'vendor_signer':'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81','guest_kernel_release':'6.8.0-147-generic',
       'reboot_required':False,'review_notes':'Owned inert test context; not actual root maintenance evidence'})


def readiness(ctx,maint):
    now=int(time.time())
    return canonical({'schema':'paw-s14-i08-readiness-v2','context_sha256':auth.digest(canonical(ctx)),
       'maintenance_sha256':auth.digest(maint),'reviewed_head':'a'*40,
       'review_url':'https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/108#issuecomment-1',
       'ci_runs':[100,200],'ci_successful_jobs':7,'created_at':now,'expires_at':now+86400,
       'decision':'ready-for-explicit-single-hash-offline-python-grants'})


@contextlib.contextmanager
def authority():
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);(root/'legacy').mkdir(mode=0o700);(root/'v2').mkdir(mode=0o700)
        @contextlib.contextmanager
        def opened(path=auth.fs.ROOT):
            target=root/('v2' if path==auth.ROOT else 'legacy');fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:auth.fs.trusted(os.fstat(fd),True);yield fd
            finally:os.close(fd)
        with patch.object(auth.fs,'root_directory',opened),patch.object(auth.fs,'OWNER_UID',os.getuid()),patch.object(auth.os,'geteuid',return_value=0),patch.object(adapter.shutil,'disk_usage',return_value=SimpleNamespace(free=20*1024**3)):
            ctx=context();maint=maintenance(ctx)
            with auth.store() as fd:auth.fs.exclusive(fd,'maintenance-'+auth.digest(maint)+'.json',maint)
            yield root,ctx,maint


def make_policy(ctx,maint,hashes,**kwargs):
    if kwargs.get('mode','validation')=='validation':kwargs.setdefault('validation_manifest_sha256','f'*64)
    return auth.make_policy(ctx,maint,hashes,**kwargs)


def install_policy(policy):
    with auth.store() as fd:auth.fs.exclusive(fd,'policy-'+auth.digest(policy)+'.json',policy)


class FakeHash(adapter.HashGate):
    __init__=FakeGate.__init__;start=FakeGate.start;stop=FakeGate.stop;call=FakeGate.call


class HashAuthority(unittest.TestCase):
    def test_low_disk_refuses_before_consumption_or_vm(self):
        with authority() as (root,ctx,maint),patch.object(adapter.shutil,'disk_usage',return_value=SimpleNamespace(free=0)):
            source=b"print('owned capacity test')\n";raw=frame(source=source)
            policy=make_policy(ctx,maint,[auth.digest(source)]);install_policy(policy);auth.issue(raw,policy,ctx)
            gate=FakeHash(root/'out');gate.output.mkdir()
            with self.assertRaisesRegex(ValueError,'host_disk_admission'):adapter.run_hash_granted(gate,raw,policy)
            self.assertEqual(gate.starts,0);self.assertFalse((root/'v2/consumed').exists())

    def test_novel_source_not_in_catalogue_executes_only_via_exact_hash_grant(self):
        with authority() as (root,ctx,maint),patch.object(auth,'capture',return_value=ctx):
            marker=root/'must-not-exist';source=("from pathlib import Path\nPath("+repr(str(marker))+").write_text('never on host')\n").encode()
            self.assertNotIn(source,SOURCES.values());raw=frame(source=source)
            policy=make_policy(ctx,maint,[auth.digest(source)]);install_policy(policy)
            gate=FakeHash(root/'out');gate.output.mkdir()
            with self.assertRaises(FileNotFoundError):adapter.run_hash_granted(gate,raw,policy)
            self.assertEqual(gate.starts,0)
            auth.issue(raw,policy,ctx);result=adapter.run_hash_granted(gate,raw,policy)
            self.assertEqual(result['execution_purpose'],'validation');self.assertEqual(gate.starts,1)
            self.assertFalse(marker.exists()) # Stub lifecycle did not evaluate source.
            other=FakeHash(root/'other');other.output.mkdir()
            with self.assertRaises(FileExistsError):adapter.run_hash_granted(other,raw,policy)
            self.assertEqual(other.starts,0)

    def test_unapproved_hash_and_frame_mutation_refuse_without_consumption(self):
        with authority() as (root,ctx,maint),patch.object(auth,'capture',return_value=ctx):
            source=b"print('a novel approved harmless input')\n";raw=frame(source=source)
            policy=make_policy(ctx,maint,[auth.digest(source)]);install_policy(policy)
            with self.assertRaisesRegex(ValueError,'source_not_explicitly_approved'):auth.issue(frame('e'*32,b"print('different')\n"),policy,ctx)
            auth.issue(raw,policy,ctx);value=json.loads(raw);value['provenance']['reference']='changed claim'
            gate=FakeHash(root/'out');gate.output.mkdir()
            with self.assertRaisesRegex(ValueError,'hash_grant_binding:frame_sha256'):adapter.run_hash_granted(gate,canonical(value),policy)
            self.assertEqual(gate.starts,0);self.assertFalse((root/'v2/consumed').exists())

    def test_real_analysis_requires_installed_current_review_and_ci_receipt(self):
        with authority() as (root,ctx,maint):
            source=b"print('owned stand-in, never a real sample')\n"
            with self.assertRaisesRegex(ValueError,'readiness'):make_policy(ctx,maint,[auth.digest(source)],mode='sample-analysis')
            ready=readiness(ctx,maint);policy=make_policy(ctx,maint,[auth.digest(source)],mode='sample-analysis',readiness_raw=ready)
            install_policy(policy)
            with self.assertRaises(FileNotFoundError):auth.issue(frame(source=source),policy,ctx)
            with auth.store() as fd:auth.fs.exclusive(fd,'readiness-'+auth.digest(ready)+'.json',ready)
            grant=auth.issue(frame(source=source),policy,ctx);self.assertEqual(grant['execution_purpose'],'sample-analysis')
            # This test only issued metadata; never runs even the harmless stand-in.
            self.assertFalse((root/'v2/consumed').exists())
            with self.assertRaises(ValueError):make_policy(ctx,maint,[auth.digest(source),'e'*64],mode='sample-analysis',readiness_raw=ready)

    def test_review_ci_expiry_and_maintenance_mismatches_fail_closed(self):
        ctx=context();maint=maintenance(ctx);ready=readiness(ctx,maint)
        for key,value in [('context_sha256','0'*64),('maintenance_sha256','0'*64),('ci_successful_jobs',6),
                          ('reviewed_head','a'),('review_url','https://evil.invalid/'),('expires_at',int(time.time())-1)]:
            changed=json.loads(ready);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):auth.validate_readiness(canonical(changed),ctx,maint)
        for key,value in [('reboot_required',True),('qemu_binary_sha256','0'*64),('guest_kernel_release','other')]:
            changed=json.loads(maint);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):auth.validate_maintenance(canonical(changed),ctx)
        changed=copy.deepcopy(ctx);changed['host']['packages']['qemu-system-x86']='old'
        with self.assertRaisesRegex(ValueError,'baseline'):auth.validate_context(changed)

    def test_faults_consume_forever_without_quarantine(self):
        for fault in ['startup','owner-loss','malformed-output','unknown-stop']:
            with self.subTest(fault=fault),authority() as (root,ctx,maint),patch.object(auth,'capture',return_value=ctx):
                source=b"print('another novel owned fixture')\n";raw=frame(source=source)
                policy=make_policy(ctx,maint,[auth.digest(source)]);install_policy(policy);auth.issue(raw,policy,ctx)
                gate=FakeHash(root/'out',fault);gate.output.mkdir()
                with self.assertRaises((ValueError,TimeoutError)):adapter.run_hash_granted(gate,raw,policy)
                self.assertEqual(gate.stops,1);self.assertIsNone(gate.active_vm)
                self.assertFalse(any(gate.output.glob('*-quarantine')))
                with self.assertRaises(FileExistsError):auth.consume(raw,policy,ctx)

    def test_changed_effective_context_after_boot_stops_before_publication(self):
        with authority() as (root,ctx,maint):
            source=b"print('a harmless context-change test')\n";raw=frame(source=source)
            policy=make_policy(ctx,maint,[auth.digest(source)]);install_policy(policy);auth.issue(raw,policy,ctx)
            changed=copy.deepcopy(ctx);changed['host']['kernel']='other'
            gate=FakeHash(root/'out');gate.output.mkdir()
            with patch.object(auth,'capture',side_effect=[ctx,changed]),self.assertRaises(ValueError):adapter.run_hash_granted(gate,raw,policy)
            self.assertEqual(gate.stops,1);self.assertFalse(any(gate.output.glob('*-quarantine')))

    def test_legacy_policy_cannot_be_promoted_to_hash_authority(self):
        ctx=context();maint=maintenance(ctx)
        with self.assertRaises(ValueError):auth.validate_policy(canonical(auth.fs.make_policy(ctx['host'])),ctx,maint)
        policy=json.loads(make_policy(ctx,maint,['a'*64]));policy['mode']='sample-analysis';policy['readiness_sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'readiness'):auth.validate_policy(canonical(policy),ctx,maint)

    def test_post_stop_context_change_refuses_publication_and_retains_consumption(self):
        with authority() as (root,ctx,maint):
            source=b"print('owned post-stop check')\n";raw=frame(source=source)
            policy=make_policy(ctx,maint,[auth.digest(source)]);install_policy(policy);auth.issue(raw,policy,ctx)
            other=copy.deepcopy(ctx);other['dpkg_inventory_sha256']='0'*64
            gate=FakeHash(root/'out');gate.output.mkdir()
            with patch.object(auth,'capture',side_effect=[ctx,ctx,other]),self.assertRaises(ValueError):adapter.run_hash_granted(gate,raw,policy)
            self.assertEqual(gate.stops,1);self.assertFalse(any(gate.output.glob('*-quarantine')))
            with self.assertRaises(FileExistsError):auth.consume(raw,policy,ctx)


if __name__=='__main__':unittest.main()
