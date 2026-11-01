"""Trusted binding bootstrap is inert here; no daemon, VM, network or Root."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
from types import ModuleType,SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch
import importlib.util
from paw.core import mail_browser_native as n,mail_browser_public as p
J='1'*32;R='3'*40
class Flags:
    def __init__(self,**values):self.real=sys.flags;self.values=values
    def __getattr__(self,name):return self.values.get(name,getattr(self.real,name))

class Bindings(unittest.TestCase):
    def exercise(self,*,change=False,path_change=False,source_error=False):
        saved_path=list(sys.path);calls=[]
        source=b'raise RuntimeError("inert source failure")'if source_error else b'import libvirtmod\nVALUE=42\n'
        def protected(path,cap,**kwargs):
            calls.append((path,cap,kwargs));return source if path.name=='libvirt.py'else b'changed'if change and len(calls)>2 else b'fixed extension'
        created={}
        def spec(name,path):
            def execute(module):
                self.assertEqual(name,'libvirtmod','Python cache/source loader must never execute')
                if path_change:sys.path.append('/inert/untrusted')
            return NS(name=name,origin=str(path),loader=NS(exec_module=execute))
        def module(spec):
            value=ModuleType(spec.name);value.__file__=spec.origin;created[spec.name]=value;return value
        with patch.dict(sys.modules),patch.object(n,'_libvirt_binding',None), \
             patch.object(n.sys,'flags',Flags(isolated=1,no_site=1)), \
             patch.object(n,'protected',side_effect=protected), \
             patch.object(importlib.util,'spec_from_file_location',side_effect=spec), \
             patch.object(importlib.util,'module_from_spec',side_effect=module):
            sys.modules.pop('libvirt',None);sys.modules.pop('libvirtmod',None)
            error=None;answer=None
            try:answer=n.system_libvirt()
            except (ValueError,RuntimeError)as e:error=str(e)
            if error:
                self.assertIsNone(n._libvirt_binding)
                self.assertNotIn('libvirt',sys.modules);self.assertNotIn('libvirtmod',sys.modules)
            else:
                self.assertEqual(answer[0].VALUE,42);self.assertIsNone(answer[0].__cached__)
                self.assertIs(answer[0],n.system_libvirt()[0])
                sys.modules['libvirt']=ModuleType('foreign')
                with self.assertRaisesRegex(ValueError,'module_changed'):n.system_libvirt()
            self.assertEqual(sys.path,saved_path,'Never retain an import-path expansion on failure')
        return answer,error,calls
    def test_only_two_fixed_root_files_direct_source_and_stable_extension(self):
        answer,error,calls=self.exercise();self.assertIsNone(error)
        self.assertEqual(len(calls),4)
        for path,cap,kwargs in calls:
            self.assertEqual(path.parent,n.SYSTEM_BINDINGS);self.assertEqual(cap,2*1024**2);self.assertEqual(kwargs,{'mode':0o644})
        self.assertEqual({x[0].name for x in calls},set(answer[1]))
        self.assertEqual(answer[1]['libvirt.py']['sha256'],hashlib.sha256(b'import libvirtmod\nVALUE=42\n').hexdigest())
    def test_changed_files_path_expansion_and_source_failure_refuse_and_clear_modules(self):
        for changes,reason in [({'change':True},'files_changed'),({'path_change':True},'import_paths'),({'source_error':True},'source failure')]:
            with self.subTest(changes=changes):self.assertIn(reason,self.exercise(**changes)[1])
    def test_site_enabled_or_preloaded_module_refuses_before_any_binding_file_read(self):
        for values in [{'isolated':0,'no_site':1},{'isolated':1,'no_site':0}]:
            with patch.object(n,'_libvirt_binding',None),patch.object(n.sys,'flags',Flags(**values)),patch.object(n,'protected')as read:
                with self.assertRaisesRegex(ValueError,'isolated_interpreter'):n.system_libvirt()
                read.assert_not_called()
        with patch.dict(sys.modules,{'libvirt':ModuleType('untrusted')}),patch.object(n,'_libvirt_binding',None), \
             patch.object(n.sys,'flags',Flags(isolated=1,no_site=1)),patch.object(n,'protected')as read:
            with self.assertRaisesRegex(ValueError,'preloaded_module'):n.system_libvirt()
            read.assert_not_called()
    def test_import_check_is_bound_to_exact_owned_parent_and_recipe_and_never_connects(self):
        from paw.core import owned_kernel_runtime as k
        parent='paw-vm-owned-'+J+'.service';ppid=n.os.getppid()
        props={'ActiveState':'active','MainPID':str(ppid),'ControlGroup':'/system.slice/'+parent,
               'MemoryMax':str(192*1024**2),'MemorySwapMax':'0','TasksMax':'24','CPUQuotaPerSecUSec':'350ms'}
        worker=str(n.HERE.parents[2]/'lab/s14/vm_operator_worker.py')
        argv=['/usr/bin/python3','-I','-B',worker,'--recipe','vm-acceptance-v1','--job',J]
        for altered,foreign_recipe in [({},False),({'MainPID':'1'},False),({},True)]:
            fake=Mock();fake.getVersion.return_value=12000000
            def read(path):
                if str(path).startswith('/proc/'):
                    return b'\0'.join(x.encode()for x in ([*argv[:5],'browser-owned-v1',*argv[6:]]if foreign_recipe else argv))+b'\0'
                return b'fixed loader'
            with patch.object(n,'root'),patch.object(k,'unit_properties',return_value={**props,**altered}), \
                 patch.object(n.Path,'read_bytes',read),patch.object(n,'system_libvirt',return_value=(fake,{}))as load:
                if altered or foreign_recipe:
                    with self.assertRaisesRegex(ValueError,'owned_parent|owned_recipe'):n.owned_bindings(J,R)
                    load.assert_not_called()
                else:
                    value=n.owned_bindings(J,R);self.assertEqual(value['result'],'PASS')
                    self.assertFalse(value['vm_started']);self.assertFalse(value['native_authority_created'])
                    self.assertEqual(value['real_connections'],0);fake.getVersion.assert_called_once()
                    fake.open.assert_not_called();fake.openReadOnly.assert_not_called()
    def test_parent_launches_only_no_site_fixed_import_and_refuses_foreign_scope(self):
        raw={'schema':'paw-mail-owned-bindings-v1','result':'PASS','job':J,'release_sha':R,
             'vm_started':False,'native_authority_created':False,'interpreter_isolated':True,'site_disabled':True,
             'site_hooks_executed':False,'real_connections':0,'loader_sha256':hashlib.sha256(b'loader').hexdigest()}
        for changes in [{},{'native_authority_created':True},{'site_disabled':False},{'real_connections':True},{'job':'4'*32}]:
            with patch.object(p.subprocess,'run',return_value=NS(returncode=0,stdout=p.canonical({**raw,**changes}),stderr=b''))as run, \
                 patch.object(p.Path,'read_bytes',return_value=b'loader'):
                if changes:
                    with self.assertRaisesRegex(ValueError,'scope|identity'):p.owned_binding_probe(J,R)
                else:self.assertEqual(p.owned_binding_probe(J,R),raw)
                self.assertEqual(run.call_args.args[0],['/usr/bin/python3','-I','-S','-B',str(p.HERE.with_name('mail_browser_native.py')),'--owned-bindings',J,R])
                self.assertEqual(run.call_args.kwargs,{'capture_output':True,'timeout':10})

if __name__=='__main__':unittest.main()
