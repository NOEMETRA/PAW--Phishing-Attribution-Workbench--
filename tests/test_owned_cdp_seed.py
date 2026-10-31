"""Inert actual seed generation; no image, process, Root or VM launch."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]
CORE=REPO/'paw/core'
sys.path[:0]=[str(REPO/'lab/s14'),str(REPO)]
spec=importlib.util.spec_from_file_location('proposed_browser_vm',REPO/'lab/s14/browser_vm.py')
vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)


class Seed(unittest.TestCase):
    def compose(self,phase):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);here=root/'lab/s14';here.mkdir(parents=True)
            core=root/'paw/core';core.mkdir(parents=True);out=root/'seed';out.mkdir()
            for name in ['browser_guest.py','browser_build_guest.py','browser_policy.py','browser_sandbox.py']:
                (here/name).write_bytes((REPO/'lab/s14'/name).read_bytes())
            for name in ['browser_cdp.py','browser_owned_cdp_guest.py','browser_owned_broker_guest.py']:
                (core/name).write_bytes((CORE/name).read_bytes())
            gate=object.__new__(vm.BrowserVM);gate.phase=phase
            gate.seed_config={'kind':'owned-cdp-probe-v1','nonce':'a'*32} if phase in {'owned_cdp','owned_brokered'} else {'owned':'inert seed fixture'}
            calls=[]
            def compile_iso(args):
                calls.append(args);(out/'seed.iso').write_bytes(b'not an actual ISO')
            gate.run=compile_iso
            with patch.object(vm,'HERE',here):gate.seed(out,'extractor','owned-job','unused')
            cloud=json.loads((out/'user-data').read_text().split('\n',1)[1])
            files={r['path']:base64.b64decode(r['content']) for r in cloud['write_files']}
            network=json.loads((out/'network-config').read_text())
            return files,network,calls
    def test_new_seed_has_only_fixed_probe_controller_and_bounded_service(self):
        files,network,calls=self.compose('owned_cdp')
        self.assertEqual(files['/usr/local/lib/paw-s14/browser_owned_cdp_guest.py'],(CORE/'browser_owned_cdp_guest.py').read_bytes())
        self.assertEqual(files['/usr/local/lib/paw-s14/browser_cdp.py'],(CORE/'browser_cdp.py').read_bytes())
        config=json.loads(files['/etc/paw-owned-cdp.json'])
        self.assertEqual(config,{'kind':'owned-cdp-probe-v1','nonce':'a'*32})
        unit=files['/etc/systemd/system/paw-browser.service'].decode()
        self.assertIn('MemoryMax=128M\n',unit);self.assertIn('TasksMax=32\n',unit)
        self.assertIn('MemorySwapMax=0\n',unit);self.assertIn('CPUQuota=100%\n',unit)
        self.assertEqual(network,{'version':2,'ethernets':{}})
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],'/usr/bin/genisoimage')
    def test_brokered_seed_preserves_no_nic_and_actual_isolated_dependency_lookup(self):
        files,network,_=self.compose('owned_brokered')
        unit=files['/etc/systemd/system/paw-browser.service'].decode()
        self.assertIn('/browser_owned_broker_guest.py',unit)
        self.assertIn('MemoryMax=128M\n',unit);self.assertIn('TasksMax=32\n',unit)
        self.assertEqual(network,{'version':2,'ethernets':{}})
        self.assertEqual(vm.LIFETIME['owned_brokered'],vm.LIFETIME['job'])
        self.assertEqual(vm.FILE_CAP['owned_brokered'],vm.FILE_CAP['job'])
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder)
            for name in ['browser_owned_broker_guest.py','browser_owned_cdp_guest.py','browser_cdp.py','browser_sandbox.py']:
                (root/name).write_bytes(files['/usr/local/lib/paw-s14/'+name])
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',
                'import runpy,sys;v=runpy.run_path(sys.argv[1]);assert callable(v["main"])',
                str(root/'browser_owned_broker_guest.py')],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_original_job_seed_still_uses_original_guest_and_config(self):
        files,network,_=self.compose('job')
        self.assertEqual(files['/usr/local/lib/paw-s14/browser_guest.py'],(REPO/'lab/s14/browser_guest.py').read_bytes())
        self.assertIn('/etc/paw-browser-job.json',files)
        self.assertNotIn('/etc/paw-owned-cdp.json',files)
        self.assertNotIn('/usr/local/lib/paw-s14/browser_cdp.py',files)
    def test_actual_generated_guest_imports_in_isolated_interpreter(self):
        files,_,_=self.compose('owned_cdp')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ['browser_owned_cdp_guest.py','browser_cdp.py','browser_sandbox.py']:
                (root/name).write_bytes(files['/usr/local/lib/paw-s14/'+name])
            # Import with the service's -I shape but do not call guest main,
            # inspect/start Chrome, create a cgroup or run a VM.
            code=("import runpy,sys,importlib.util;"
                  "runpy.run_path(sys.argv[1],run_name='owned_inert_import');"
                  "assert importlib.util.find_spec('browser_sandbox') is not None")
            completed=subprocess.run([sys.executable,'-I','-B','-u','-c',code,
                str(root/'browser_owned_cdp_guest.py')],capture_output=True,text=True,timeout=5)
            self.assertEqual(completed.returncode,0,completed.stderr)
    def test_owned_phase_preserves_existing_job_lifetime_file_and_qemu_bounds(self):
        self.assertEqual(vm.LIFETIME['owned_cdp'],vm.LIFETIME['job'])
        self.assertEqual(vm.FILE_CAP['owned_cdp'],vm.FILE_CAP['job'])
        self.assertEqual(vm.LIMITS,{'memory.max':str(1536*1024**2),'memory.swap.max':'0','pids.max':'64','cpu.max':'50000 100000'})

if __name__=='__main__':unittest.main()
