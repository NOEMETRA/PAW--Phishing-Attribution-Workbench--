"""Inert browser image input/resource contracts; no VM, package or browser runs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from browser_image import validate_packages, copy_approved, GOOGLE_PRIMARY, validate_builder_shutdown
from browser_policy import chrome_arguments, JOB_MEMORY, JOB_TASKS, MAX_HTML
from browser_build_guest import installation_failure, cached_package, installation_command, probe_evidence
import browser_build_guest
from browser_vm import validate_xml, LIMITS, FILE_CAP, LIFETIME, HERE, validate_owner_config, scope_root
from owned_grant_fixtures import CPU_DISABLED
from offline_candidate import canonical


def manifest():
    return {'schema': 'paw-browser-verified-packages-v1', 'host_installs': 0,
            'google_primary_fingerprint': GOOGLE_PRIMARY, 'packages': [
                {'file': name+'_1_amd64.deb', 'package': name, 'version': '1', 'architecture': 'amd64',
                 'bytes': 3, 'sha256': hashlib.sha256(b'own').hexdigest(),
                 'verified_signed_indices': [{'purpose': 'inert unit role, not a signature proof'}]}
                for name in ['google-chrome-stable', 'apparmor']]}


def descriptor():
    root = ET.fromstring((HERE/'paused-probe.xml').read_bytes()); root.find('devices').remove(root.find('devices/interface'))
    for tag in ['memory', 'currentMemory']: root.find(tag).text = '1024'
    ET.SubElement(ET.SubElement(root, 'resource'), 'partition').text = '/machine/paws14'
    ET.SubElement(ET.SubElement(root, 'memoryBacking'), 'nosharepages')
    ET.SubElement(root.find('features'), 'pmu', {'state': 'off'}); ET.SubElement(root.find('features'), 'vmport', {'state': 'off'})
    for feature in [*CPU_DISABLED, 'vmx', 'svm']: ET.SubElement(root.find('cpu'), 'feature', {'name': feature, 'policy': 'disable'})
    ET.SubElement(root.find('devices'), 'controller', {'type': 'usb', 'model': 'none'})
    for target in ['vda', 'vdb', 'vdc']:
        disk=ET.SubElement(root.find('devices'), 'disk'); ET.SubElement(disk, 'target', {'dev': target})
        if target!='vda': ET.SubElement(disk, 'readonly')
    return root


class BrowserImage(unittest.TestCase):
    def test_pid_calibration_never_accepts_failure_and_final_probe_requires_full_sandbox(self):
        sandbox={k:True for k in ['renderer_seen','renderer_nnp','renderer_seccomp','all_uids_nonroot','renderer_pid_namespace']}
        events={'pids.events':'max 1','memory.events':'oom 0\noom_kill 0\noom_group_kill 0'}
        calibration=probe_evidence(-9,b'',b'owned thread refusal',sandbox,events,128,True)
        self.assertFalse(calibration['accepted']);self.assertTrue(calibration['calibration_only'])
        with self.assertRaises(ValueError):probe_evidence(-9,b'',b'owned refusal',sandbox,events,JOB_TASKS)
        with self.assertRaises(ValueError):probe_evidence(-9,b'',b'other failure',sandbox,{**events,'pids.events':'max 0'},128,True)
        with self.assertRaises(ValueError):probe_evidence(-9,b'',b'oom',sandbox,{**events,'memory.events':'oom 1\noom_kill 1'},128,True)
        for memory in ['oom 0\noom_kill 1\noom_group_kill 0', 'oom 0\noom_kill 0\noom_group_kill 1', 'oom 0']:
            with self.subTest(memory=memory),self.assertRaises(ValueError):
                probe_evidence(-9,b'',b'mixed PID and guest-wide OOM',sandbox,{**events,'memory.events':memory},128,True)
        dom=b'<title>PAW-BROWSER-PROBE</title>'
        clean={**events,'pids.events':'max 0'}
        good=probe_evidence(0,dom,b'',sandbox,clean,JOB_TASKS);self.assertTrue(good['accepted'])
        with self.assertRaises(ValueError):probe_evidence(0,dom,b'',sandbox,events,JOB_TASKS)
        with self.assertRaises(ValueError):probe_evidence(0,dom,b'',sandbox,{**clean,'memory.events':'oom 0\noom_kill 1\noom_group_kill 0'},JOB_TASKS)
        with self.assertRaises(ValueError):probe_evidence(0,dom,b'',{**sandbox,'renderer_seccomp':False},clean,JOB_TASKS)
        with self.assertRaises(ValueError):probe_evidence(0,b'<title>before</title><script>document.title="PAW-BROWSER-PROBE"</script>',b'',sandbox,clean,JOB_TASKS)

    def test_offline_upgrade_archives_are_cached_verified_absolute_and_removals_forbidden(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); source=root/'owned.deb'; source.write_bytes(b'own')
            item={'file':'owned.deb','bytes':3,'sha256':hashlib.sha256(b'own').hexdigest()}
            with patch.object(browser_build_guest,'CACHE',root/'cache'):
                target=cached_package(source,item); self.assertEqual(Path(target).read_bytes(),b'own')
                self.assertEqual(Path(target).stat().st_mode&0o777,0o444)
                self.assertEqual(cached_package(source,item),target)
                command=installation_command([target]); self.assertIn('--no-download',command); self.assertIn('--no-remove',command)
                self.assertEqual(command[-1],str(root/'cache/owned.deb'))
                with self.assertRaises(ValueError):installation_command(['owned.deb'])
                with self.assertRaises(ValueError):installation_command([str(source)])
                with self.assertRaises(ValueError):cached_package(source,{**item,'sha256':'0'*64})
                link=root/'cache/link.deb';link.symlink_to(source)
                with self.assertRaises(ValueError):cached_package(source,{**item,'file':'link.deb'})

    def test_failed_offline_install_reports_only_bounded_log_tail_and_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'owned-install.log'
            path.write_bytes(b'OMITTED-PREFIX' + b'x'*10000 + b'\nE: owned missing dependency\n')
            message=installation_failure(path,100)
            self.assertTrue(message.startswith('guest_offline_package_install_failed:exit=100:'))
            self.assertTrue(message.endswith('E: owned missing dependency\n'))
            self.assertNotIn('OMITTED-PREFIX',message)
            self.assertLess(len(message),3100)

    def test_canonical_administratively_approved_manifest_and_exact_digest_required(self):
        raw=canonical(manifest()); self.assertEqual(len(validate_packages(raw, hashlib.sha256(raw).hexdigest())), 2)
        with self.assertRaisesRegex(ValueError, 'approved_package_manifest_digest'): validate_packages(raw, '0'*64)
        raw=b'{"schema":1,"schema":2}'
        with self.assertRaisesRegex(ValueError, 'duplicate'): validate_packages(raw, hashlib.sha256(raw).hexdigest())

    def test_manifest_does_not_allow_path_escape_unverified_blob_wrong_vendor_or_cohort(self):
        for mutation in ['path','hash','size','bool','signed','vendor','duplicate','chrome','version']:
            m=manifest()
            if mutation=='path':m['packages'][0]['file']='../outside.deb'
            elif mutation=='hash':m['packages'][0]['sha256']='bad'
            elif mutation=='size':m['packages'][0]['bytes']=2**30
            elif mutation=='bool':m['packages'][0]['bytes']=True
            elif mutation=='signed':m['packages'][0]['verified_signed_indices']=[]
            elif mutation=='vendor':m['google_primary_fingerprint']='0'*40
            elif mutation=='duplicate':m['packages'].append(m['packages'][0])
            elif mutation=='chrome':m['packages']=m['packages'][1:]
            else:m['packages'][0]['version']='x\nmalformed'
            raw=canonical(m)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):validate_packages(raw,hashlib.sha256(raw).hexdigest())

    def test_stream_copy_requires_exact_bytes_and_never_follows_links(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'source.deb';source.write_bytes(b'own');target=root/'copied.deb'
            copy_approved(source,target,hashlib.sha256(b'own').hexdigest(),3)
            self.assertEqual(target.read_bytes(),b'own');self.assertEqual(target.stat().st_mode&0o777,0o444)
            with self.assertRaises(FileExistsError):copy_approved(source,target,hashlib.sha256(b'own').hexdigest(),3)
            with self.assertRaises(ValueError):copy_approved(source,root/'mismatch','0'*64,3)
            self.assertEqual((root/'mismatch').stat().st_mode&0o777,0o600)
            link=root/'link';link.symlink_to(source)
            with self.assertRaises(OSError):copy_approved(link,root/'outside',hashlib.sha256(b'own').hexdigest(),3)

    def test_browser_xml_accepts_actual_libvirt_memory_units_and_refuses_exposure(self):
        root=descriptor();validate_xml(root)
        for tag in ['memory','currentMemory']:root.find(tag).set('unit','KiB');root.find(tag).text='1048576'
        validate_xml(root)
        for kind in ['interface','filesystem','hostdev','vsock','graphics']:
            changed=copy.deepcopy(root);ET.SubElement(changed.find('devices'),kind)
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate_xml(changed)
        for mutation in ['memory','merge','pmu','usb','media','partition']:
            changed=descriptor()
            if mutation=='memory':changed.find('memory').text='2048'
            elif mutation=='merge':changed.remove(changed.find('memoryBacking'))
            elif mutation=='pmu':changed.find('features/pmu').set('state','on')
            elif mutation=='usb':changed.find('devices/controller').set('model','qemu-xhci')
            elif mutation=='media':changed.find('devices/disk[3]').remove(changed.find('devices/disk[3]/readonly'))
            else:changed.find('resource/partition').text='/machine/other'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):validate_xml(changed)

    def test_threaded_libvirt_descendant_resolves_the_modified_scope_root(self):
        parent='/machine.slice/machine-paws14.slice/machine-qemu-owned.scope'
        expected=Path('/sys/fs/cgroup'+parent)
        self.assertEqual(scope_root(parent),expected)
        self.assertEqual(scope_root(parent+'/libvirt/emulator'),expected)
        # The old code read descendant files ('max' or absent), not these limits.
        self.assertNotEqual(Path('/sys/fs/cgroup'+parent+'/libvirt/emulator'),scope_root(parent+'/libvirt/emulator'))
        with self.assertRaises(ValueError):scope_root('/machine.slice/other.slice/unrelated.scope/libvirt/emulator')

    def test_absence_after_owner_failure_cannot_publish_a_derived_image(self):
        good={'reason':'guest_shutdown','connection_closed':True,'guest_shutdown_event':True,'vm_uuid':'owned-uuid'}
        validate_builder_shutdown(good,'owned-uuid')
        for reason in ['guard_changed','heartbeat_lost','clock_changed','limits_changed','requested_stop','qemu_exited']:
            with self.subTest(reason=reason),self.assertRaises(ValueError):
                validate_builder_shutdown({**good,'reason':reason},'owned-uuid')
        with self.assertRaises(ValueError):validate_builder_shutdown({**good,'guest_shutdown_event':False},'owned-uuid')
        with self.assertRaises(ValueError):validate_builder_shutdown(good,'other-uuid')

    def test_owner_configuration_cannot_choose_other_host_paths_or_budgets(self):
        path=Path('/var/lib/paw-s14/control/browser-image-owned/owner.json')
        config={'phase':'build','parent_pid':123,'parent_identity':'456','guard':'a'*64,'qemu_sha256':'b'*64,
                **{k:str(path.parent/(k+('.xml' if k=='xml' else '.json'))) for k in ['xml','control','ready','result']}}
        validate_owner_config(config,path)
        for field,value in [('phase','unbounded'),('parent_pid',True),('xml','/etc/shadow'),('guard','bad')]:
            changed=copy.deepcopy(config);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate_owner_config(changed,path)
        changed={**config,'memory_limit':2**40}
        with self.assertRaises(ValueError):validate_owner_config(changed,path)

    def test_fixed_local_browser_command_retains_sandbox_and_has_no_tcp_debugging(self):
        args=chrome_arguments(Path('/mnt/paw-browser-input/input.html'),Path('/run/paw-browser/profile'))
        self.assertEqual(args[-1],'file:///mnt/paw-browser-input/input.html')
        self.assertFalse(any(v.startswith(('--no-sandbox','--disable-setuid-sandbox','--disable-web-security',
                                           '--ignore-certificate-errors','--remote-debugging-port')) for v in args))
        for value in ['https://fixture.invalid/',Path('relative.html'),Path('/mnt/../outside')]:
            with self.subTest(value=value),self.assertRaises(ValueError):chrome_arguments(value,Path('/run/profile'))
        self.assertEqual((JOB_MEMORY,JOB_TASKS,MAX_HTML),(536870912,256,524288))
        self.assertEqual(LIMITS,{'memory.max':'1610612736','memory.swap.max':'0','pids.max':'64','cpu.max':'50000 100000'})
        self.assertEqual(FILE_CAP['job'],268435456);self.assertLessEqual(LIFETIME['job'],360)


if __name__=='__main__':unittest.main()
