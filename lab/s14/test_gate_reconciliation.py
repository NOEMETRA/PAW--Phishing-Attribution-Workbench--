"""Kernel fault evidence must refer to the declared VM, not another process."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from verify_synthetic_gate import CHECKS, REQUIRED_SOURCES, verify, verify_vm_bindings


def fixture():
    names = ['boundaries', 'reset-storage', 'host-oom']
    vms = [{'label': name, 'uuid': 'owned-' + name,
            'actual': {'uuid': 'owned-' + name, 'pid': 100 + i, 'pid_identity': str(500 + i)}}
           for i, name in enumerate(names)]
    oom = {'kernel_witness': 'Memory cgroup out of memory: Killed process 102 (qemu-system-x86)'}
    return vms, oom


class FaultProvenance(unittest.TestCase):
    def test_matching_controlled_victim_passes(self):
        vms, oom = fixture(); verify_vm_bindings(vms, oom)

    def test_unrelated_kernel_victim_or_reused_domain_refuses(self):
        vms, oom = fixture()
        with self.assertRaisesRegex(ValueError, 'oom_victim'):
            verify_vm_bindings(vms, {'kernel_witness': oom['kernel_witness'].replace('102', '999999')})
        for key in ['uuid', 'label']:
            forged = copy.deepcopy(vms); forged[2][key] = forged[0][key]
            with self.subTest(key=key), self.assertRaises(ValueError): verify_vm_bindings(forged, oom)

    def test_pid_reuse_requires_distinct_start_identity(self):
        vms, oom = fixture()
        vms[0]['actual']['pid'] = 102
        verify_vm_bindings(vms, oom)
        vms[0]['actual']['pid_identity'] = vms[2]['actual']['pid_identity']
        with self.assertRaisesRegex(ValueError, 'reused_process_identity'): verify_vm_bindings(vms, oom)


def write_bundle(root):
    """Inert complete export exercising the public reader, with no VM or code run."""
    (root / 'sources').mkdir(); content = b'inert source fixture\n'
    hashes = {name: hashlib.sha256(content).hexdigest() for name in REQUIRED_SOURCES}
    for name in hashes: (root / 'sources' / name).write_bytes(content)
    vms, oom = fixture()
    for vm in vms:
        vm.update(stopped=True, stop_seconds=.1, overlay_bytes=1, fsize_limit=1024, host_status='Seccomp:\t2')
        vm['actual'].update(limits={'memory.max': str(768 * 1024**2), 'memory.swap.max': '0', 'pids.max': '64'},
                            apparmor='libvirt-owned (enforce)')
        (root / (vm['label'] + '-domain.xml')).write_text(
            '<domain><uuid>' + vm['uuid'] + '</uuid><memory>512</memory>'
            '<defaultiothread thread_pool_max="8"/><devices/>'
            '<seclabel model="dac"><label>+64055:+64055</label></seclabel></domain>')
    checks = [{'name': name, 'result': 'PASS'} for name in CHECKS]
    checks[0]['observation'] = {'data': dict(uid=65534, gid=65534, no_new_privs='1', cap_eff='0',
        stdin_path='/dev/null', interfaces=['lo'], positive_read=True, denied_paths={'owned': True},
        network=[{'denied': True}], setuid_denied=True, mount_denied=True, cgroup_write_denied=True)}
    checks[1]['observation'] = {'data': {'denied': True, 'spawned': 1, 'reaped': 1},
                                'events': {'pids.peak': '2', 'pids.events': 'max 1'}}
    checks[2]['observation'] = {'data': {'actual_guest_cgroup_oom': True}, 'returncode': -9,
                                'events': {'memory.events': 'oom_kill 1'}}
    checks[3]['observation'] = {'data': {'refused': True, 'bytes': 1024}}
    checks[5].update(channel_failure='frame_object_required', stop_seconds=.1)
    checks[6]['observation'] = {'data': {'prior_marker_absent': True}}
    checks[7].update(overlay_bytes=1, cap_bytes=1024, emulator_io_error='IO error: File too large', fault_seconds=.1)
    checks[8].update(oom, injected_limit_bytes=1024**2, guest_payload_started=False, fault_seconds=.1)
    (root / 'quarantine').mkdir(); (root / 'quarantine/artifact-00.bin').write_bytes(b'opaque')
    r = dict(result='PASS', host_before={}, host_after={}, real_connections=0,
             source_hashes=hashes, vms=vms, checks=checks, general_hostile_launcher='NOT_IMPLEMENTED',
             quarantine=[{'stored_as': 'artifact-00.bin', 'bytes': 6, 'sha256': hashlib.sha256(b'opaque').hexdigest()}])
    r.update({key: True for key in ['host_restored', 'source_freeze_unchanged', 'base_unchanged',
                                   'host_canary_unchanged', 'writers_stopped', 'stable_publication']})
    (root / 'results.json').write_text(json.dumps(r))
    return r


class ExportProvenance(unittest.TestCase):
    def test_complete_export_and_matching_domains_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write_bundle(root)
            self.assertEqual(verify(root)['source_count'], len(REQUIRED_SOURCES))

    def test_missing_sources_or_unlisted_export_refuse(self):
        for mutation in ['empty', 'missing_runner', 'unlisted', 'missing_export', 'changed_bytes']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); r = write_bundle(root)
                if mutation == 'empty':
                    r['source_hashes'] = {}; shutil.rmtree(root / 'sources')
                elif mutation == 'missing_runner':
                    del r['source_hashes']['synthetic_gate.py']; (root / 'sources/synthetic_gate.py').unlink()
                elif mutation == 'unlisted': (root / 'sources/unlisted.py').write_bytes(b'inert')
                elif mutation == 'missing_export': (root / 'sources/gate_guest.py').unlink()
                else: (root / 'sources/gate_guest.py').write_bytes(b'changed')
                (root / 'results.json').write_text(json.dumps(r))
                with self.assertRaisesRegex(ValueError, 'source_'): verify(root)

    def test_duplicated_or_missing_domain_uuid_refuses(self):
        for mutation in ['duplicate', 'missing']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); write_bundle(root)
                target = root / 'host-oom-domain.xml'
                if mutation == 'duplicate': shutil.copyfile(root / 'boundaries-domain.xml', target)
                else: target.write_text(target.read_text().replace('<uuid>owned-host-oom</uuid>', ''))
                with self.assertRaisesRegex(ValueError, 'domain_xml_uuid:host-oom'): verify(root)

    def test_external_absolute_traversal_symlink_or_unlisted_quarantine_refuses(self):
        for mutation in ['absolute', 'traversal', 'file_link', 'directory_link', 'unlisted']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory); root = parent / 'bundle'; root.mkdir(); r = write_bundle(root)
                artifact = root / 'quarantine/artifact-00.bin'; outside = parent / 'artifact-00.bin'
                outside.write_bytes(artifact.read_bytes())
                if mutation in {'absolute', 'traversal'}:
                    artifact.unlink(); (root / 'quarantine').rmdir()
                    r['quarantine'][0]['stored_as'] = str(outside) if mutation == 'absolute' else '../../artifact-00.bin'
                elif mutation == 'file_link': artifact.unlink(); artifact.symlink_to(outside)
                elif mutation == 'directory_link':
                    external = parent / 'external'; (root / 'quarantine').rename(external)
                    (root / 'quarantine').symlink_to(external, target_is_directory=True)
                else: (root / 'quarantine/unlisted.bin').write_bytes(b'extra')
                (root / 'results.json').write_text(json.dumps(r))
                with self.assertRaisesRegex(ValueError, 'quarantine_'): verify(root)


if __name__ == '__main__': unittest.main()
