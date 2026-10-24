"""Kernel fault evidence must refer to the declared VM, not another process."""
import copy
import unittest
from verify_synthetic_gate import verify_vm_bindings


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


if __name__ == '__main__': unittest.main()
