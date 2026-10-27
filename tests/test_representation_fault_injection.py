"""Fixed fault subclasses with inert owners/channels; never signals a process."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO/'lab/s14')]
import representation_producer as p
import benign_guest_validation


class FakeGate:
    def __init__(self):
        self.connection = SimpleNamespace(lookupByUUIDString=mock.Mock(return_value=SimpleNamespace(state=lambda: (3, 0))))
        self.libvirt = SimpleNamespace(VIR_DOMAIN_PAUSED=3)
    def start(self, label, boot=True):
        self.boot = boot; owner = mock.Mock(pid=12345, returncode=-9)
        serial = SimpleNamespace(close=mock.Mock(), log=SimpleNamespace(close=mock.Mock()))
        channel = SimpleNamespace(call=mock.Mock(side_effect=lambda operation, **kwargs: {'owned': operation}), serial=serial)
        self.active_vm = {'node': {'uuid': '00000000-0000-4000-8000-000000000001'}, 'owner': owner, 'channel': channel}
        return self.active_vm
    def stop(self, vm, kill=False): self.active_vm = None; return .01


class Injection(unittest.TestCase):
    def test_paused_refusal_never_boots_or_calls_guest_and_records_stop(self):
        witness = {}
        with mock.patch.object(p.adapter, 'HashGate', FakeGate): gate = p.owned_fault_gate(p.adapter.PYTHON, 'paused-refusal', witness)()
        with self.assertRaisesRegex(ValueError, p.FAULTS['paused-refusal']): gate.start('owned')
        vm = gate.active_vm; self.assertFalse(gate.boot); vm['channel'].call.assert_not_called()
        gate.stop(vm); self.assertTrue(witness['paused_before_refusal']); self.assertLess(witness['fault_stop_seconds'], 12)

    def test_owner_and_protocol_faults_follow_actual_start_and_stop_without_publishing(self):
        for profile in [p.adapter.PYTHON, p.adapter.HTML]:
            for case in ['owner-loss', 'protocol-loss']:
                witness = {}
                with mock.patch.object(p.adapter, 'HashGate', FakeGate), mock.patch.object(p.adapter, 'BrowserVM', FakeGate):
                    gate = p.owned_fault_gate(profile, case, witness)()
                vm = gate.start('owned'); channel = vm['channel']; channel.call('inspect', seconds=10); channel.call('start')
                with mock.patch.object(benign_guest_validation, 'process_identity', return_value='98765'), \
                     self.subTest(profile=profile, case=case), self.assertRaisesRegex(ValueError, p.FAULTS[case]):
                    channel.call('poll', seconds=8)
                gate.stop(vm)
                self.assertEqual(witness['guest_admission'], {'owned': 'start'})
                self.assertIn('admitted_at', witness); self.assertLess(witness['fault_stop_seconds'], 12)
                if case == 'owner-loss': vm['owner'].kill.assert_called_once(); self.assertEqual(witness['owner_returncode'], -9)
                else: self.assertTrue(witness['serial_closed'])

    def test_unknown_profiles_and_unexpected_faults_do_not_inherit_a_backend(self):
        with self.assertRaises(ValueError): p.owned_fault_gate('unknown', 'owner-loss', {})
        with self.assertRaises(ValueError): p.owned_fault_gate(p.adapter.PYTHON, 'caller-command', {})
        with self.assertRaises(ValueError): p.owned_probe_gate('unknown', {})


if __name__ == '__main__': unittest.main()
