"""Real stop implementation with an inert owner and no virtual machine."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from synthetic_gate import Gate


class PartialStartup(unittest.TestCase):
    def check_stop(self, limit):
        with tempfile.TemporaryDirectory() as directory:
            overlay = Path(directory) / 'overlay'; overlay.write_bytes(b'owned')
            owner = SimpleNamespace(poll=lambda: None, terminate=lambda: None, wait=lambda timeout: 0)
            vm = {'node': {'uuid': 'owned-partial', 'overlay': overlay}, 'owner': owner, 'label': 'partial'}
            if limit is not None: vm['fsize_limit'] = limit
            gate = Gate.__new__(Gate); gate.report = {'vms': []}; gate.active_vm = vm
            gate.absent = lambda value: True
            gate.stop(vm)
            self.assertIsNone(gate.active_vm)
            self.assertEqual(len(gate.report['vms']), 1)
            record = gate.report['vms'][0]
            self.assertIs(record['stopped'], True)
            self.assertEqual(record['fsize_limit'], limit)
            self.assertEqual(record['overlay_bytes'], 5)

    def test_missing_pre_admission_limit_records_confirmed_stop_as_unknown_cap(self):
        self.check_stop(None)

    def test_completed_admission_keeps_known_file_cap_and_stop_inventory(self):
        self.check_stop(1024)


if __name__ == '__main__': unittest.main()
