"""Draft real serialized failed custody checks; hardware/Root substituted."""
import copy
import json
from pathlib import Path
import shutil
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(REPO), str(REPO/'lab/s14'), str(REPO/'tests')]
import verify_representation as fault
import test_representation_evidence as evidence


class Faults(unittest.TestCase):
    def setUp(self): self.base = evidence.Evidence(); self.base.setUp()
    def tearDown(self): self.base.tearDown()

    def fixture(self, profile, case):
        root, report, context = self.base.fixture(profile); run = report['runs'][0]; vm = report['vms'][0]
        label = run['job']['job_id']; rid = run['request_id']; raw = (root/'authority-copy'/rid/'request.json').read_bytes()
        shutil.rmtree(root/(label+'-quarantine'))
        report.update(result='FAIL', error=fault.FAULTS[case], runs=[])
        witness = {'schema': 'paw-s14-representation-fault-v1', 'case': case, 'vm_uuid': vm['uuid'], 'fault_stop_seconds': .1}
        if case == 'paused-refusal': witness['paused_before_refusal'] = True
        else:
            admission = copy.deepcopy(run['guest_admission']); admission['started'] = True
            witness.update(admitted_at=run['admitted_at'], guest_admission=admission)
            if profile == fault.HTML: witness['guest_inspection'] = run['guest_inspection']
            if case == 'owner-loss':
                witness.update(owner_pid=4321, owner_identity='12345', owner_returncode=-9)
                (root/(label+'-owner-result.json')).unlink()
            else: witness['serial_closed'] = True
        (root/'results.json').write_bytes(fault.auth.canonical(report))
        return root, raw, case, witness

    def verify(self, *args):
        # Same explicit hardware/Root substitutions as the accepted successful
        # custody fixture. All new negative flow/source/authority/output reads
        # and comparisons operate on actual temporary files.
        with mock.patch.object(fault.auth, '_backend', return_value=SimpleNamespace(validate_context=lambda value: None)), \
             mock.patch.object(fault.auth.python_backend, 'validate_maintenance'), \
             mock.patch.object(fault, 'python_vm_evidence'), mock.patch.object(fault, '_html_vm'):
            return fault.verify_fault(*args)

    def test_six_owned_fault_profile_combinations_have_known_stop_and_no_output(self):
        for profile in [fault.PYTHON, fault.HTML]:
            for case in fault.FAULTS:
                with self.subTest(profile=profile, case=case): self.assertEqual(self.verify(*self.fixture(profile, case))['result'], 'PASS')

    def test_unknown_stop_extra_run_or_output_and_wrong_snapshot_refuse(self):
        for mutation in ['stop', 'run', 'output', 'snapshot', 'reason']:
            args = self.fixture(fault.PYTHON, 'protocol-loss'); root, _, _, _ = args
            report = json.loads((root/'results.json').read_bytes()); label = report['vms'][0]['label']
            if mutation == 'stop': report['vms'][0]['stopped'] = None
            elif mutation == 'run': report['runs'] = [{'unreported': 'output'}]
            elif mutation == 'output': (root/(label+'-quarantine')).mkdir()
            elif mutation == 'snapshot': (root/'runtime-snapshot/paw/owned.py').write_bytes(b'changed')
            else: report['error'] = 'different failure'
            (root/'results.json').write_bytes(fault.auth.canonical(report))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(*args)

    def test_bad_witness_clock_owner_status_protocol_or_admission_refuses(self):
        for case, key, value in [('owner-loss', 'owner_returncode', 0), ('owner-loss', 'owner_pid', True),
                ('protocol-loss', 'serial_closed', False), ('paused-refusal', 'paused_before_refusal', False),
                ('owner-loss', 'admitted_at', 0), ('protocol-loss', 'fault_stop_seconds', float('nan'))]:
            args = self.fixture(fault.HTML, case); args[3][key] = value
            with self.subTest(case=case, key=key), self.assertRaises(ValueError): self.verify(*args)
        args = self.fixture(fault.HTML, 'protocol-loss'); args[3]['guest_admission']['job_sha256'] = '0'*64
        with self.assertRaises(ValueError): self.verify(*args)

    def test_unaccounted_authority_and_changed_ledger_refuse(self):
        for mutation in ['extra', 'ledger']:
            args = self.fixture(fault.PYTHON, 'paused-refusal'); root, raw, _, _ = args
            if mutation == 'extra': (root/'authority-copy'/('f'*32)).mkdir()
            else:
                rid = fault.auth.decode(raw)['candidate']['request_id']; p = root/'authority-copy'/rid/'consumed.json'
                value = fault.auth.decode(p.read_bytes()); value['request_sha256'] = '0'*64; p.write_bytes(fault.auth.canonical(value))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(*args)


if __name__ == '__main__': unittest.main()
