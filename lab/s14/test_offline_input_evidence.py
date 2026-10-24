"""Inert complete exports reproduce confinement evidence substitutions."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from offline_input_matrix import job
from offline_input import admit
from verify_offline_input import EXTRA_SOURCES, verify
from verify_synthetic_gate import REQUIRED_SOURCES


def bundle(root):
    sources = REQUIRED_SOURCES | EXTRA_SOURCES
    (root / 'sources').mkdir(); content = b'inert source snapshot'
    for name in sources: (root / 'sources' / name).write_bytes(content)
    r = dict(result='PASS', source_hashes={n: hashlib.sha256(content).hexdigest() for n in sources},
             host_before={}, host_after={}, real_connections=0, vms=[], input_runs=[])
    r.update({k: True for k in ['host_restored', 'base_unchanged', 'host_canary_unchanged',
                              'source_freeze_unchanged', 'writers_stopped', 'replay_refused_before_vm',
                              'unknown_stop_publication_refused']})
    (root / 'admissions').mkdir()
    for i, (case, status) in enumerate([('success', 'completed'), ('timeout', 'timeout'), ('cancel', 'cancelled'), ('overflow', 'output_budget')]):
        j = job(case); admitted = admit(j); uid = 'owned-vm-' + str(i)
        (root / 'admissions' / (j['job_id'] + '.json')).write_text(json.dumps(j))
        vm = dict(label=j['job_id'], uuid=uid, actual=dict(uuid=uid, pid=100 + i, pid_identity=str(200 + i),
            apparmor='libvirt-owned (enforce)', limits={'memory.max': str(768 * 1024**2), 'memory.swap.max': '0', 'pids.max': '64'}),
            host_status='Seccomp:\t2', stopped=True, stop_seconds=.1, overlay_bytes=1, fsize_limit=256 * 1024**2)
        r['vms'].append(vm)
        (root / (j['job_id'] + '-domain.xml')).write_text('<domain><uuid>' + uid + '</uuid><memory unit="KiB">524288</memory>'
            '<defaultiothread thread_pool_max="8"/><devices/><seclabel model="dac"><label>+64055:+64055</label></seclabel></domain>')
        folder = root / (j['job_id'] + '-quarantine'); folder.mkdir()
        records = []; manifest = []
        if case != 'cancel':
            for number, data in enumerate([b'OWNED-IMMUTABLE-INPUT\n' if case == 'success' else b'', b'']):
                sha = hashlib.sha256(data).hexdigest(); name = f'artifact-{number:02d}.bin'
                records.append({'bytes_hex': data.hex()}); (folder / name).write_bytes(data)
                manifest.append({'stored_as': name, 'bytes': len(data), 'sha256': sha})
        outcome = dict(status=status, records=records, done=case != 'cancel', writers_stopped=True,
                       events={'pids.current': '0'}, returncode=0)
        r['input_runs'].append(dict(job=j, job_sha256=admitted['job_sha256'], vm_uuid=uid,
            guest_admission={'source_sha256': j['source_sha256'], 'job_sha256': admitted['job_sha256'], 'prior_marker_absent': True},
            outcome=outcome, stop_seconds=.1, writers_stopped=True, quarantine=manifest))
    (root / 'results.json').write_text(json.dumps(r))


class Confinement(unittest.TestCase):
    def test_complete_synthetic_export_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bundle(root); self.assertEqual(verify(root)['jobs'], 4)

    def test_root_dac_large_memory_or_io_pool_refuses(self):
        for old, new, reason in [('64055', '0', 'dac'), ('524288', '8388608', 'memory'),
                                  ('thread_pool_max="8"', 'thread_pool_max="800"', 'io')]:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); bundle(root); path = root / 'owned-success-domain.xml'
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaisesRegex(ValueError, reason): verify(root)


if __name__ == '__main__': unittest.main()
