"""Synthetic acceptance of the same offline input API; no arbitrary launcher."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from offline_input import PROFILE, admit
from synthetic_gate import Gate
from benign_guest_validation import BASE, digest
from gw_quarantine import publish

PARENT = hashlib.sha256(b'owned synthetic parent reference, not a PAW authenticity claim').hexdigest()
SAMPLES = {
    'success': b"import os,json\nfrom pathlib import Path\ns=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)\nassert os.getuid()==os.getgid()==65534 and int(s['CapEff'],16)==0 and s['NoNewPrivs'].strip()=='1'\nassert sorted(p.name for p in Path('/sys/class/net').iterdir())==['lo']\nassert os.readlink('/proc/self/fd/0')=='/dev/null'\nPath('previous-job-marker').write_text('owned reset marker')\nprint('OWNED-IMMUTABLE-INPUT')\n",
    'timeout': b"import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=os.fork()\nif p==0:\n time.sleep(12);open('late-marker','w').write('late');time.sleep(2)\nelse: time.sleep(20)\n",
    'cancel': b"import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=os.fork()\nif p==0: time.sleep(12)\nelse: time.sleep(20)\n",
    'overflow': b"import os\nos.write(1,b'X'*4096)\n",
}


def job(case):
    source = SAMPLES[case]; now = int(time.time())
    return {'profile': PROFILE, 'job_id': 'owned-' + case, 'parent_sha256': PARENT,
            'source_hex': source.hex(), 'source_sha256': hashlib.sha256(source).hexdigest(),
            'operator_authorization': 'synthetic-only-this-pc', 'created_at': now, 'expires_at': now + 900}


def authorize(value):
    admitted = admit(value)
    if admitted['source'] not in SAMPLES.values() or admitted['job']['parent_sha256'] != PARENT:
        raise ValueError('synthetic_catalog_only')
    return admitted


class InputGate(Gate):
    def seed(self, folder, role, job_id, token):
        super().seed(folder, role, job_id, token)
        cloud = json.loads((folder / 'user-data').read_text().split('\n', 1)[1])
        for item in cloud['write_files']:
            if item['path'].endswith('/paw-gate.service'):
                content = base64.b64decode(item['content']).replace(b'/gate_guest.py', b'/offline_input_guest.py')
                item['content'] = base64.b64encode(content).decode()
        files = [('/usr/local/lib/paw-s14/offline_input_guest.py', (HERE / 'offline_input_guest.py').read_bytes()),
                 ('/opt/paw-input/sample.py', self.current['source']),
                 ('/etc/paw-input.json', json.dumps({'source_sha256': self.current['job']['source_sha256'],
                                                    'job_sha256': self.current['job_sha256']}).encode())]
        cloud['write_files'] += [{'path': name, 'encoding': 'b64', 'content': base64.b64encode(data).decode(),
                                  'permissions': '0444'} for name, data in files]
        (folder / 'user-data').write_text('#cloud-config\n' + json.dumps(cloud))
        self.run(['/usr/bin/genisoimage', '-quiet', '-output', str(folder / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                  str(folder / 'user-data'), str(folder / 'meta-data'), str(folder / 'network-config')])


def run_job(gate, value, cancel=False):
    """The single measured local Python API, used by the CLI acceptance matrix."""
    if getattr(gate, 'active_vm', None) is not None: raise ValueError('gate_busy')
    current = authorize(value)
    return _run_admitted_job(gate, current, lambda: authorize(current['job']), cancel)


def _run_admitted_job(gate, current, revalidate, cancel=False):
    """Shared lifecycle; only trusted adapters supply already admitted input."""
    if getattr(gate, 'active_vm', None) is not None: raise ValueError('gate_busy')
    folder = gate.output / 'admissions'; folder.mkdir(mode=0o700, exist_ok=True)
    # Atomic one-use ledger, before any guest creation. No caller-selected paths.
    with (folder / (current['job']['job_id'] + '.json')).open('x') as stream:
        stream.write(json.dumps(current['job'], sort_keys=True)); stream.flush(); os.fsync(stream.fileno())
    gate.current = current
    try:
        vm = gate.start(current['job']['job_id'])
        revalidate()  # expiry/digest/authority rechecked after boot, before execution
        started = vm['channel'].call('start')
        if started['source_sha256'] != current['job']['source_sha256'] or started['job_sha256'] != current['job_sha256']:
            raise ValueError('guest_admission_binding')
        if not started['prior_marker_absent']: raise ValueError('reset_marker_survived')
        if cancel:
            time.sleep(.25)
            outcome = {'status': 'cancelled', 'records': [], 'done': False}
        else:
            deadline = time.monotonic() + 8
            while True:
                outcome = vm['channel'].call('poll', seconds=3)
                if outcome['done']: break
                if time.monotonic() >= deadline: raise TimeoutError('host_job_deadline')
                time.sleep(.05)
        records = outcome['records']
        # Same publication function used for normal, timeout, cancellation and fault cases.
        gate.stop(vm)
        quarantine = publish(gate.output / (current['job']['job_id'] + '-quarantine'), records, stopped=vm.get('stopped'))
        result = {'job': current['job'], 'job_sha256': current['job_sha256'], 'vm_uuid': vm['node']['uuid'],
                  'guest_admission': started, 'outcome': outcome, 'stop_seconds': vm['stop_seconds'],
                  'writers_stopped': vm['stopped'], 'quarantine': quarantine}
        return result
    finally:
        if getattr(gate, 'active_vm', None) is not None: gate.stop(gate.active_vm)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-acceptance', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True); parser.add_argument('--export', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or Path('/proc/self/attr/current').read_text().strip() != 'unconfined':
        raise ValueError('root_pid1_service_required')
    if shutil.disk_usage('/var/lib/libvirt/images').free < 10 * 1024**3: raise ValueError('free_disk_admission')
    gate = InputGate(args); gate.active_vm = None
    gate.canary = gate.output / 'host-owned-canary.bin'; gate.canary.write_bytes(os.urandom(32)); gate.canary.chmod(0o600)
    canary = digest(gate.canary); before = gate.snapshot_host()
    gate.report.update(scope=PROFILE + '; trusted synthetic catalog only', input_runs=[], vms=[], real_connections=0)
    try:
        for case in ['success', 'timeout', 'cancel', 'overflow']:
            result = run_job(gate, job(case), cancel=case == 'cancel')
            if result['outcome']['status'] != {'success': 'completed', 'timeout': 'timeout', 'cancel': 'cancelled', 'overflow': 'output_budget'}[case]:
                raise ValueError('unexpected_outcome:' + case)
            if case == 'success' and bytes.fromhex(result['outcome']['records'][0]['bytes_hex']) != b'OWNED-IMMUTABLE-INPUT\n':
                raise ValueError('positive_execution_oracle')
            gate.report['input_runs'].append(result)
            print('PASS: immutable input / ' + case, flush=True)
        try: run_job(gate, job('success'))
        except FileExistsError: gate.report['replay_refused_before_vm'] = True
        else: raise ValueError('replayed_job')
        unknown = gate.output / 'unknown-stop-must-not-publish'
        try: publish(unknown, [], stopped=None)
        except ValueError: gate.report['unknown_stop_publication_refused'] = not unknown.exists()
        else: raise ValueError('unknown_stop_publication')
        gate.report['result'] = 'PASS'
    except Exception as error:
        gate.report.update(result='FAIL', error=str(error), traceback=traceback.format_exc()); print(gate.report['traceback'], flush=True)
    finally:
        try:
            if gate.active_vm: gate.stop(gate.active_vm)
            if gate.connection.listAllDomains(0) or before != gate.snapshot_host(): raise ValueError('host_not_restored')
            if digest(BASE) != gate.root_image_sha or digest(gate.canary) != canary: raise ValueError('immutable_bytes_changed')
            if any(digest(HERE / n) != h for n, h in gate.source_hashes.items()): raise ValueError('source_freeze_changed')
            gate.report.update(host_before=before, host_after=gate.snapshot_host(), host_restored=True,
                               source_freeze_unchanged=True, base_unchanged=True, host_canary_unchanged=True, writers_stopped=True)
        except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error))
        gate.connection.close()
        (args.output / 'results.json').write_text(json.dumps(gate.report, indent=2) + '\n')
        args.export.mkdir(mode=0o700, parents=True, exist_ok=False)
        for p in args.output.iterdir():
            if p.is_file() and p.suffix in {'.json', '.log', '.xml'}: shutil.copyfile(p, args.export / p.name)
            elif p.is_dir() and (p.name in {'sources', 'admissions'} or p.name.endswith('-quarantine')):
                shutil.copytree(p, args.export / p.name)
        for p in [args.export, *args.export.rglob('*')]: os.chown(p, 1000, 1000)
        print('Offline input acceptance: ' + gate.report['result'], flush=True)
    if gate.report['result'] != 'PASS': raise SystemExit(1)


if __name__ == '__main__': main()
