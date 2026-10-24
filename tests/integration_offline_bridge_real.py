"""Actual EML/installed CLI/seals with inert root exports; never a guest/sample execution."""
import argparse
from email.message import EmailMessage
from email.policy import SMTP
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

REPO = Path(__file__).resolve().parents[1]
WITNESS = hashlib.sha256(b'CI inert case bridge export; no KVM').hexdigest()


def fixture(args):
    assert os.geteuid() == 0
    sys.path.insert(0, str(REPO)); sys.path.insert(0, str(REPO / 'lab/s14'))
    from paw.core import offline_bridge as c
    from paw_hash_bridge import export_receipt
    if args.remove:
        with c.trusted_export(args.remove) as fd:
            receipt = json.loads(c.shared._read_regular('receipt.json', c.RECEIPT_LIMIT, directory_fd=fd, root_owned=True))
            assert receipt['runtime']['raw_result_sha256'] == WITNESS
            names = set(os.listdir(fd)); assert names <= {'request.json', 'receipt.json', 'artifact-00.bin'}
            for name in names: os.unlink(name, dir_fd=fd)
        (c.EXPORT_ROOT / args.remove).rmdir(); return
    raw = c.shared._read_regular(args.publish, c.REQUEST_LIMIT); assert c.digest(raw) == args.expected_sha256
    request = c.validate_request(raw); frame = request['candidate']; now = frame['created_at']
    hashes = {k: '1'*64 for k in ['job_sha256', 'source_inventory_sha256', 'policy_sha256', 'grant_sha256',
                                 'readiness_sha256', 'consumption_sha256']}
    receipt = {'schema': 'paw-s14-case-result-v1', 'producer_kind': 'local-root-verified-hash-offline',
        'request_id': frame['request_id'], 'request_sha256': c.digest(raw), 'candidate_sha256': c.digest(c.canonical(frame)),
        'binding_sha256': frame['case_reference_sha256'], 'source_sha256': frame['source']['sha256'],
        'execution_status': 'failed' if args.mode == 'failed' else 'completed',
        'runtime': {**hashes, 'raw_result_sha256': WITNESS, 'bridge_contract_sha256': c.contract_hash(),
            'vm_uuid': str(uuid.uuid4()), 'image_sha256': c.shared.IMAGE_SHA256, 'source_count': 81,
            'admitted_at': now, 'completed_at': now, 'stop_seconds': .1, 'writers_stopped': True},
        'artifacts': [{'stored_as': 'artifact-00.bin', 'bytes': 3, 'sha256': c.digest(b'out')}]}
    c.validate_receipt(c.canonical(receipt), request, c.digest(raw))
    path = export_receipt(raw, request, receipt, {'artifact-00.bin': b'out'})
    if args.mode == 'unknown-stop':
        receipt['runtime']['writers_stopped'] = False
        (path / 'receipt.json').chmod(0o600); (path / 'receipt.json').write_bytes(c.canonical(receipt)); (path / 'receipt.json').chmod(0o444)
    elif args.mode == 'symlink':
        (path / 'artifact-00.bin').unlink(); (path / 'artifact-00.bin').symlink_to('/dev/null')
    elif args.mode == 'digest':
        (path / 'artifact-00.bin').chmod(0o600); (path / 'artifact-00.bin').write_bytes(b'bad'); (path / 'artifact-00.bin').chmod(0o444)


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='store_true'); parser.add_argument('--root-fixture', action='store_true')
    parser.add_argument('--output', type=Path); parser.add_argument('--publish', type=Path)
    parser.add_argument('--expected-sha256'); parser.add_argument('--remove')
    parser.add_argument('--mode', choices=['completed', 'failed', 'unknown-stop', 'symlink', 'digest'], default='completed')
    args = parser.parse_args()
    if args.publish or args.remove: fixture(args); return
    environment = dict(os.environ, PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8')
    environment.pop('PYTHONPATH', None); environment.pop('PYTHONHOME', None)
    if args.source: environment['PYTHONPATH'] = str(REPO)
    prefix = [sys.executable, *([] if args.source else ['-I']), '-m', 'paw']
    logs = []; exports = []
    with tempfile.TemporaryDirectory(prefix='paw-case-bridge-') as directory:
        root = Path(directory); source = root / 'owned.eml'; message = EmailMessage(policy=SMTP)
        message['From'] = 'owner@fixture.invalid'; message['To'] = 'analyst@fixture.invalid'
        message['Subject'] = 'Owned no-network attachment custody fixture'
        message.set_content('Owned inert attachment. No URL or external dependency.')
        message.add_attachment(b'print("owned new outside catalogue")\n', maintype='text', subtype='x-python', filename='owned.py')
        original = message.as_bytes(); source.write_bytes(original)
        def cli(arguments, success=True):
            p = subprocess.run(prefix + arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)
            logs.append({'arguments': arguments, 'returncode': p.returncode, 'stdout': p.stdout[-12000:], 'stderr': p.stderr[-5000:]})
            assert (p.returncode == 0) == success, logs[-1]
            return p
        try:
            cli(['quick', str(source), '--deadline', '90', '--stage-timeout', '30', '--memory-mib', '512'])
            case, = list((root / 'cases').glob('case-*')); before = snapshot(case)
            assert (case / 'input.eml').read_bytes() == original
            attachment, = json.loads((case / 'attachments.json').read_text()); relative = attachment['evidence_path']
            cli(['verify', '--case', str(case)])
            modes = ['completed', 'failed', 'unknown-stop', 'symlink', 'digest'] if args.root_fixture else ['missing']
            for mode in modes:
                info = json.loads(cli(['lab-offline', 'prepare', '--case', str(case), '--attachment-path', relative,
                                      '--output', str(root / ('request-' + mode))]).stdout)
                assert not info['execution_authorized']
                if args.root_fixture:
                    exports.append(info['request_id'])
                    p = subprocess.run(['sudo', '-n', '/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                        '--publish', info['request'], '--expected-sha256', info['request_sha256'], '--mode', mode],
                        capture_output=True, text=True, timeout=20)
                    assert p.returncode == 0, (p.stdout, p.stderr)
                output = root / ('import-' + mode); valid = mode in {'completed', 'failed'}
                p = cli(['lab-offline', 'import', '--case', str(case), '--request', info['request'], '--output', str(output)], valid)
                if valid:
                    result = json.loads(p.stdout); assert result['execution_status'] == mode
                    sidecar = Path(result['result']); cli(['verify', '--case', str(sidecar)])
                    assert (sidecar / 'artifact-00.bin').read_bytes() == b'out'
                    assert 'risk_score' not in json.loads((sidecar / 'result.json').read_text())
                    cli(['lab-offline', 'import', '--case', str(case), '--request', info['request'], '--output', str(output)], False)
                else: assert not output.exists()
            assert snapshot(case) == before; cli(['verify', '--case', str(case)])
        finally:
            for identifier in exports:
                p = subprocess.run(['sudo', '-n', '/usr/bin/python3', '-I', str(Path(__file__).resolve()), '--remove', identifier],
                                   capture_output=True, text=True, timeout=20)
                assert p.returncode == 0, p.stderr
    result = {'result': 'PASS', 'original_and_case_unchanged': True, 'installed': not args.source,
              'root_fixture': args.root_fixture, 'kvm_executed': False, 'source_executed': False, 'logs': logs}
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True); (args.output / 'integration.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'logs'}))


if __name__ == '__main__': main()
