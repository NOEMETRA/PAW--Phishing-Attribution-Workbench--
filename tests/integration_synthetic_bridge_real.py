"""Real PAW analysis/CLI/sidecar flow; optional root receipt fixture, never a VM.

The root fixture tests the local trust boundary only. It is not KVM evidence.
Actual operator/KVM acceptance is recorded separately on the Linux lab PC.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
TEST_WITNESS = hashlib.sha256(b'CI-only simulated root receipt; no KVM execution').hexdigest()


def root_fixture(args):
    assert os.geteuid() == 0
    sys.path.insert(0, str(REPO))
    from paw.core import synthetic_bridge as c
    prefix = c.EXPORT_ROOT
    if not prefix.exists(): prefix.mkdir(mode=0o755); prefix.chmod(0o755)
    info = prefix.lstat(); assert prefix.is_dir() and not prefix.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022
    if args.remove_test_export:
        identifier = args.remove_test_export; assert re.fullmatch('[0-9a-f]{32}', identifier)
        folder = prefix / identifier
        raw = c._read_regular(folder / 'receipt.json', c.RECEIPT_LIMIT, root_owned=True)
        assert json.loads(raw)['raw_result_sha256'] == TEST_WITNESS
        assert set(p.name for p in folder.iterdir()) == {'request.json', 'receipt.json', 'artifact-00.bin', 'artifact-01.bin'}
        for path in folder.iterdir(): path.unlink()
        folder.rmdir(); return
    raw = c._read_regular(args.publish_test_export, c.REQUEST_LIMIT)
    assert c.digest(raw) == args.expected_sha256
    request = c.validate_request(raw)
    folder = prefix / request['request_id']; folder.mkdir(mode=0o755)
    now = int(time.time())
    receipt = {'schema': 'paw-s14-synthetic-result-v1', 'request_id': request['request_id'], 'request_sha256': c.digest(raw),
               'case_reference_sha256': request['case_reference_sha256'], 'profile': c.PROFILE, 'fixture_sha256': c.FIXTURE_SHA256,
               'producer_kind': 'local-root-verified-no-nic-synthetic', 'status': 'completed', 'raw_result_sha256': TEST_WITNESS,
               'runtime': {'vm_uuid': str(uuid.uuid4()), 'job_sha256': '1'*64, 'image_sha256': c.IMAGE_SHA256,
                           'source_inventory_sha256': '2'*64, 'bridge_contract_sha256': c.digest(Path(c.__file__).read_bytes()),
                           'source_count': 61, 'started_at': now, 'completed_at': now, 'stop_seconds': .5,
                           'writers_stopped': args.fixture_mode != 'unknown-stop'},
               'artifacts': [{'stored_as': f'artifact-{i:02d}.bin', 'bytes': len(data), 'sha256': c.digest(data)}
                             for i, data in enumerate([c.MARKER, b''])]}
    data = {'request.json': raw, 'receipt.json': c.canonical(receipt), 'artifact-00.bin': c.MARKER, 'artifact-01.bin': b''}
    for name, content in data.items():
        with (folder / name).open('xb') as stream: stream.write(content)
        (folder / name).chmod(0o444)
    if args.fixture_mode == 'artifact-symlink':
        (folder / 'artifact-00.bin').unlink(); (folder / 'artifact-00.bin').symlink_to('/dev/null')
    print(json.dumps({'test_export': str(folder), 'kvm_executed': False}))


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='store_true', help='Use checkout for development; default tests the installed wheel')
    parser.add_argument('--root-fixture', action='store_true', help='CI-only simulated trusted local producer via sudo -n')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--publish-test-export', type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--remove-test-export')
    parser.add_argument('--fixture-mode', choices=['complete', 'unknown-stop', 'artifact-symlink'], default='complete')
    args = parser.parse_args()
    if args.publish_test_export or args.remove_test_export: root_fixture(args); return
    if not sys.platform.startswith('linux'):
        print(json.dumps({'status': 'not_evaluated', 'reason': 'Linux-only local-root bridge'})); return
    environment = dict(os.environ, PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8')
    environment.pop('PYTHONPATH', None); environment.pop('PYTHONHOME', None)
    if args.source: environment['PYTHONPATH'] = str(REPO)
    prefix = [sys.executable, *([] if args.source else ['-I']), '-m', 'paw']
    with tempfile.TemporaryDirectory(prefix='paw-synthetic-bridge-') as temporary:
        root = Path(temporary); logs = []; exports = []
        source = root / 'owned.eml'
        original = b'From: Owner <owner@fixture.invalid>\r\nTo: analyst@fixture.invalid\r\nSubject: Owned synthetic integration\r\nDate: Sat, 24 Oct 2026 12:00:00 +0000\r\nMessage-ID: <owned@fixture.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nFixed harmless local workflow. No URL or attachment.\r\n'
        source.write_bytes(original)
        def cli(arguments, success=True):
            p = subprocess.run(prefix + arguments, cwd=root, env=environment, capture_output=True, text=True, timeout=120)
            logs.append({'arguments': arguments, 'returncode': p.returncode, 'stdout': p.stdout[-20000:], 'stderr': p.stderr[-10000:]})
            if args.output:
                args.output.mkdir(parents=True, exist_ok=True)
                (args.output / 'synthetic-bridge-progress.json').write_text(json.dumps({'result': 'IN_PROGRESS', 'logs': logs}, indent=2) + '\n')
            assert (p.returncode == 0) == success, logs[-1]
            return p
        try:
            cli(['quick', str(source), '--deadline', '90', '--stage-timeout', '30', '--memory-mib', '512'])
            cases = list((root / 'cases').glob('case-*')); assert len(cases) == 1
            case = cases[0]; before = snapshot(case)
            assert any(p.read_bytes() == original for p in case.rglob('*.eml'))
            cli(['verify', '--case', str(case)])
            prep = json.loads(cli(['lab-synthetic', 'prepare', '--case', str(case), '--output', str(root / 'request')]).stdout)
            request_path = Path(prep['request']); raw = request_path.read_bytes(); request = json.loads(raw)
            assert hashlib.sha256(raw).hexdigest() == prep['request_sha256']
            assert not any(key in request for key in ['source_hex', 'url', 'command'])
            missing = root / 'missing-producer-result'
            cli(['lab-synthetic', 'import', '--case', str(case), '--request', str(request_path), '--output', str(missing)], False)
            assert not missing.exists()
            if args.root_fixture:
                for mode in ['complete', 'unknown-stop', 'artifact-symlink']:
                    if mode == 'complete': info = prep
                    else: info = json.loads(cli(['lab-synthetic', 'prepare', '--case', str(case), '--output', str(root / ('request-' + mode))]).stdout)
                    exports.append(info['request_id'])
                    p = subprocess.run(['sudo', '-n', '/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                                        '--publish-test-export', info['request'], '--expected-sha256', info['request_sha256'],
                                        '--fixture-mode', mode], capture_output=True, text=True, timeout=15)
                    assert p.returncode == 0, (p.stdout, p.stderr)
                    output = root / ('import-' + mode)
                    result = cli(['lab-synthetic', 'import', '--case', str(case), '--request', info['request'], '--output', str(output)], mode == 'complete')
                    if mode == 'complete':
                        value = json.loads(result.stdout); sidecar = Path(value['result'])
                        assert sidecar == output / 'result' and value['case_unchanged'] is True
                        cli(['verify', '--case', str(sidecar)])
                        assert (sidecar / 'artifact-00.bin').read_bytes() == b'OWNED-IMMUTABLE-INPUT\n'
                        assert (sidecar / 'artifact-01.bin').read_bytes() == b''
                        cli(['lab-synthetic', 'import', '--case', str(case), '--request', info['request'], '--output', str(output)], False)
                        wrong = root / 'cases/case-wrong'; shutil.copytree(case, wrong)
                        cli(['lab-synthetic', 'import', '--case', str(wrong), '--request', info['request'], '--output', str(root / 'wrong-case-result')], False)
                        assert not (root / 'wrong-case-result').exists()
                    else: assert not output.exists()
            assert snapshot(case) == before
            cli(['verify', '--case', str(case)])
            result = {'result': 'PASS', 'real_analysis': True, 'original_and_seal_unchanged': True,
                      'root_receipt_fixture': args.root_fixture, 'kvm_executed': False,
                      'installed_mode': not args.source, 'logs': logs}
        finally:
            cleanup_failures = []
            for identifier in exports:
                p = subprocess.run(['sudo', '-n', '/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                                    '--remove-test-export', identifier], capture_output=True, text=True, timeout=15)
                if p.returncode: cleanup_failures.append({'request_id': identifier, 'stderr': p.stderr})
            if cleanup_failures: raise RuntimeError('Root fixture cleanup failed: ' + json.dumps(cleanup_failures))
        if args.output:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / 'synthetic-bridge-integration.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: v for k, v in result.items() if k != 'logs'}))


if __name__ == '__main__': main()
