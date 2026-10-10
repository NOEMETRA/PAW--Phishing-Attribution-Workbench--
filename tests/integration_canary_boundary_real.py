"""Actual offline analysis and rejected canary processes; no live collection."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.evidence import seal_case
from paw.core.network_policy import offline_policy, violations
from paw.core.verify import verify_case
from paw.canary.server import run_canary

LAUNCHER = REPO/'start_canary.py'
RAW = b'From: analyst@example.com\r\nSubject: Canary integrity regression\r\n\r\nplain regression fixture\r\n'


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


def invoke(root, logs, name, kind, arguments):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    # Launch a real CLI/module/console/checkout process. Bootstrap the common CLI
    # before guarding dispatch, as normal CLI startup does. A cold urllib3 import
    # probes local IPv6 support with a socket; that is not canary deployment.
    # During dispatch, even a swallowed socket/SMTP/subprocess attempt fails this
    # check instead of masquerading as an unavailable-feature rejection.
    source = """import runpy,sys
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
from paw.__main__ import main as cli_main
sys.argv=%r
try:
    with offline_policy():
        %s
finally:
    assert not violations(),violations()
    print('CANARY_BOUNDARY_NO_BLOCKED_OPERATIONS')
""" % (str(REPO), ['entry', *arguments], {
        'cli': "cli_main()",
        'module': "runpy.run_module('paw.canary.server',run_name='__main__',alter_sys=True)",
        'console': "from paw.canary.server import main; main()",
        'launcher': "sys.path.remove(%r); runpy.run_path(%r,run_name='__main__')" % (str(REPO), str(LAUNCHER)),
    }[kind])
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', source], cwd=root,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    (logs/(name+'.log')).write_bytes(result.stdout)
    text = result.stdout.decode('utf-8')
    assert 'CANARY_BOUNDARY_NO_BLOCKED_OPERATIONS' in text, text
    return result, text


def main():
    with tempfile.TemporaryDirectory(prefix='paw-canary-boundary-', dir=REPO.parent) as temporary:
        base = Path(temporary)
        root = base/'run'; root.mkdir()
        logs = base/'logs'; logs.mkdir()
        (root/'input.eml').write_bytes(RAW)
        env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        result = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'paw', 'full', 'input.eml',
            '--no-egress', '--deadline', '60', '--stage-timeout', '30'], cwd=root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        (logs/'full.log').write_bytes(result.stdout)
        assert result.returncode == 0, result.stdout.decode('utf-8')
        case, = (root/'cases').glob('case-*')
        control, = (p for p in (root/'jobs').iterdir() if p.is_dir())
        supervisor = json.loads((control/'supervisor.json').read_text(encoding='utf-8'))
        execution = json.loads((case/'execution.json').read_text(encoding='utf-8'))
        assert supervisor['tree_stopped'] and supervisor['returncode'] == 0, supervisor
        assert execution['no_egress'] and not execution['blocked_operations'], execution
        assert (case/'input.eml').read_bytes() == RAW and verify_case(str(case))

        # These two extra directories are metadata fixtures, not simulated
        # analyses/live writers: rejection must not depend on ownership or seal.
        unsealed = root/'cases'/'legacy-unsealed'; unsealed.mkdir()
        (unsealed/'headers.json').write_text('{"urls":[]}', encoding='utf-8')
        owned = root/'cases'/'blocked-owner'; owned.mkdir()
        identifier = 'analysis_'+'1'*32
        (owned/'manifest.json').write_text(json.dumps({'analysis_job': identifier}), encoding='utf-8')
        (root/'jobs'/(identifier+'.json')).write_text(json.dumps({'origin':'cli','status':'running'}), encoding='utf-8')
        seal_case(owned)
        outside = base/'outside'; outside.mkdir()
        (outside/'preserve.txt').write_bytes(b'outside case must remain unchanged')
        before = snapshot(root), snapshot(outside)

        cwd, argv, path = Path.cwd(), sys.argv[:], sys.path[:]
        try:
            os.chdir(root)
            count = len(violations())
            with offline_policy():
                runpy.run_path(str(LAUNCHER), run_name='canary_import_check')
                runpy.run_path(str(REPO/'paw'/'canary'/'server.py'), run_name='canary_import_check')
            assert Path.cwd() == root and sys.argv == argv and sys.path == path
            assert len(violations()) == count
            attempts = []
            gate = {'active': False}
            def forbid_case_io(event, args):
                if gate['active'] and (event == 'open' or event.startswith('os.')):
                    attempts.append(event)
                    raise AssertionError('Canary rejection attempted filesystem access: '+event)
            sys.addaudithook(forbid_case_io)
            targets = [case.name, unsealed.name, owned.name, 'missing', '../outside',
                       str(outside), str(case), None]
            with offline_policy():
                for target in targets:
                    gate['active'] = True
                    try:
                        try: run_canary(target, 8787)
                        except RuntimeError as exc:
                            assert 'Canary deployment unavailable' in str(exc), exc
                        else: raise AssertionError('Canary deployment was accepted')
                    finally: gate['active'] = False
            assert not attempts and len(violations()) == count
        finally:
            os.chdir(cwd)

        for kind in ('cli', 'module', 'console', 'launcher'):
            prefix = ['canary'] if kind == 'cli' else []
            for number, target in enumerate(targets[:-1]):
                result, text = invoke(root, logs, f'{kind}-{number}', kind,
                    [*prefix, '--case', target, '--port', '8787'])
                assert result.returncode == 1 and 'Canary deployment unavailable' in text, text
                assert (snapshot(root), snapshot(outside)) == before
            result, text = invoke(root, logs, kind+'-missing-argument', kind, prefix)
            assert result.returncode == 2, text
            result, text = invoke(root, logs, kind+'-help', kind, [*prefix, '--help'])
            assert result.returncode == 0 and 'unavailable' in text.lower(), text
        result, text = invoke(root, logs, 'topic-help', 'cli', ['help','canary'])
        assert result.returncode == 0 and 'unavailable' in text.lower(), text
        # Direct checkout invocation exercises its bootstrap without any parent
        # PYTHONPATH or -c sys.path setup, including obsolete positional syntax.
        env.pop('PYTHONPATH', None)
        for args in (['--case', case.name], [case.name, '8787'], []):
            result = subprocess.run([sys.executable, '-X', 'utf8', str(LAUNCHER), *args],
                cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            assert result.returncode != 0, result.stdout.decode('utf-8')
        assert (snapshot(root), snapshot(outside)) == before
        assert (case/'input.eml').read_bytes() == RAW and verify_case(str(case))
        assert verify_case(str(owned))
    print('PASS: actual supervised offline full case remains byte-identical and sealed; '
          'CLI/module/console/checkout canary entries reject completed, unsealed, '
          'blocked-owner metadata, missing and path arguments without network attempts; '
          'inert imports, no direct case I/O, honest help and nonzero launcher errors.')


if __name__ == '__main__': main()
