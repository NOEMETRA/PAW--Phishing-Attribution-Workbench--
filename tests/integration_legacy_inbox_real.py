"""Real legacy launcher processes; constructed EMLs are regression fixtures."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.network_policy import offline_policy, violations
from paw.core.verify import verify_case

LAUNCHER = REPO/'tools'/'analyze_inbox.py'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def invoke(root, arguments):
    root.mkdir()
    # Exercise the standalone checkout bootstrap, without inherited PYTHONPATH.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', str(LAUNCHER), *arguments],
        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
    (root/'launcher.log').write_bytes(result.stdout)
    return result


def check_completed(root, expected):
    control, = (p for p in (root/'jobs').iterdir() if p.is_dir())
    request = read(control/'request.json')
    assert request['no_egress'] is True and request['profile']=='strict', request
    assert request['stix'] and request['abuse'] and not request['anchor'], request
    supervisor = read(control/'supervisor.json')
    assert supervisor['tree_stopped'] and supervisor['status']=='exited', supervisor
    value = read(control/'result.json')
    assert len(value['case_ids'])==len(expected), value
    observed = set()
    for identifier in value['case_ids']:
        case = root/'cases'/identifier
        name = read(case/'manifest.json')['source_name']
        observed.add(name)
        assert (case/'input.eml').read_bytes()==expected[name]
        execution = read(case/'execution.json')
        assert execution['no_egress'] is True and not execution['blocked_operations'], execution
        assert verify_case(str(case)), case
    assert observed==set(expected)
    return control, value


def main():
    with tempfile.TemporaryDirectory(prefix='paw-legacy-inbox-', dir=REPO.parent) as temporary:
        base = Path(temporary)
        imported = base/'import'; imported.mkdir()
        inbox = imported/'inbox'; inbox.mkdir()
        # This name caused the old module to read a message and write output on import.
        legacy_name = 'Ultimo tentativo per dacangs@hotmail.it, il tuo kit di emergenza per auto GRATUITO ti aspetta....eml'
        (inbox/legacy_name).write_bytes(b'From: a@example.com\r\n\r\nplain fixture')
        (imported/'paw'/'intelligence').mkdir(parents=True)
        before = {p.relative_to(imported):p.read_bytes() for p in imported.rglob('*') if p.is_file()}
        cwd, argv = Path.cwd(), sys.argv[:]
        blocked_before = len(violations())
        try:
            os.chdir(imported)
            with offline_policy():
                runpy.run_path(str(LAUNCHER), run_name='legacy_import_check')
        finally:
            os.chdir(cwd)
        after = {p.relative_to(imported):p.read_bytes() for p in imported.rglob('*') if p.is_file()}
        assert before==after, 'Import read/analyzed the fixed inbox sample and wrote output'
        assert sys.argv==argv and len(violations())==blocked_before

        inputs = base/'inputs'; inputs.mkdir()
        raw = b'From: a@example.com\r\nSubject: Offline fixture\r\n\r\nhttp://127.0.0.1:9/never-fetch\r\n'
        source = inputs/'a.eml'; source.write_bytes(raw)
        (inputs/'b.EML').write_bytes(raw.replace(b'Offline fixture', b'Second fixture'))
        (inputs/'ignored.txt').write_text('ignored', encoding='utf-8')
        expected = {p.name:p.read_bytes() for p in inputs.iterdir() if p.suffix.lower()=='.eml'}
        for name, argument, samples in [('single', source, {'a.eml':raw}), ('batch', inputs, expected)]:
            root = base/name
            result = invoke(root, [str(argument), '--deadline', '60', '--stage-timeout', '30'])
            assert result.returncode==0, result.stdout.decode('utf-8')
            _, value = check_completed(root, samples)
            assert value['status']=='completed', value

        separator = base/'separator'
        separator.mkdir()
        (separator/'-sample.eml').write_bytes(raw)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
        env.pop('PYTHONPATH', None)
        result = subprocess.run([sys.executable, '-X', 'utf8', str(LAUNCHER), '--', '-sample.eml'],
            cwd=separator, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        (separator/'launcher.log').write_bytes(result.stdout)
        assert result.returncode==0, result.stdout.decode('utf-8')
        _, value = check_completed(separator, {'-sample.eml':raw})
        assert value['status']=='completed', value

        (inputs/'bad.msg').write_bytes(b'not an Outlook MSG')
        partial = base/'partial'
        result = invoke(partial, [str(inputs), '--deadline', '60', '--stage-timeout', '30'])
        assert result.returncode==1, result.stdout.decode('utf-8')
        _, value = check_completed(partial, expected)
        assert value['status']=='partial' and value['failed_inputs'][0]['input']=='bad.msg', value

        timeout = base/'timeout'
        result = invoke(timeout, [str(source), '--deadline', '.05'])
        assert result.returncode==1, result.stdout.decode('utf-8')
        control, = (p for p in (timeout/'jobs').iterdir() if p.is_dir())
        outcome = read(control/'supervisor.json')
        assert outcome['status']=='timed_out' and outcome['tree_stopped'], outcome
        assert read(control.with_suffix('.json'))['status']=='timed_out'
        for name, args, status in [('help', ['--help'], 0), ('missing', [], 2),
                                  ('bad-option', [str(source), '--online'], 2)]:
            root = base/name
            result = invoke(root, args)
            assert result.returncode==status, result.stdout.decode('utf-8')
            assert not (root/'jobs').exists() and not (root/'cases').exists()
    print('PASS: import is inert; real single/batch/end-of-options full analyses are supervised, strict, offline and sealed; partial batch and deadline errors retain honest state; help/missing input/unsupported online option start no job. No analysis is mocked.')


if __name__=='__main__':
    main()
