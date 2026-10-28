"""Actual owned forensic CLI→selection custody, source/installed; no VM or grant."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
PYTHON = b'print("owned source is only transported, never executed on host")\n'
FIXTURES = [
    ('html-prefix', b'Content-Type: text/html; charset=us-ascii\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+b3duZWQ8L2I+Z',
     'mime', 'partial_decoded_candidate', 'html', b'<b>owned</b>'),
    ('html-selected', b'Content-Type: text/html\r\n\r\n<b>owned selected</b>',
     'mime', 'parser_selected_payload', 'html', b'<b>owned selected</b>'),
    ('html-original', b'<script>document.title="owned inert transfer"</script>',
     'html-utf8', 'original', 'html', b'<script>document.title="owned inert transfer"</script>'),
    ('html-qp', b'Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<b>=6Fwned=3C/b>',
     'mime', 'decoded_candidate', 'html', b'<b>owned</b>'),
    ('python-prefix', b'Content-Type: text/x-python\r\nContent-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(PYTHON)+b'Z',
     'mime', 'partial_decoded_candidate', 'python', PYTHON),
    ('python-selected', b'Content-Type: text/x-python\r\nContent-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(PYTHON),
     'mime', 'parser_selected_payload', 'python', PYTHON),
]

# Load only this fixed inert byte-fixture helper under installed Python -P.
_spec = importlib.util.spec_from_file_location('owned_linux_bytes', Path(__file__).with_name('linux_profile_fixtures.py'))
_fixture = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_fixture)
_ELF = _fixture.executable()
_SHELL = b'#!/not/a/selector\nprintf "owned native custody"\n'
_SHELL_MAX = b'#'+b'x'*(64*1024-2)+b'\n'
_ELF_MAX = _ELF+bytes(1024**2-len(_ELF))
FIXTURES += [
    ('shell-max', _SHELL_MAX, 'posix-shell-utf8', 'original', 'shell', _SHELL_MAX),
    ('shell-derived', b'Content-Type: text/x-shellscript\r\nContent-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(_SHELL),
     'mime', 'parser_selected_payload', 'shell', _SHELL),
    ('elf-max', _ELF_MAX, 'elf64-x86_64', 'original', 'elf', _ELF_MAX),
    ('elf-pie', _fixture.executable('/lib64/ld-linux-x86-64.so.2', kind=3), 'elf64-x86_64', 'original', 'elf',
     _fixture.executable('/lib64/ld-linux-x86-64.so.2', kind=3)),
]


def inventory(case):
    return {str(p.relative_to(case)): hashlib.sha256(p.read_bytes()).hexdigest() for p in case.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed', action='store_true'); parser.add_argument('--output', type=Path)
    args = parser.parse_args(); env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    if not args.installed: env['PYTHONPATH'] = str(REPO); sys.path.insert(0, str(REPO))
    import paw
    from paw.core import representation_bridge, native_bridge
    from paw.core.job_registry import require_stopped_case
    from paw.core.verify import verify_case
    if args.installed:
        assert Path(paw.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
        assert not Path(paw.__file__).resolve().is_relative_to(REPO)
    rows = []; refusals = 0
    root = Path(tempfile.mkdtemp(prefix='paw-selection-acceptance-')); completed = False
    try:
        workspace = root/'workspace'; workspace.mkdir(); (workspace/'cases').mkdir(mode=0o755)
        (workspace/'paw.py').write_text('raise RuntimeError("workspace import forbidden")')
        def cli(arguments, expected=0):
            run = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', *arguments], cwd=workspace,
                                 env=env, capture_output=True, text=True, timeout=60)
            assert (run.returncode == 0) == (expected == 0), (arguments, run.stdout, run.stderr)
            return json.loads(run.stdout) if expected == 0 else None
        first_request = None; first_case = None
        for name, raw, interpretation, kind, profile, selected_bytes in FIXTURES:
            bridge = native_bridge if profile in {'shell', 'elf'} else representation_bridge
            command = 'lab-native' if profile in {'shell', 'elf'} else 'lab-representation'
            source = root/(name+'.bin'); source.write_bytes(raw); source.chmod(0o400)
            result = cli(['inspect-representations', str(source), '--interpretation', interpretation])
            assert result['supervisor']['tree_stopped'] is True
            case = workspace/'cases'/result['worker']['case_id']; require_stopped_case(case); assert verify_case(case)
            graph = json.loads((case/'report/representations.json').read_bytes())
            selected = next(row['id'] for row in graph['nodes'] if row['kind'] == kind and
                            (case/row['blob_path']).read_bytes() == selected_bytes)
            before = inventory(case); destination = root/(name+'-request')
            prepared = cli([command, 'prepare', '--case', str(case), '--node', selected,
                            '--profile', profile, '--output', str(destination)])
            request_raw = Path(prepared['request']).read_bytes(); request = bridge.validate_request(request_raw)
            assert request['candidate']['source']['data_hex'] == selected_bytes.hex()
            assert request['binding']['derivation']['selected'] == selected
            assert request['binding']['original_source']['sha256'] == hashlib.sha256(raw).hexdigest()
            assert request['binding']['case_reference']['case_id'] == case.name
            assert prepared['execution_authorized'] is False and inventory(case) == before
            assert destination.stat().st_mode & 0o777 == 0o700
            assert all((destination/p).stat().st_mode & 0o777 == 0o400 for p in ['request.json', 'candidate.json'])
            if first_request is None: first_request, first_case = prepared['request'], case
            missing = root/(name+'-missing-producer')
            cli([command, 'import', '--case', str(case), '--request', prepared['request'], '--output', str(missing)], expected=1)
            assert not missing.exists(); refusals += 1
            unknown = root/(name+'-unknown-node')
            cli([command, 'prepare', '--case', str(case), '--node', '0'*64,
                 '--profile', profile, '--output', str(unknown)], expected=1)
            assert not unknown.exists(); refusals += 1
            if case != first_case:
                wrong = root/(name+'-wrong-parent')
                cli([command, 'import', '--case', str(case), '--request', first_request,
                     '--output', str(wrong)], expected=1)
                assert not wrong.exists(); refusals += 1
            assert inventory(case) == before and verify_case(case) and source.read_bytes() == raw
            rows.append({'fixture': name, 'profile': profile, 'custody_command': command, 'node': selected, 'node_kind': kind,
                         'original_sha256': hashlib.sha256(raw).hexdigest(), 'selected_sha256': hashlib.sha256(selected_bytes).hexdigest(),
                         'lineage_nodes': len(request['binding']['derivation']['nodes']), 'execution_authorized': False})
        report = {'result': 'PASS', 'mode': 'installed' if args.installed else 'source', 'cases': rows,
                  'refusals': refusals, 'vm_started': False, 'root_grants_issued': 0,
                  'scope': 'actual CLI custody/refusals only; separate root runtime/I08 acceptance still required'}
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2)); completed = True
    finally:
        # Delete only when every owned analysis has externally known stop. Any
        # exceptional/unconfirmed run keeps its original control and case data.
        if completed:
            from paw.core.job_registry import require_stopped_case
            import shutil
            for case in root.glob('workspace/cases/case-*'):
                if case.is_dir(): require_stopped_case(case)
            shutil.rmtree(root)
        else: print('Preserved selection acceptance: '+str(root), file=sys.stderr)


if __name__ == '__main__': main()
