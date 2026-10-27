"""Finite owned P3 data and unprivileged PAW case preparation; never a launcher.

A reviewed Root recipe must drop UID/capabilities before invoking this client,
distrust its output and independently restrict approval to the immutable-owned
exact expected bytes. No such invocation is installed by this module.
"""
import argparse
import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def require(value, reason):
    if not value: raise ValueError(reason)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def fixtures(nonce):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'owned_representation_nonce')
    python = ('print("OWNED-REPRESENTATION-'+nonce+'")\n').encode('ascii')
    html = ('<!doctype html><meta charset="utf-8"><script>document.title="OWNED-REPRESENTATION-'+nonce+'";</script>').encode('ascii')
    # The invalid suffix is outside complete quartets; do not assume recovery
    # retains bytes from an incomplete padded quartet. This is fixture design,
    # not a relaxation/change to the existing forensic decoder.
    python += b'\n'*(-len(python) % 3); html += b'\n'*(-len(html) % 3)
    def mime(source, kind, encoding):
        body = base64.b64encode(source) if encoding == 'base64' else source.replace(b'=', b'=3D').replace(b'<', b'=3C')
        return ('Content-Type: '+kind+'\r\nContent-Transfer-Encoding: '+encoding+'\r\n\r\n').encode()+body
    return [
        {'name': 'python-selected', 'profile': 'python', 'interpretation': 'mime', 'kind': 'parser_selected_payload',
         'original': mime(python, 'text/x-python', 'base64'), 'selected': python},
        {'name': 'python-prefix', 'profile': 'python', 'interpretation': 'mime', 'kind': 'partial_decoded_candidate',
         'original': mime(python, 'text/x-python', 'base64')+b'Z', 'selected': python},
        {'name': 'python-qp', 'profile': 'python', 'interpretation': 'mime', 'kind': 'decoded_candidate',
         'original': mime(python, 'text/x-python', 'quoted-printable'), 'selected': python},
        {'name': 'html-original', 'profile': 'html', 'interpretation': 'html-utf8', 'kind': 'original',
         'original': html, 'selected': html},
        {'name': 'html-prefix', 'profile': 'html', 'interpretation': 'mime', 'kind': 'partial_decoded_candidate',
         'original': mime(html, 'text/html', 'base64')+b'Z', 'selected': html},
        {'name': 'html-qp', 'profile': 'html', 'interpretation': 'mime', 'kind': 'decoded_candidate',
         'original': mime(html, 'text/html', 'quoted-printable'), 'selected': html},
    ]


def inventory(case):
    return {p.relative_to(case).as_posix(): digest(p.read_bytes()) for p in case.rglob('*') if p.is_file()}


def validate_owned(raw, entry, bridge):
    request = bridge.validate_request(raw); selected = request['candidate']; binding = request['binding']
    require(selected['profile'] == bridge.PROFILES[entry['profile']][0] and
            selected['source']['data_hex'] == entry['selected'].hex() and
            binding['original_source']['sha256'] == digest(entry['original']) and
            binding['original_source']['bytes'] == len(entry['original']), 'owned_representation_bytes')
    row = next(v for v in binding['derivation']['nodes'] if v['id'] == binding['derivation']['selected'])
    require(row['kind'] == entry['kind'] and row['sha256'] == digest(entry['selected']), 'owned_representation_selection')
    return request


def prepare(workspace, nonce, source_tree=None):
    require(os.geteuid() != 0, 'owned_PAW_client_must_run_unprivileged')
    workspace = Path(workspace).absolute(); workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
    if source_tree is not None:
        source_tree = Path(source_tree).resolve(strict=True); sys.path.insert(0, str(source_tree))
    import paw
    from paw.core import representation_bridge as bridge
    from paw.core.job_registry import require_stopped_case
    from paw.core.verify import verify_case
    package = Path(paw.__file__).resolve()
    if source_tree is None: require(package.is_relative_to(Path(sys.prefix).resolve()), 'owned_installed_PAW_required')
    else: require(package.is_relative_to(source_tree), 'owned_source_PAW_required')
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1'); env.pop('PYTHONHOME', None); env.pop('PYTHONPATH', None)
    if source_tree is not None: env['PYTHONPATH'] = str(source_tree)
    def cli(arguments):
        result = subprocess.run([sys.executable, '-P', '-B', '-m', 'paw', *arguments], cwd=workspace,
                                env=env, capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'owned_PAW_cli_failed:'+result.stderr[-2000:])
        return json.loads(result.stdout)
    rows = []
    for entry in fixtures(nonce):
        original = workspace/(entry['name']+'.bin'); original.write_bytes(entry['original']); original.chmod(0o400)
        analyzed = cli(['inspect-representations', str(original), '--interpretation', entry['interpretation']])
        require(analyzed['supervisor']['tree_stopped'] is True, 'owned_PAW_tree_not_stopped')
        case = workspace/'cases'/analyzed['worker']['case_id']; require_stopped_case(case)
        with redirect_stdout(io.StringIO()): require(verify_case(case), 'owned_PAW_case_seal')
        before = inventory(case); graph = json.loads((case/'report/representations.json').read_bytes())
        matching = [v for v in graph['nodes'] if v['kind'] == entry['kind'] and
                    (case/v['blob_path']).read_bytes() == entry['selected']]
        require(len(matching) == 1, 'owned_PAW_explicit_unique_node:'+entry['name'])
        destination = workspace/(entry['name']+'-request')
        prepared = cli(['lab-representation', 'prepare', '--case', str(case), '--node', matching[0]['id'],
                        '--profile', entry['profile'], '--output', str(destination)])
        raw = Path(prepared['request']).read_bytes(); request = validate_owned(raw, entry, bridge)
        require(prepared['execution_authorized'] is False and inventory(case) == before and
                request['binding']['case_reference']['case_id'] == case.name and original.read_bytes() == entry['original'],
                'owned_PAW_original_or_execution_authority')
        require(destination.stat().st_mode & 0o777 == 0o700 and all((destination/name).stat().st_mode & 0o777 == 0o400
                for name in ['request.json', 'candidate.json']), 'owned_PAW_request_privacy')
        rows.append({'name': entry['name'], 'profile': entry['profile'], 'kind': entry['kind'], 'case': str(case),
            'original_sha256': digest(entry['original']), 'source_sha256': digest(entry['selected']),
            'request': prepared['request'], 'request_sha256': digest(raw), 'case_inventory': before})
    report = {'result': 'PASS', 'scope': 'unprivileged owned case/selection preparation only; no grant, VM or I08',
              'mode': 'source' if source_tree else 'installed', 'nonce': nonce, 'package': str(package), 'cases': rows,
              'vm_started': False, 'execution_authorized': False}
    target = workspace/'prepared.json'; target.write_text(json.dumps(report, indent=2)+'\n'); target.chmod(0o400)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path); parser.add_argument('--nonce', required=True)
    parser.add_argument('--source-tree', type=Path)
    args = parser.parse_args(); print(json.dumps(prepare(args.workspace, args.nonce, args.source_tree), indent=2))


if __name__ == '__main__': main()
