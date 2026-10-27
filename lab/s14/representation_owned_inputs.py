"""Finite owned P3 data and unprivileged PAW case preparation; never a launcher.

A reviewed Root recipe must drop UID/capabilities before invoking this client,
distrust its output and independently restrict approval to the immutable-owned
exact expected bytes. The fixed invocation lives in the separately reviewed producer recipe.
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
import stat
import time

SLOTS = {'positive', 'prefix', 'qp', 'paused-refusal', 'owner-loss', 'protocol-loss', 'smoke'}


def identity(raw):
    require(type(raw) is str and len(raw) <= 65536, 'owned_client_process_status_budget')
    fields = {}
    for line in raw.splitlines():
        if ':' in line:
            key, value = line.split(':', 1); require(key not in fields, 'owned_client_duplicate_process_status')
            fields[key] = value.split()
    require(fields.get('Uid') == ['1000']*4 and fields.get('Gid') == ['1000']*4 and fields.get('Groups') == [] and
            fields.get('NoNewPrivs') == ['1'], 'owned_client_uid_groups_or_nnp')
    for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        values = fields.get(key)
        require(type(values) is list and len(values) == 1 and re.fullmatch('[0-9a-fA-F]{1,16}', values[0]) and
                int(values[0], 16) == 0, 'owned_client_capabilities')
    return {'uid': 1000, 'gid': 1000, 'groups': [], 'no_new_privileges': True, 'capabilities': 'all zero including bounding'}


def await_gate(path, tag, nonce):
    """Root's protected acknowledgment follows independent kernel PID checks.

    Does not grant execution: this process remains the unprivileged PAW client.
    """
    identity(Path('/proc/self/status').read_text())
    require(type(tag) is str and re.fullmatch('[a-z-]{1,96}', tag) and path.is_absolute() and
            path.name == 'go-'+tag+'.json' and '..' not in path.parts, 'owned_client_gate_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            info = os.fstat(fd); require(info.st_uid == 0 and not info.st_mode & 0o022, 'owned_client_gate_ancestor')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd); require(info.st_uid == 0 and not info.st_mode & 0o022, 'owned_client_gate_parent')
        deadline = time.monotonic()+15
        while True:
            try: leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            except (FileNotFoundError, PermissionError):
                require(time.monotonic() < deadline, 'owned_client_gate_deadline'); time.sleep(.05); continue
            try:
                before = os.fstat(leaf)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022 and
                        before.st_nlink == 1 and before.st_size <= 1024, 'owned_client_gate_file')
                raw = os.read(leaf, 1025); after = os.fstat(leaf)
                require(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_mtime_ns) ==
                        (after.st_dev, after.st_ino, after.st_mtime_ns), 'owned_client_gate_changed')
                value = json.loads(raw)
                require(value == {'schema': 'paw-s14-owned-client-go-v1', 'nonce': nonce, 'tag': tag, 'pid': os.getpid()} and
                        type(value['pid']) is int, 'owned_client_gate_binding')
                return
            finally: os.close(leaf)
    finally: os.close(fd)


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


def prepare(workspace, nonce, source_tree=None, profile=None):
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
    require(profile is None or type(profile) is str and profile in {'python', 'html'}, 'owned_client_profile')
    for entry in fixtures(nonce):
        if profile is not None and entry['profile'] != profile: continue
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


def next_request(workspace, nonce, profile, slot, source_tree=None, *, collect=False):
    require(os.geteuid() != 0 and type(profile) is str and profile in {'python', 'html'} and
            type(slot) is str and slot in SLOTS, 'owned_client_fixed_request_slot')
    if source_tree is not None: sys.path.insert(0, str(Path(source_tree).resolve(strict=True)))
    import paw
    from paw.core import representation_bridge as bridge
    from paw.core.job_registry import require_stopped_case
    from paw.core.verify import verify_case
    package = Path(paw.__file__).resolve()
    if source_tree is None: require(package.is_relative_to(Path(sys.prefix).resolve()), 'owned_installed_PAW_required')
    else: require(package.is_relative_to(Path(source_tree).resolve()), 'owned_source_PAW_required')
    workspace = Path(workspace).absolute()
    name = profile+('-selected' if profile == 'python' else '-original') if slot == 'positive' else profile+('-qp' if slot == 'qp' else '-prefix')
    entry = next(v for v in fixtures(nonce) if v['name'] == name)
    prepared = json.loads((workspace/'prepared.json').read_bytes())
    require(prepared['nonce'] == nonce and prepared['mode'] == ('source' if source_tree else 'installed'), 'owned_client_prepared_context')
    row = next(v for v in prepared['cases'] if v['name'] == name)
    case_id = Path(row['case']).name
    require(re.fullmatch('case-forensic-[0-9a-f]{32}', case_id), 'owned_client_case_id')
    case = workspace/'cases'/case_id; require_stopped_case(case)
    require(inventory(case) == row['case_inventory'] and (workspace/(name+'.bin')).read_bytes() == entry['original'],
            'owned_client_prepared_case_changed')
    before = inventory(case)
    with redirect_stdout(io.StringIO()): require(verify_case(case), 'owned_client_case_seal')
    slots = workspace/'slots'; slots.mkdir(mode=0o700, exist_ok=True); target = slots/slot
    if not collect:
        graph = json.loads((case/'report/representations.json').read_bytes())
        selected = [v for v in graph['nodes'] if v['kind'] == entry['kind'] and (case/v['blob_path']).read_bytes() == entry['selected']]
        require(len(selected) == 1, 'owned_client_unique_slot_node')
        value = bridge.prepare(case, selected[0]['id'], profile, target)
        validate_owned(Path(value['request']).read_bytes(), entry, bridge)
    else:
        raw = (target/'request.json').read_bytes(); validate_owned(raw, entry, bridge)
        value = bridge.import_result(case, target/'request.json', workspace/('sidecar-'+slot))
    require(inventory(case) == before, 'owned_client_original_case_changed')
    return {'result': 'PASS', 'phase': 'import' if collect else 'request', 'slot': slot, 'case': str(case),
            'execution_authorized': False, 'original_case_unchanged': True, 'client_result': value}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path); parser.add_argument('--nonce', required=True)
    parser.add_argument('--source-tree', type=Path)
    parser.add_argument('--profile', choices=['python', 'html'])
    parser.add_argument('--phase', choices=['prepare', 'request', 'import'], default='prepare')
    parser.add_argument('--slot', choices=sorted(SLOTS)); parser.add_argument('--gate-file', type=Path); parser.add_argument('--gate-tag')
    args = parser.parse_args()
    require((args.gate_file is None) == (args.gate_tag is None), 'owned_client_gate_pair')
    if args.gate_file is not None: await_gate(args.gate_file, args.gate_tag, args.nonce)
    if args.phase == 'prepare':
        require(args.slot is None, 'owned_client_prepare_without_slot')
        result = prepare(args.workspace, args.nonce, args.source_tree, args.profile)
    else: result = next_request(args.workspace, args.nonce, args.profile, args.slot, args.source_tree, collect=args.phase == 'import')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
