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
import struct
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


def javascript_fixture(nonce):
    """Owned maximum-size classic script and independently encoded HTML bytes.

    The host encodes data only. Root regenerates this exact nonce-bound pair
    before issuing any grant; the unprivileged PAW client cannot choose bytes.
    """
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}', nonce), 'owned_javascript_nonce')
    # Keep the input at its maximum while making the owned page's resulting
    # DOM small. Otherwise --dump-dom echoes this entire Base64 script URL,
    # exceeding the separate unchanged256KiB output budget by construction.
    prefix = ('document.title="OWNED-REPRESENTATION-'+nonce+'";document.currentScript.remove();\n/*').encode('ascii')
    original = prefix + b'x'*(256*1024-len(prefix)-3) + b'*/\n'
    selected = (b'<!doctype html><meta charset="utf-8"><title>PAW explicit JavaScript view</title>\n'
                b'<script src="data:text/javascript;charset=utf-8;base64,'+base64.b64encode(original)+b'"></script>\n')
    require(len(original) == 256*1024 and len(selected) <= 512*1024, 'owned_javascript_budget')
    return {'name': 'javascript-original', 'profile': 'html', 'interpretation': 'javascript-utf8',
            'kind': 'browser_html_candidate', 'original': original, 'selected': selected,
            'javascript_browser': True}


def validate_owned(raw, entry, bridge):
    request = bridge.validate_request(raw); selected = request['candidate']; binding = request['binding']
    spec = bridge.PROFILES[entry['profile']]
    engine = spec.engine if entry['profile'] in {'shell', 'elf'} else spec[0]
    require(selected['profile'] == engine and
            selected['source']['data_hex'] == entry['selected'].hex() and
            binding['original_source']['sha256'] == digest(entry['original']) and
            binding['original_source']['bytes'] == len(entry['original']), 'owned_representation_bytes')
    row = next(v for v in binding['derivation']['nodes'] if v['id'] == binding['derivation']['selected'])
    require(row['kind'] == entry['kind'] and row['sha256'] == digest(entry['selected']), 'owned_representation_selection')
    if entry.get('javascript_browser') is True:
        require(len(binding['derivation']['nodes']) == 2 and row['parents'] == [binding['derivation']['root']] and
                row['complete_transform'] is True and row['transform'] == {
                    'name': 'javascript-to-browser-html', 'version': 1, 'parameters': {
                        'input_charset': 'utf-8', 'errors': 'strict', 'embedding': 'base64-data-classic-script',
                        'source_sha256': digest(entry['original']), 'environment': 'new_document_and_origin'}},
                'owned_javascript_exact_derivation')
    return request


def prepare(workspace, nonce, source_tree=None, profile=None):
    require(os.geteuid() != 0, 'owned_PAW_client_must_run_unprivileged')
    workspace = Path(workspace).absolute(); workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
    if source_tree is not None:
        source_tree = Path(source_tree).resolve(strict=True); sys.path.insert(0, str(source_tree))
    import paw
    if profile in {'shell', 'elf'}:
        from paw.core import native_bridge as bridge
    else:
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
    require(profile is None or type(profile) is str and profile in {'python', 'html', 'shell', 'elf', 'javascript'}, 'owned_client_profile')
    entries = ([javascript_fixture(nonce)] if profile == 'javascript' else
               native_fixtures(nonce, profile) if profile in {'shell', 'elf'} else fixtures(nonce))
    for entry in entries:
        if profile is not None and entry['profile'] != ('html' if profile == 'javascript' else profile): continue
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
        prepared = cli(['lab-native' if profile in {'shell','elf'} else 'lab-representation', 'prepare', '--case', str(case), '--node', matching[0]['id'],
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
    require(os.geteuid() != 0 and type(profile) is str and profile in {'python', 'html', 'shell', 'elf', 'javascript'} and
            type(slot) is str and slot in (set(NATIVE_CASES[profile]) | {'smoke'} if profile in {'shell','elf'} else
                                          {'smoke'} if profile == 'javascript' else SLOTS), 'owned_client_fixed_request_slot')
    if source_tree is not None: sys.path.insert(0, str(Path(source_tree).resolve(strict=True)))
    import paw
    if profile in {'shell', 'elf'}:
        from paw.core import native_bridge as bridge
    else:
        from paw.core import representation_bridge as bridge
    from paw.core.job_registry import require_stopped_case
    from paw.core.verify import verify_case
    package = Path(paw.__file__).resolve()
    if source_tree is None: require(package.is_relative_to(Path(sys.prefix).resolve()), 'owned_installed_PAW_required')
    else: require(package.is_relative_to(Path(source_tree).resolve()), 'owned_source_PAW_required')
    workspace = Path(workspace).absolute()
    name = profile+('-selected' if profile == 'python' else '-original') if slot == 'positive' else profile+('-qp' if slot == 'qp' else '-prefix')
    if profile == 'javascript':
        entry = javascript_fixture(nonce); name = entry['name']
    elif profile in {'shell','elf'}:
        entry = next(v for v in native_fixtures(nonce,profile) if v['slot'] == slot); name = entry['name']
    else: entry = next(v for v in fixtures(nonce) if v['name'] == name)
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
        value = bridge.prepare(case, selected[0]['id'], entry['profile'], target)
        validate_owned(Path(value['request']).read_bytes(), entry, bridge)
    else:
        raw = (target/'request.json').read_bytes(); validate_owned(raw, entry, bridge)
        value = bridge.import_result(case, target/'request.json', workspace/('sidecar-'+slot))
    require(inventory(case) == before, 'owned_client_original_case_changed')
    return {'result': 'PASS', 'phase': 'import' if collect else 'request', 'slot': slot, 'case': str(case),
            'execution_authorized': False, 'original_case_unchanged': True, 'client_result': value}



NATIVE_COMMON = ('positive', 'derived', 'error', 'loop', 'fork', 'output', 'memory', 'file', 'cancel',
                 'paused-refusal', 'owner-loss', 'protocol-loss')
NATIVE_CASES = {'shell': NATIVE_COMMON, 'elf': ('positive', 'pie', 'dynamic')+NATIVE_COMMON[1:]}
NATIVE_SLOTS = frozenset({slot for slots in NATIVE_CASES.values() for slot in slots} | {'smoke'})


class _OwnedX64:
    """Tiny fixed byte emitter, never a host compiler, assembler or runner."""
    def __init__(self): self.code=bytearray();self.labels={};self.fixups=[]
    def emit(self,raw):self.code.extend(raw)
    def mov(self,register,value):
        prefixes={'eax':b'\xb8','edi':b'\xbf','esi':b'\xbe','edx':b'\xba','ebx':b'\xbb','ecx':b'\xb9','r10d':b'\x41\xba'}
        self.emit(prefixes[register]+struct.pack('<I',value & 0xffffffff))
    def syscall(self,number):self.mov('eax',number);self.emit(b'\x0f\x05')
    def label(self,name):require(name not in self.labels,'owned_x64_label');self.labels[name]=len(self.code)
    def relative(self,prefix,target):
        self.emit(prefix);self.fixups.append((len(self.code),target));self.emit(bytes(4))
    def lea(self,target='data'):self.relative(b'\x48\x8d\x35',target)
    def exit(self,code):self.mov('edi',code);self.syscall(60)
    def finish(self,data_labels=None):
        labels={**self.labels,'data':len(self.code)}
        labels.update({name:len(self.code)+offset for name,offset in (data_labels or {}).items()})
        for offset,target in self.fixups:struct.pack_into('<i',self.code,offset,labels[target]-offset-4)
        return bytes(self.code)


def _native_elf(case,message,mode='static',minimum_bytes=0):
    """Owned ELF64 bytes, including a minimal real dynamic PIE, never executed here."""
    require(case in set(NATIVE_SLOTS) and mode in {'static','pie','dynamic'},'owned_elf_case')
    code=_OwnedX64();data=b'';labels={}
    if case in {'positive','derived','pie','dynamic','smoke','paused-refusal','owner-loss','protocol-loss'}:
        data=message+b'previous-job-marker\0';labels={'marker':len(message)}
        code.mov('edi',1);code.lea();code.mov('edx',len(message));code.syscall(1)
        code.mov('edi',-100);code.lea('marker');code.mov('edx',0x41);code.mov('r10d',0o600);code.syscall(257)
        code.emit(b'\x48\x85\xc0');code.relative(b'\x0f\x88','marker_failed');code.exit(0)
        code.label('marker_failed');code.exit(7)
    elif case=='error':code.exit(7)
    elif case in {'loop','cancel'}:code.label('again');code.relative(b'\xe9','again')
    elif case=='fork':
        code.mov('ebx',32);code.label('fork');code.syscall(57);code.emit(b'\x48\x85\xc0')
        code.relative(b'\x0f\x84','wait');code.relative(b'\x0f\x88','wait')
        code.emit(b'\xff\xcb');code.relative(b'\x0f\x85','fork');code.label('wait')
        code.syscall(34);code.relative(b'\xe9','wait')
    elif case=='output':
        data=b'X'*4096;code.mov('edi',1);code.lea();code.mov('edx',len(data));code.syscall(1);code.exit(0)
    elif case=='memory':
        code.mov('edi',0);code.mov('esi',96*1024**2);code.mov('edx',3);code.mov('r10d',0x22)
        code.emit(b'\x49\xb8'+struct.pack('<Q',2**64-1)+b'\x45\x31\xc9');code.syscall(9)
        code.emit(b'\x48\x85\xc0');code.relative(b'\x0f\x88','failed')
        code.emit(b'\x48\x89\xc7');code.mov('ecx',96*1024**2);code.emit(b'\x31\xc0\xf3\xaa')
        code.label('failed');code.exit(7)
    elif case=='file':
        name=b'resource-file.bin\0';data=name+b'F'*8192;labels={'payload':len(name)}
        code.mov('edi',-100);code.lea();code.mov('edx',0x241);code.mov('r10d',0o600);code.syscall(257)
        code.emit(b'\x48\x85\xc0');code.relative(b'\x0f\x88','failed');code.emit(b'\x89\xc7')
        code.lea('payload');code.mov('edx',8192);code.syscall(1);code.mov('edx',1);code.syscall(1)
        code.label('failed');code.exit(7)
    else:raise ValueError('owned_elf_fixed_case_only')
    program=code.finish(labels);dynamic=mode=='dynamic';count=4 if dynamic else 1
    base=0x400000 if mode=='static' else 0;prefix=64+count*56;interpreter=b'/lib64/ld-linux-x86-64.so.2\0'
    if dynamic:
        interp_offset=prefix;dyn_offset=(interp_offset+len(interpreter)+7)//8*8
        str_offset=dyn_offset+6*16;sym_offset=(str_offset+1+7)//8*8;hash_offset=sym_offset+24
        entry_offset=(hash_offset+16+15)//16*16
        metadata=bytearray(entry_offset-prefix);metadata[:len(interpreter)]=interpreter
        entries=[(5,str_offset),(10,1),(6,sym_offset),(11,24),(4,hash_offset),(0,0)]
        for index,row in enumerate(entries):struct.pack_into('<qQ',metadata,dyn_offset-prefix+index*16,*row)
        struct.pack_into('<IIII',metadata,hash_offset-prefix,1,1,0,0)
    else:entry_offset=(prefix+15)//16*16;metadata=bytes(entry_offset-prefix)
    size=max(entry_offset+len(program)+len(data),minimum_bytes)
    require(size<=1024**2,'owned_elf_byte_budget')
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),2 if mode=='static' else 3,
                       62,1,base+entry_offset,64,0,0,64,56,count,0,0,0)
    load=struct.pack('<IIQQQQQQ',1,5,0,base,0,size,size,4096)
    if dynamic:
        phdr=struct.pack('<IIQQQQQQ',6,4,64,64,0,count*56,count*56,8)
        interp=struct.pack('<IIQQQQQQ',3,4,interp_offset,interp_offset,0,len(interpreter),len(interpreter),1)
        dyn=struct.pack('<IIQQQQQQ',2,4,dyn_offset,dyn_offset,0,96,96,8)
        headers=phdr+interp+load+dyn
    else:headers=load
    raw=header+headers+bytes(metadata)+program+data
    return raw+bytes(size-len(raw))


def native_fixtures(nonce,profile):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}',nonce) and profile in NATIVE_CASES,'owned_native_fixture_identity')
    marker=('OWNED-NATIVE-'+profile.upper()+'-'+nonce+'\n').encode('ascii')
    success=b'#!/ignored/never-selected\nprintf "'+marker[:-1]+b'\\n"\n: > previous-job-marker\n'
    shell={'error':b'exit 7\n','loop':b'while :; do :; done\n','cancel':b'while :; do :; done\n',
           'fork':b'i=0; while [ "$i" -lt 32 ]; do sleep 20 & i=$((i+1)); done; wait\n',
           'output':b'i=0; while [ "$i" -lt 4096 ]; do printf X; i=$((i+1)); done\n',
           'memory':b'x=0123456789012345678901234567890123456789012345678901234567890123; while :; do x=$x$x; done\n',
           'file':b'dd if=/dev/zero of=resource-file.bin bs=8192 count=2 2>/dev/null; exit $?\n'}
    rows=[]
    for slot in (*NATIVE_CASES[profile],'smoke'):
        if profile=='shell':
            selected=shell.get(slot,success)
            if slot=='smoke':selected+=b'#'+b'x'*(64*1024-len(selected)-2)+b'\n'
        else:selected=_native_elf(slot,marker,mode=slot if slot in {'pie','dynamic'} else 'static',minimum_bytes=1024**2 if slot=='smoke' else 0)
        original=selected;kind='original';interpretation='posix-shell-utf8' if profile=='shell' else 'elf64-x86_64'
        if slot=='derived':
            original=b'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n'+base64.b64encode(selected)
            kind='parser_selected_payload';interpretation='mime'
        rows.append({'slot':slot,'name':'native-'+profile+'-'+slot,'profile':profile,'interpretation':interpretation,
                     'kind':kind,'original':original,'selected':selected})
    return rows

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path); parser.add_argument('--nonce', required=True)
    parser.add_argument('--source-tree', type=Path)
    parser.add_argument('--profile', choices=['python', 'html', 'shell', 'elf', 'javascript'])
    parser.add_argument('--phase', choices=['prepare', 'request', 'import'], default='prepare')
    parser.add_argument('--slot', choices=sorted(SLOTS | NATIVE_SLOTS)); parser.add_argument('--gate-file', type=Path); parser.add_argument('--gate-tag')
    args = parser.parse_args()
    require((args.gate_file is None) == (args.gate_tag is None), 'owned_client_gate_pair')
    if args.gate_file is not None: await_gate(args.gate_file, args.gate_tag, args.nonce)
    if args.phase == 'prepare':
        require(args.slot is None, 'owned_client_prepare_without_slot')
        result = prepare(args.workspace, args.nonce, args.source_tree, args.profile)
    else: result = next_request(args.workspace, args.nonce, args.profile, args.slot, args.source_tree, collect=args.phase == 'import')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
