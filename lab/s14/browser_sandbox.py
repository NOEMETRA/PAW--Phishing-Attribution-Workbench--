"""Per-identity renderer observations; startup samples are retained, not hidden."""
import os
from pathlib import Path
import shlex


def renderer_command(command):
    if type(command) is not bytes or len(command) > 32768: raise ValueError('renderer_command_budget')
    args = [v for v in command.split(b'\0') if v]
    if b'--type=renderer' in args[1:]: return True
    # Linux exposes rewritten argv storage too. Chrome can pack its process
    # title into argv[0]; parse its quoting without executing any shell syntax.
    if args and len(args[0].split()) > 1:
        try: packed = shlex.split(args[0].decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            if b'--type=renderer' in command: raise ValueError('unparseable_renderer_process_title')
            return False
        return '--type=renderer' in packed[1:]
    return False


class RendererWitness:
    def __init__(self):
        self.renderers = {}; self.nonroot = True; self.markers = {}

    def add(self, identity, command, *, uids, nnp, seccomp, pid_namespace, process=None):
        nonroot = bool(uids) and all(type(v) is int and v > 0 for v in uids)
        self.nonroot &= nonroot
        matched = renderer_command(command)
        if b'--type=renderer' in command:
            if identity not in self.markers and len(self.markers) >= 64: raise ValueError('renderer_marker_budget')
            offset = command.index(b'--type=renderer')
            self.markers[identity] = {'identity': identity, 'matched': matched, 'process': process,
                'argc': len([v for v in command.split(b'\0') if v]),
                'type_context': command[max(0,offset-40):offset+100].decode('utf-8','replace')}
        if not matched: return
        if identity not in self.renderers:
            if len(self.renderers) >= 64: raise ValueError('renderer_identity_budget')
            self.renderers[identity] = {'modes': set(), 'last_mode': None, 'nnp_all': True,
                'filtered_seen': False, 'regressed': False, 'last_namespace': False, 'unsafe_filtered': False}
        row = self.renderers[identity]
        row['process'] = process
        row['modes'].add(seccomp); row['last_mode'] = seccomp; row['nnp_all'] &= nnp == 1
        row['regressed'] |= row['filtered_seen'] and seccomp != 2
        row['filtered_seen'] |= seccomp == 2; row['last_namespace'] = pid_namespace is True
        if seccomp == 2: row['unsafe_filtered'] |= not (nonroot and nnp == 1 and pid_namespace is True)

    def observe(self, group):
        for pid in (group/'cgroup.procs').read_text().split():
            if not pid.isdecimal(): raise ValueError('renderer_pid')
            root = Path('/proc', pid)
            try:
                before = (root/'stat').read_text().rsplit(')', 1)[1].split()[19]
                status = dict(line.split(':', 1) for line in (root/'status').read_text().splitlines() if ':' in line)
                with (root/'cmdline').open('rb') as stream: command = stream.read(32769)
                namespace = os.readlink(root/'ns/pid') != os.readlink('/proc/1/ns/pid')
                after = (root/'stat').read_text().rsplit(')', 1)[1].split()[19]
            except (FileNotFoundError, ProcessLookupError): continue
            if before != after: continue
            self.add(pid+':'+before, command, uids=[int(v) for v in status['Uid'].split()],
                     nnp=int(status['NoNewPrivs']), seccomp=int(status['Seccomp']), pid_namespace=namespace,
                     process={'name': status['Name'].strip(), 'ppid': int(status['PPid']),
                              'namespace_pids': [int(v) for v in status['NSpid'].split()], 'state': status['State'].strip()})

    def flags(self):
        rows = list(self.renderers.values())
        return {'renderer_seen': bool(rows), 'renderer_nnp': bool(rows) and all(v['nnp_all'] for v in rows),
            'renderer_seccomp': bool(rows) and all(v['filtered_seen'] and v['last_mode'] == 2 and not v['regressed'] and
                not v['unsafe_filtered'] for v in rows),
            'renderer_pid_namespace': bool(rows) and all(v['last_namespace'] for v in rows), 'all_uids_nonroot': self.nonroot}

    def details(self):
        return [{'identity': key, **{k: sorted(v) if isinstance(v, set) else v for k, v in row.items()}}
                for key, row in sorted(self.renderers.items())]

    def diagnostics(self):
        return {'renderers': self.details(), 'type_markers': [v for k,v in sorted(self.markers.items())]}
