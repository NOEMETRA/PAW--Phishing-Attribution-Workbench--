"""Per-identity renderer observations; startup samples are retained, not hidden."""
import os
from pathlib import Path


class RendererWitness:
    def __init__(self):
        self.renderers = {}; self.nonroot = True

    def add(self, identity, command, *, uids, nnp, seccomp, pid_namespace):
        nonroot = bool(uids) and all(type(v) is int and v > 0 for v in uids)
        self.nonroot &= nonroot
        if b'--type=renderer' not in command.split(b'\0'): return
        if identity not in self.renderers:
            if len(self.renderers) >= 64: raise ValueError('renderer_identity_budget')
            self.renderers[identity] = {'modes': set(), 'last_mode': None, 'nnp_all': True,
                'filtered_seen': False, 'regressed': False, 'last_namespace': False, 'unsafe_filtered': False}
        row = self.renderers[identity]
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
                command = (root/'cmdline').read_bytes()
                namespace = os.readlink(root/'ns/pid') != os.readlink('/proc/1/ns/pid')
                after = (root/'stat').read_text().rsplit(')', 1)[1].split()[19]
            except (FileNotFoundError, ProcessLookupError): continue
            if before != after: continue
            self.add(pid+':'+before, command, uids=[int(v) for v in status['Uid'].split()],
                     nnp=int(status['NoNewPrivs']), seccomp=int(status['Seccomp']), pid_namespace=namespace)

    def flags(self):
        rows = list(self.renderers.values())
        return {'renderer_seen': bool(rows), 'renderer_nnp': bool(rows) and all(v['nnp_all'] for v in rows),
            'renderer_seccomp': bool(rows) and all(v['filtered_seen'] and v['last_mode'] == 2 and not v['regressed'] and
                not v['unsafe_filtered'] for v in rows),
            'renderer_pid_namespace': bool(rows) and all(v['last_namespace'] for v in rows), 'all_uids_nonroot': self.nonroot}

    def details(self):
        return [{'identity': key, **{k: sorted(v) if isinstance(v, set) else v for k, v in row.items()}}
                for key, row in sorted(self.renderers.items())]
