"""Read-only effective host freeze for the owned synthetic offline adapter."""
import json
from pathlib import Path
import subprocess

from benign_guest_validation import BASE, HERE, digest, guard_fingerprint

PACKAGES = ('qemu-system-x86', 'libvirt-daemon-system', 'intel-microcode')


def capture():
    packages = subprocess.check_output(['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\n', *PACKAGES], text=True, timeout=10)
    slice_root = Path('/sys/fs/cgroup/machine.slice/machine-paws14.slice')
    return {'kernel': subprocess.check_output(['/usr/bin/uname', '-r'], text=True, timeout=3).strip(),
            'packages': dict(line.split('\t', 1) for line in packages.splitlines()),
            'image_sha256': digest(BASE), 'guard_fingerprint': guard_fingerprint(),
            'source_hashes': {p.name: digest(p) for p in HERE.iterdir() if p.suffix in {'.py', '.nft', '.xml', '.service', '.conf', '.slice'}},
            'smt_active': Path('/sys/devices/system/cpu/smt/active').read_text().strip(),
            'apparmor_enabled': Path('/sys/module/apparmor/parameters/enabled').read_text().strip(),
            'slice': {name: (slice_root / name).read_text().strip() for name in ['memory.max', 'memory.swap.max', 'pids.max']},
            'mitigations': {p.name: p.read_text().strip() for p in Path('/sys/devices/system/cpu/vulnerabilities').iterdir()},
            'mitigation_cmdline': sorted(token for token in Path('/proc/cmdline').read_text().split()
                                         if token.startswith(('mitigations=', 'l1tf=', 'gather_data_sampling=', 'clearcpuid=', 'nosmt')))}
