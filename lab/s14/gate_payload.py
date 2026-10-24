"""Finite benign pressure/boundary fixtures, executed only as guest uid65534."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

WORK = Path('/tmp/paw-gate-fixture')


def boundary(config):
    result = {'uid': os.getuid(), 'gid': os.getgid(), 'interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir())}
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    result.update(cap_eff=status['CapEff'].strip(), no_new_privs=status['NoNewPrivs'].strip())
    result['positive_read'] = (WORK / 'positive.txt').read_text() == 'owned positive control'
    result['denied_paths'] = {}
    for path in [config['host_canary'], '/run/libvirt/libvirt-sock', '/var/run/docker.sock', '/run/user/1000/bus']:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK); os.close(fd); denied = False
        except OSError as error: denied = error.errno in {errno.ENOENT, errno.EACCES, errno.ENXIO, errno.ENOTDIR}
        result['denied_paths'][path] = denied
    try: os.setuid(0); result['setuid_denied'] = False
    except PermissionError: result['setuid_denied'] = True
    library = ctypes.CDLL(None, use_errno=True)
    result['mount_denied'] = library.mount(b'none', str(WORK).encode(), b'tmpfs', 0, None) == -1 and ctypes.get_errno() == errno.EPERM
    try: Path(config['cgroup'] + '/memory.max').write_text('67108864'); result['cgroup_write_denied'] = False
    except PermissionError: result['cgroup_write_denied'] = True
    result['network'] = []
    for family, kind, target in [(socket.AF_INET, socket.SOCK_STREAM, ('198.18.41.1', 18080)),
                                 (socket.AF_INET, socket.SOCK_DGRAM, ('192.0.2.53', 53)),
                                 (socket.AF_INET6, socket.SOCK_STREAM, ('fd42:14::1', 18080))]:
        with socket.socket(family, kind) as client:
            client.settimeout(.2)
            try:
                if kind == socket.SOCK_DGRAM: client.sendto(b'owned-no-network-probe', target)
                else: client.connect(target)
                denied = False
            except OSError as error: denied = error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL, errno.ENODEV}
        result['network'].append({'target': list(target), 'denied': denied})
    (WORK / 'previous-job-marker').write_text('must not survive fresh overlay')
    return result


def main():
    case = sys.argv[1]
    if os.getuid() != 65534: raise ValueError('guest_unprivileged_only')
    config = json.loads(Path('/etc/paw-gate-fixture.json').read_text())
    if case == 'boundary': result = boundary(config)
    elif case == 'fork':
        children = []; denied = False
        try:
            for _ in range(20):
                try: pid = os.fork()
                except OSError as error:
                    denied = error.errno == errno.EAGAIN; break
                if pid == 0: time.sleep(2); os._exit(0)
                children.append(pid)
        finally:
            for pid in children:
                try: os.kill(pid, signal.SIGTERM)
                except ProcessLookupError: pass
            for pid in children: os.waitpid(pid, 0)
        result = {'spawned': len(children), 'denied': denied, 'reaped': len(children)}
    elif case == 'memory':
        data = bytearray(96 * 1024**2)
        for index in range(0, len(data), 4096): data[index] = 1
        result = {'unexpected_allocation_completed': len(data)}
    elif case == 'file':
        target = WORK / 'file-budget.bin'; refused = False
        try:
            with target.open('wb') as stream: stream.write(b'x' * 2048); stream.flush(); os.fsync(stream.fileno())
        except OSError as error: refused = error.errno == errno.EFBIG
        result = {'refused': refused, 'bytes': target.stat().st_size}
    elif case == 'reset': result = {'prior_marker_absent': not (WORK / 'previous-job-marker').exists()}
    elif case == 'storage':
        with (WORK / 'host-cap.bin').open('wb') as stream:
            for _ in range(32): stream.write(b'X' * 1024**2)
            stream.flush(); os.fsync(stream.fileno())
        result = {'unexpected_write_completed': True}
    elif case == 'stubborn':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        pid = os.fork()
        if pid == 0:
            time.sleep(10); (WORK / 'late-writer-marker').write_text('late'); time.sleep(10); os._exit(0)
        print(json.dumps({'stubborn_parent': os.getpid(), 'descendant': pid, 'late_write_after_seconds': 10}), flush=True)
        time.sleep(25); return
    else: raise ValueError('fixed_case_only')
    print(json.dumps(result), flush=True)


if __name__ == '__main__': main()
