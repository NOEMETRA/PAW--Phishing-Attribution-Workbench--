"""Fixed benign guest-only execution fixture; no payload or command arguments."""
import hashlib
import json
import os
from pathlib import Path
import resource

MARKER = b'PAW BENIGN SYNTHETIC FIXTURE\n'


def main():
    names = sorted(p.name for p in Path('/sys/class/net').iterdir())
    if names != ['lo']:
        raise ValueError('fixture_requires_no_network_device')
    for kind, maximum in [(resource.RLIMIT_CPU, 1), (resource.RLIMIT_FSIZE, 4096),
                          (resource.RLIMIT_AS, 64 * 1024**2), (resource.RLIMIT_NOFILE, 16),
                          (resource.RLIMIT_CORE, 0)]:
        resource.setrlimit(kind, (maximum, maximum))
    folder = Path('/var/lib/paw-benign-synthetic')
    folder.mkdir(mode=0o700, exist_ok=False)
    target = folder / 'marker.bin'
    target.write_bytes(MARKER)
    print(json.dumps({'pid': os.getpid(), 'network_interfaces': names,
                      'marker_hex': target.read_bytes().hex(),
                      'marker_sha256': hashlib.sha256(MARKER).hexdigest(),
                      'marker_bytes': len(MARKER), 'fixture': 'fixed-benign-v1'}))


if __name__ == '__main__':
    main()
