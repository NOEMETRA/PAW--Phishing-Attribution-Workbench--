"""Fetch one pinned Ubuntu vendor image; verify signature before image admission."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

BASE = 'https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261017/'
IMAGE = 'ubuntu-24.04-minimal-cloudimg-amd64.img'
KEYRING = Path('/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg')

def sha256(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()

def fetch(directory, name, limit):
    target = directory / name
    if target.exists():
        raise RuntimeError(f'Refusing overwrite: {target}')
    temporary = target.with_name(name + '.part')
    total = 0
    with urllib.request.urlopen(BASE + name, timeout=45) as response, temporary.open('xb') as stream:
        if not response.url.startswith(BASE):
            raise RuntimeError('Unexpected vendor redirect')
        while data := response.read(1024 * 1024):
            total += len(data)
            if total > limit:
                raise RuntimeError('Vendor file exceeds byte budget')
            stream.write(data)
    temporary.rename(target)
    return target

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    sums = fetch(args.output, 'SHA256SUMS', 64 * 1024)
    signature = fetch(args.output, 'SHA256SUMS.gpg', 64 * 1024)
    verified = subprocess.run(['gpgv', '--status-fd=1', '--keyring', str(KEYRING),
                               str(signature), str(sums)], capture_output=True, text=True)
    (args.output / 'signature.log').write_text(verified.stdout + verified.stderr)
    if verified.returncode or '[GNUPG:] VALIDSIG ' not in verified.stdout:
        raise RuntimeError('Vendor manifest signature did not verify against installed distribution keyring')
    expected = [line.split()[0] for line in sums.read_text().splitlines()
                if len(line.split()) == 2 and line.split()[1] == '*' + IMAGE]
    if len(expected) != 1 or len(expected[0]) != 64:
        raise RuntimeError('Missing or ambiguous signed image hash')
    print('Vendor manifest signature PASS; downloading pinned amd64 image', flush=True)
    image = fetch(args.output, IMAGE, 384 * 1024 * 1024)
    actual = sha256(image)
    if actual != expected[0]:
        raise RuntimeError('Image differs from signed vendor hash')
    info = subprocess.run(['qemu-img', 'info', '--output=json', str(image)],
                          capture_output=True, text=True, check=True)
    metadata = json.loads(info.stdout)
    if metadata['format'] != 'qcow2' or metadata.get('backing-filename') or metadata['virtual-size'] > 8 * 1024**3:
        raise RuntimeError('Unexpected vendor disk metadata')
    report = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'vendor_base': BASE, 'image': IMAGE, 'sha256': actual, 'bytes': image.stat().st_size,
              'signed_manifest': True, 'signature_status': verified.stdout,
              'keyring': str(KEYRING), 'keyring_sha256': sha256(KEYRING), 'qemu_image_info': metadata,
              'result': 'PASS', 'scope': 'Vendor signature and byte integrity; no guest execution or malware-safety attestation'}
    (args.output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
