"""Unprivileged native enrollment preparation from committed Git blobs only.

The launcher requires ordinary native administrator authentication. It neither
stores an Ubuntu password nor creates a generic passwordless command. Root
executes only the installer bytes in the digest-pinned data bundle, after the
small literal bootstrap has verified the entire bundle and installer digest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vm_operator_install as native
import vm_release_contract as contract

LOADER = r'''
import hashlib,json,os,stat,sys
def need(value, reason):
    if not value: raise ValueError(reason)
need(os.geteuid()==0 and len(sys.argv)==3,'native_bootstrap_root_arguments')
path,expected=sys.argv[1:]
need(len(expected)==64 and all(v in '0123456789abcdef' for v in expected),'native_bootstrap_digest_shape')
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    before=os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=69206016,'native_bootstrap_regular_budget')
    with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(69206017)
    after=os.fstat(fd)
    need(len(raw)==before.st_size==after.st_size and before.st_mtime_ns==after.st_mtime_ns and
         before.st_ctime_ns==after.st_ctime_ns,'native_bootstrap_changed')
finally: os.close(fd)
need(hashlib.sha256(raw).hexdigest()==expected,'native_bootstrap_approved_digest')
def pairs(items):
    value={}
    for key,item in items:
        need(key not in value,'native_bootstrap_duplicate'); value[key]=item
    return value
value=json.loads(raw,object_pairs_hook=pairs)
item=value['files']['lab/s14/vm_operator_install.py']
need(type(item) is dict and set(item)=={'bytes','sha256','data_hex'} and
     type(item['bytes']) is int and 0<item['bytes']<=1048576 and
     type(item['data_hex']) is str and len(item['data_hex'])==2*item['bytes'],'native_bootstrap_installer_shape')
source=bytes.fromhex(item['data_hex'])
need(len(source)==item['bytes'] and hashlib.sha256(source).hexdigest()==item['sha256'],'native_bootstrap_installer_digest')
sys.argv=['<digest-approved-native-installer>','--bundle',path,'--sha256',expected]
exec(compile(source,'<digest-approved-native-installer>','exec'),{'__name__':'__main__','__file__':'<digest-approved-native-installer>'})
'''


def git(repository, *argv):
    return subprocess.check_output(['/usr/bin/git', '-C', str(repository), *argv], timeout=30)


def committed_sources(repository, head):
    contract.require(contract.sha(head), 'setup_full_commit_required')
    contract.require(git(repository, 'rev-parse', '--verify', head+'^{commit}').decode().strip() == head,
                     'setup_commit_identity')
    rows = git(repository, 'ls-tree', '-r', '-l', '-z', head).split(b'\0')
    contract.require(len(rows) <= 8193, 'setup_git_tree_budget')
    sources = {}; total = 0
    for row in rows:
        if not row: continue
        metadata, encoded = row.split(b'\t', 1); name = encoded.decode('utf-8')
        try: native.path_parts(name)
        except ValueError: continue
        mode, kind, identity, size = metadata.split()
        contract.require(mode in {b'100644', b'100755'} and kind == b'blob' and size.isdigit() and
                         int(size) <= 1024**2 and name not in sources, 'setup_committed_regular_blob')
        total += int(size)
        contract.require(total <= native.MAX_TOTAL and len(sources) < 2048, 'setup_source_budget')
        data = git(repository, 'cat-file', 'blob', identity.decode('ascii'))
        contract.require(len(data) == int(size) and
                         hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest().encode() == identity,
                         'setup_git_blob_identity')
        sources[name] = data
    return sources


def enrollment_policy(head, now):
    value = {'schema': 'paw-vm-operator-policy-v1', 'repository': native.REPOSITORY, 'owner_uid': 1000,
             'reviewer_login': contract.REVIEWER, 'reviewer_id': 199175422, 'anchor_sha': head,
             'created_at': now, 'expires_at': now+30*86400, 'workflows': {
                 '.github/workflows/static-integrity.yml': {'workflow_id': 378856216, 'jobs': [
                     'static-preflight', 'archive-runtime-compatibility (3.12)', 'archive-runtime-compatibility (3.13)']},
                 '.github/workflows/linux-installed-package.yml': {'workflow_id': 394599156, 'jobs': [
                     'installed-offline ('+v+')' for v in ['3.11', '3.12', '3.13', '3.14']]}}}
    return contract.policy(value, now)


def build(repository, head, number, now=None, repair_from=None):
    contract.require(type(number) is int and 0 < number <= 999999999, 'setup_project_pr_number')
    now = int(time.time()) if now is None else now
    files = committed_sources(repository, head)
    value = {'schema': 'paw-vm-native-bundle-v2', 'repository': native.REPOSITORY, 'owner_uid': 1000,
             'head_sha': head, 'pull_request': number, 'created_at': now, 'expires_at': now+3600,
             'repair_from': repair_from,
             'policy': enrollment_policy(head, now), 'files': {name: {'bytes': len(data),
                 'sha256': hashlib.sha256(data).hexdigest(), 'data_hex': data.hex()} for name, data in files.items()}}
    raw = native.canonical(value); digest = hashlib.sha256(raw).hexdigest()
    native.bundle(raw, digest, now)
    return raw, digest


def command(bundle, digest, head):
    contract.require(isinstance(bundle, Path) and bundle.is_absolute() and
                     re.fullmatch('[0-9a-f]{64}', digest) and contract.sha(head), 'setup_native_arguments')
    return ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/systemd-run', '--quiet', '--wait', '--pipe',
            '--collect', '--unit=paw-vm-enroll-'+head[:12], '--property=Type=exec',
            '--property=RuntimeMaxSec=2100', '--property=MemoryMax=512M', '--property=MemorySwapMax=0',
            '--property=TasksMax=64', '--property=CPUQuota=100%', '--property=TimeoutStopSec=20',
            '--property=LimitCORE=0', '--property=LimitFSIZE=64M', '--property=WorkingDirectory=/var/lib',
            '/usr/bin/python3', '-I', '-B', '-c', LOADER, str(bundle), digest]


def main():
    contract.require(os.getuid() == os.geteuid() == 1000, 'setup_unprivileged_enrolled_client_required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True); parser.add_argument('--head', required=True)
    parser.add_argument('--pr', type=int, required=True); parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--repair-release'); parser.add_argument('--repair-manifest')
    parser.add_argument('--launch', action='store_true'); args = parser.parse_args()
    contract.require((args.repair_release is None) == (args.repair_manifest is None), 'setup_repair_pair_required')
    repair = None if args.repair_release is None else {'release_sha': args.repair_release, 'manifest_sha256': args.repair_manifest}
    raw, digest = build(args.repository, args.head, args.pr, repair_from=repair)
    with args.bundle.open('xb') as stream: stream.write(raw)
    args.bundle.chmod(0o400)
    print(json.dumps({'head': args.head, 'bundle_sha256': digest, 'bytes': len(raw),
                      'native_authentication_required': True}), flush=True)
    if args.launch:
        # GitHub's existing credential provider is read once into memory; it is
        # not the administrator login password, and never enters argv or a file.
        token = subprocess.check_output(['/usr/bin/gh', 'auth', 'token', '--hostname', 'github.com'], timeout=15)
        contract.require(re.fullmatch(b'[A-Za-z0-9_]{20,256}\n?', token) is not None, 'setup_api_credential_frame')
        result = subprocess.run(command(args.bundle.absolute(), digest, args.head),
                                input=token.rstrip(b'\n')+b'\n', timeout=2160, check=False)
        raise SystemExit(result.returncode)


if __name__ == '__main__': main()
