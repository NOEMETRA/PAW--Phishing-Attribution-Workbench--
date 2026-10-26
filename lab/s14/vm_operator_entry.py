#!/usr/bin/python3 -I
"""Fixed installed entrypoint; no workspace imports or general command runner."""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys

ENTRY = Path('/usr/local/libexec/paw-vm-operator')
STATIC = Path('/usr/local/lib/paw-vm')
BOOTSTRAP = Path('/var/lib/paw-vm/bootstrap.json')
MODULES = frozenset({'vm_release_contract.py', 'vm_release_storage.py', 'vm_release_github.py',
                     'vm_release_archive.py', 'vm_operator_host.py'})


def require(value, reason):
    if not value: raise ValueError(reason)


def directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in [None, *path.parts[1:]]:
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); os.close(fd); fd = child
            value = os.fstat(fd)
            require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and value.st_mode & 0o022 == 0,
                    'operator_bootstrap_directory')
        return fd
    except BaseException: os.close(fd); raise


def read(path, mode, maximum):
    parent = directory(path.parent)
    try: fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally: os.close(parent)
    try:
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                stat.S_IMODE(value.st_mode) == mode and value.st_size <= maximum, 'operator_bootstrap_file')
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(maximum+1)
        after = os.fstat(fd)
        require(len(raw) == value.st_size and after.st_mtime_ns == value.st_mtime_ns and
                after.st_ctime_ns == value.st_ctime_ns, 'operator_bootstrap_file_changed')
        return raw
    finally: os.close(fd)


def bootstrap(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, 'operator_bootstrap_budget')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'operator_bootstrap_duplicate'); result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict and set(value) == {'schema', 'owner_uid', 'entry_sha256', 'modules'} and
            value['schema'] == 'paw-vm-bootstrap-v1' and type(value['owner_uid']) is int and value['owner_uid'] == 1000,
            'operator_bootstrap_identity')
    require(type(value['modules']) is dict and set(value['modules']) == MODULES, 'operator_bootstrap_modules')
    for digest in [value['entry_sha256'], *value['modules'].values()]:
        require(type(digest) is str and len(digest) == 64 and all(v in '0123456789abcdef' for v in digest),
                'operator_bootstrap_digest')
    return value


def main():
    require(os.geteuid() == 0 and Path(__file__) == ENTRY, 'operator_installed_root_entrypoint_required')
    caller = os.environ.get('PKEXEC_UID', '')
    require(caller == '1000', 'operator_enrolled_pkexec_caller')
    os.environ.clear(); os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LANG='C.UTF-8')
    sys.dont_write_bytecode = True
    for kind, limit in [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 64*1024**2),
                        (resource.RLIMIT_NOFILE, 256), (resource.RLIMIT_AS, 512*1024**2), (resource.RLIMIT_CPU, 120)]:
        resource.setrlimit(kind, (limit, limit))
    value = bootstrap(read(BOOTSTRAP, 0o600, 16384))
    require(hashlib.sha256(read(ENTRY, 0o755, 1024**2)).hexdigest() == value['entry_sha256'], 'operator_entry_digest')
    fd = directory(STATIC)
    try: require(set(os.listdir(fd)) == MODULES, 'operator_static_inventory')
    finally: os.close(fd)
    for name, digest in value['modules'].items():
        require(hashlib.sha256(read(STATIC/name, 0o444, 1024**2)).hexdigest() == digest, 'operator_module_digest')
    os.chdir('/var/lib/paw-vm'); sys.path.insert(0, str(STATIC))
    from vm_operator_host import main as dispatch
    print(json.dumps(dispatch(sys.argv[1:], int(caller)), sort_keys=True), flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('operator_error:'+type(error).__name__+':'+str(error), file=sys.stderr, flush=True); raise SystemExit(1)
