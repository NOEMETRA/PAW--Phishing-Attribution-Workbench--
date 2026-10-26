"""Read-only immutable snapshot verification under an already trusted root fd.

No installation, remote-proof authentication, policy change or execution here.
The installed dispatcher must open/check its fixed root ancestors before use.
"""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat

from vm_release_contract import REPOSITORY, decode, require, sha, shape

ROOT_UID = 0
MAX_FILES = 2048
MAX_FILE = 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_MANIFEST = 512 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def hex64(value): return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def source_path(value):
    require(type(value) is str and 0 < len(value) <= 240 and '\\' not in value, 'snapshot_source_path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in {'', '.', '..'} for part in path.parts) and
            (re.fullmatch(r'paw/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.py', value) or
             re.fullmatch(r'lab/s14/[A-Za-z0-9_.-]+\.(?:py|nft|xml|service|conf|slice)', value)),
            'snapshot_source_path')
    return path.parts


def manifest(raw, release_sha):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST, 'snapshot_manifest_budget')
    # This manifest can exceed the smaller remote proof budget, but retains the
    # same strict duplicate/scalar/depth checks through bounded per-entry shape.
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'snapshot_duplicate_key'); result[key] = value
        return result
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error: raise ValueError('snapshot_manifest_json') from error
    shape(value, {'schema', 'repository', 'release_sha', 'head_sha', 'proof_sha256', 'files'}, 'snapshot_manifest_shape')
    require(value['schema'] == 'paw-vm-root-snapshot-v1' and value['repository'] == REPOSITORY and
            sha(release_sha) and value['release_sha'] == release_sha and sha(value['head_sha']) and
            hex64(value['proof_sha256']) and type(value['files']) is dict and
            1 <= len(value['files']) <= MAX_FILES, 'snapshot_manifest_identity')
    total = 0
    for name, item in value['files'].items():
        source_path(name); shape(item, {'sha256', 'bytes'}, 'snapshot_file_shape')
        require(hex64(item['sha256']) and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_FILE,
                'snapshot_file_digest_or_budget'); total += item['bytes']
    require(total <= MAX_TOTAL and raw == canonical(value), 'snapshot_total_budget_or_canonical')
    return value


def directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and info.st_mode & 0o022 == 0,
            'snapshot_directory_not_root_protected')


def open_dir(parent_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try: directory(fd)
    except BaseException: os.close(fd); raise
    return fd


def read_file(parent_fd, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == ROOT_UID and
                stat.S_IMODE(before.st_mode) == 0o444 and before.st_nlink == 1 and before.st_size <= maximum,
                'snapshot_file_not_immutable_regular')
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size <= maximum and before.st_size == after.st_size and
                before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns,
                'snapshot_file_changed')
        return raw
    finally: os.close(fd)


def inventory(fd, prefix='', depth=0, budget=None):
    require(depth <= 12, 'snapshot_tree_depth'); result = set()
    budget = [0] if budget is None else budget
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            names.append(entry.name); budget[0] += 1
            require(len(names) <= MAX_FILES + 2 and budget[0] <= 4096, 'snapshot_directory_budget')
    for name in names:
        require(re.fullmatch('[A-Za-z0-9_.-]{1,128}', name) is not None and name not in {'.', '..'},
                'snapshot_tree_name')
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(info.st_uid == ROOT_UID, 'snapshot_tree_owner')
        path = prefix + name
        if stat.S_ISDIR(info.st_mode):
            result.add(path+'/')
            child = open_dir(fd, name)
            try: result.update(inventory(child, path+'/', depth+1, budget))
            finally: os.close(child)
        else:
            require(stat.S_ISREG(info.st_mode), 'snapshot_tree_special_file'); result.add(path)
        require(len(result) <= 4096, 'snapshot_tree_budget')
    return result


def verify(parent_fd, release_sha, manifest_sha256):
    """Check exact immutable bytes; parent fd and expected hash are root state."""
    directory(parent_fd); require(sha(release_sha) and hex64(manifest_sha256), 'snapshot_selection')
    root = open_dir(parent_fd, release_sha)
    try:
        raw = read_file(root, 'release.json', MAX_MANIFEST)
        require(hashlib.sha256(raw).hexdigest() == manifest_sha256, 'snapshot_manifest_digest')
        value = manifest(raw, release_sha)
        parents = {'/'.join(source_path(name)[:n])+'/' for name in value['files']
                   for n in range(1, len(source_path(name)))}
        require(inventory(root) == set(value['files']) | parents | {'release.json', 'proof.json'}, 'snapshot_exact_inventory')
        proof_raw = read_file(root, 'proof.json', 128*1024)
        require(hashlib.sha256(proof_raw).hexdigest() == value['proof_sha256'], 'snapshot_proof_digest')
        proof = decode(proof_raw)
        require(type(proof) is dict and proof.get('repository') == REPOSITORY and
                proof.get('head_sha') == value['head_sha'] and proof.get('merge_sha') == release_sha,
                'snapshot_proof_identity')
        for name, item in value['files'].items():
            parts = source_path(name); current = os.dup(root)
            try:
                for part in parts[:-1]:
                    child = open_dir(current, part); os.close(current); current = child
                data = read_file(current, parts[-1], MAX_FILE)
                require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
                        'snapshot_source_digest')
            finally: os.close(current)
        return value, proof
    finally: os.close(root)
