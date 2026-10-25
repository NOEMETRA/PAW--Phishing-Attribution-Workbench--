"""Bounded public commit archive acquisition and root snapshot staging.

Only the installed privileged adapter may select proof/commit and trusted parent
fd. These helpers alone do not authenticate caller-supplied proof JSON or bytes.
No archive member is extracted with tarfile.extract/extractall or executed.
"""
import gzip
import hashlib
import io
import os
from pathlib import PurePosixPath
import re
import shutil
import tarfile
import urllib.error
import urllib.request
import uuid
import zlib

from vm_release_contract import REPOSITORY, require, sha, decode
from vm_release_github import NoRedirect
import vm_release_storage as storage

MAX_COMPRESSED = 16 * 1024**2
MAX_EXPANDED = 96 * 1024**2
MAX_MEMBERS = 8192


def fetch(release_sha):
    require(sha(release_sha), 'archive_full_commit_required')
    url = 'https://codeload.github.com/'+REPOSITORY+'/tar.gz/'+release_sha
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'PAW-fixed-vm-release-verifier'})
    try:
        with opener.open(request, timeout=30) as response:
            require(response.geturl() == url, 'archive_response_endpoint_changed')
            raw = response.read(MAX_COMPRESSED+1)
    except (urllib.error.URLError, TimeoutError, OSError): raise ValueError('archive_transport_unavailable') from None
    require(0 < len(raw) <= MAX_COMPRESSED, 'archive_download_budget'); return raw


def sources(raw, release_sha):
    require(sha(release_sha) and type(raw) is bytes and 0 < len(raw) <= MAX_COMPRESSED, 'archive_input_budget')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed: expanded = compressed.read(MAX_EXPANDED+1)
    except (OSError, EOFError, zlib.error): raise ValueError('archive_invalid_gzip') from None
    require(len(expanded) <= MAX_EXPANDED, 'archive_expansion_budget')
    files = {}; names = set(); prefix = None; total = 0; members = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            # git archive advertises the exact commit in the global PAX header.
            require(archive.pax_headers.get('comment') == release_sha, 'archive_commit_header')
            for member in archive:
                members += 1; require(members <= MAX_MEMBERS, 'archive_member_budget')
                name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
                require(type(name) is str and '\\' not in name and '\x00' not in name and 0 < len(name) <= 1024,
                        'archive_member_name')
                path = PurePosixPath(name)
                require(not path.is_absolute() and path.as_posix() == name and
                        all(v not in {'', '.', '..'} for v in path.parts) and name not in names,
                        'archive_member_path'); names.add(name)
                if prefix is None:
                    prefix = path.parts[0]
                    require(prefix.endswith('-'+release_sha) and re.fullmatch('[A-Za-z0-9_.-]+', prefix), 'archive_commit_prefix')
                require(path.parts[0] == prefix and (member.isdir() or member.isreg()), 'archive_member_type_or_root')
                require(type(member.size) is int and 0 <= member.size <= MAX_EXPANDED, 'archive_member_size')
                if member.isdir() or len(path.parts) == 1: continue
                relative = '/'.join(path.parts[1:])
                try: storage.source_path(relative)
                except ValueError: continue
                require(relative not in files and len(files) < storage.MAX_FILES and member.size <= storage.MAX_FILE,
                        'archive_source_budget')
                total += member.size; require(total <= storage.MAX_TOTAL, 'archive_source_total_budget')
                stream = archive.extractfile(member); require(stream is not None, 'archive_source_stream')
                with stream: data = stream.read(storage.MAX_FILE+1)
                require(len(data) == member.size, 'archive_source_length'); files[relative] = data
    except (tarfile.TarError, EOFError, OSError): raise ValueError('archive_invalid_tar') from None
    require(files, 'archive_no_supported_sources'); return files


def verify_git_tree(client, proof, files):
    """Bind every downloaded source byte to GitHub API's exact commit tree."""
    require(type(proof) is dict and sha(proof.get('merge_sha')), 'archive_commit_identity')
    base = '/repos/'+REPOSITORY
    commit = client.get(base+'/git/commits/'+proof['merge_sha'])
    tree_sha = commit.get('tree', {}).get('sha')
    require(commit.get('sha') == proof['merge_sha'] and sha(tree_sha), 'archive_commit_tree_identity')
    tree = client.get(base+'/git/trees/'+tree_sha+'?recursive=1')
    require(tree.get('sha') == tree_sha and tree.get('truncated') is False and
            type(tree.get('tree')) is list and len(tree['tree']) <= MAX_MEMBERS, 'archive_complete_git_tree')
    expected = {}; names = set()
    for item in tree['tree']:
        require(type(item) is dict and type(item.get('path')) is str and item['path'] not in names,
                'archive_git_tree_entry'); name = item['path']; names.add(name)
        try: storage.source_path(name)
        except ValueError: continue
        require(item.get('type') == 'blob' and item.get('mode') in {'100644', '100755'} and
                sha(item.get('sha')) and type(item.get('size')) is int and 0 <= item['size'] <= storage.MAX_FILE,
                'archive_git_source_entry'); expected[name] = item
    require(type(files) is dict and set(expected) == set(files) and expected, 'archive_git_source_inventory')
    for name, data in files.items():
        require(type(data) is bytes and len(data) == expected[name]['size'], 'archive_git_source_length')
        blob = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        require(blob == expected[name]['sha'], 'archive_git_blob_digest')
    return tree_sha


def _write(parent_fd, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream: stream.write(raw); stream.flush(); os.fsync(fd)
        os.fchmod(fd, 0o444)
    finally: os.close(fd)


def stage(parent_fd, proof, files):
    """Root-only immutable write under fixed trusted state, never activation."""
    require(os.geteuid() == 0, 'root_snapshot_install_required'); storage.directory(parent_fd)
    require(type(proof) is dict and proof.get('repository') == REPOSITORY and
            sha(proof.get('head_sha')) and sha(proof.get('merge_sha')), 'snapshot_proof_identity')
    release_sha = proof['merge_sha']; proof_raw = storage.canonical(proof)
    decode(proof_raw)
    require(type(files) is dict and 1 <= len(files) <= storage.MAX_FILES, 'snapshot_source_inventory')
    value = {'schema': 'paw-vm-root-snapshot-v1', 'repository': REPOSITORY, 'release_sha': release_sha,
             'head_sha': proof['head_sha'], 'proof_sha256': hashlib.sha256(proof_raw).hexdigest(), 'files': {}}
    for name, data in files.items():
        storage.source_path(name); require(type(data) is bytes, 'snapshot_source_bytes')
        value['files'][name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    manifest_raw = storage.canonical(value); storage.manifest(manifest_raw, release_sha)
    digest = hashlib.sha256(manifest_raw).hexdigest()
    try: os.stat(release_sha, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError: pass
    else:
        existing, _ = storage.verify(parent_fd, release_sha, digest)
        require(existing == value, 'existing_snapshot_differs'); return digest
    temporary = '.stage-'+uuid.uuid4().hex; os.mkdir(temporary, mode=0o700, dir_fd=parent_fd)
    root = storage.open_dir(parent_fd, temporary); renamed = False
    try:
        for name, data in files.items():
            parts = storage.source_path(name); current = os.dup(root)
            try:
                for part in parts[:-1]:
                    try: os.mkdir(part, mode=0o755, dir_fd=current)
                    except FileExistsError: pass
                    child = storage.open_dir(current, part); os.close(current); current = child
                _write(current, parts[-1], data)
            finally: os.close(current)
        _write(root, 'proof.json', proof_raw); _write(root, 'release.json', manifest_raw); os.fsync(root)
        # The dispatcher holds the root-only promotion lock; no unprivileged
        # process can replace names in this checked parent directory.
        os.rename(temporary, release_sha, src_dir_fd=parent_fd, dst_dir_fd=parent_fd); renamed = True; os.fsync(parent_fd)
        storage.verify(parent_fd, release_sha, digest); return digest
    finally:
        os.close(root)
        if not renamed:
            # fd-relative cleanup never accepts a caller-controlled path.
            shutil.rmtree(temporary, dir_fd=parent_fd)
