"""Seal every produced case file; explicitly exclude circular anchor metadata."""
from pathlib import Path
import json
import blake3

EXCLUDED = frozenset({'evidence/merkle_index.json', 'evidence/merkle_root.bin',
    'evidence/rekor_statement.json', 'evidence/rekor_anchor.json', 'evidence/rekor_proof.json'})


def merkle_root(files):
    """Compatibility for Sentinel's pairwise tree (distinct from case index root)."""
    if not files: return None
    level = []
    for name in files:
        digest = blake3.blake3()
        with open(name, 'rb') as stream:
            while chunk := stream.read(1024 * 1024): digest.update(chunk)
        level.append(digest.hexdigest().encode())
    while len(level) > 1:
        level = [blake3.blake3(level[index] + (level[index + 1] if index + 1 < len(level) else level[index])).hexdigest().encode()
                 for index in range(0, len(level), 2)]
    return level[0].decode()


def write_index(path, mapping):
    Path(path).write_text(json.dumps(mapping, indent=2), encoding='utf-8')


def file_inventory(root):
    root = Path(root).resolve()
    files = {}
    for path in root.rglob('*'):
        if path.is_symlink(): raise ValueError('Symlink is not allowed in case evidence')
        if path.is_file():
            if not path.resolve().is_relative_to(root): raise ValueError('Evidence path outside case')
            name = path.relative_to(root).as_posix()
            if name not in EXCLUDED: files[name] = path
    return files


def seal_case(case_dir):
    root = Path(case_dir)
    evidence = root/'evidence'
    evidence.mkdir(exist_ok=True)
    (evidence/'inventory_scope.json').write_text(json.dumps({
        'policy':'all_case_files_v1', 'excluded':sorted(EXCLUDED),
        'limitation':'Content integrity; no independent signature, origin or Rekor proof is established'}, indent=2), encoding='utf-8')
    files = file_inventory(root)
    if len(files) > 10000 or sum(path.stat().st_size for path in files.values()) > 512 * 1024 * 1024:
        raise ValueError('Case evidence inventory budget exceeded')
    hashes = {}
    for name, path in sorted(files.items()):
        digest = blake3.blake3()
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024): digest.update(chunk)
        hashes[name] = digest.hexdigest()
    (evidence/'merkle_index.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8')
    root_hash = blake3.blake3(''.join(hashes.values()).encode()).hexdigest()
    (evidence/'merkle_root.bin').write_text(root_hash, encoding='utf-8')
    return hashes
