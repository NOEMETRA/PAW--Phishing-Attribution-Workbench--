# paw/sentinel/file_monitor.py
"""
File integrity monitoring for PAW analysis files.
"""
import os
import time
import hashlib
import json
import stat
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any, TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from .database import CampaignDatabase
from ..util.fsutil import ensure_dir
from ..util.timeutil import utc_now_iso
from .contracts import _storage_path, _storage_directory, _admit_storage_path, _json_chunks
from ..core.verify import verify_case
from ..core.job_registry import require_stopped_case


class FileMonitor:
    """Monitor file integrity and changes in PAW case directories."""

    def __init__(self, cases_dir: str = "cases", database: "CampaignDatabase" = None, *,
                 max_files: int = 10000, max_bytes: int = 1024**3,
                 max_file_bytes: int = 256 * 1024**2, max_cases: int = 1000,
                 max_directories: int = 10000, max_depth: int = 64, max_output_bytes: int = 64*1024**2):
        self._limits = dict(max_files=max_files, max_bytes=max_bytes,
                            max_file_bytes=max_file_bytes, max_cases=max_cases,
                            max_directories=max_directories, max_depth=max_depth,
                            max_output_bytes=max_output_bytes)
        if any(type(value) is not int or value <= 0 for value in self._limits.values()):
            raise ValueError("File observation limits must be positive integers")
        # Bind relative configuration once, without resolving away root links.
        self.cases_dir = _storage_path(cases_dir)
        # File checks do not read or write the campaign database.
        self.db = database
        self._baseline_hashes: Dict[str, str] = {}
        self._monitored_files: Set[str] = set()
        self._scan_lock = threading.RLock()
        self._walk_budget = ContextVar('sentinel_file_walk_budget', default=None)

    @staticmethod
    def _admit(path, *, directory=False):
        if directory: _storage_directory(path)
        else: _admit_storage_path(_storage_path(path), must_exist=True)
        metadata = Path(path).lstat()
        if (stat.S_ISLNK(metadata.st_mode) or
                getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise ValueError(f"Linked/reparse paths are outside file observation scope: {path}")
        if not (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)):
            raise ValueError(f"Expected a regular {'directory' if directory else 'file'}: {path}")
        return metadata

    def _case_path(self, case_id):
        if (not isinstance(case_id, str) or not case_id.strip() or case_id in ('.', '..') or
                '/' in case_id or '\\' in case_id or Path(case_id).is_absolute() or os.path.splitdrive(case_id)[0]):
            raise ValueError("case_id must name one child of the cases directory")
        for directory in (self.cases_dir, self.cases_dir / case_id):
            try: self._admit(directory, directory=True)
            except FileNotFoundError: pass
        return self.cases_dir / case_id

    @staticmethod
    def _identity(metadata):
        # Windows path stat and descriptor fstat expose different legacy ctime
        # semantics after a write. File ID, mode, size and mtime agree on both.
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
                metadata.st_mtime_ns) + ((metadata.st_ctime_ns,) if os.name != 'nt' else ())

    def _metadata(self, files):
        result = {}; size = 0
        for path in files:
            metadata = self._admit(path)
            size += metadata.st_size
            if (len(result) >= self._limits['max_files'] or size > self._limits['max_bytes'] or
                    metadata.st_size > self._limits['max_file_bytes']):
                raise ValueError("File observation limit exceeded; no complete scan available")
            result[path] = self._identity(metadata)
        return result

    def _selection(self):
        with self._directory_budget():
            case_ids = self.scan_cases_directory()
            count = size = 0
            for case_id in case_ids:
                for identity in self._metadata(self.get_case_files(case_id)).values():
                    count += 1; size += identity[3]
                    if count > self._limits['max_files'] or size > self._limits['max_bytes']:
                        raise ValueError("File observation selection limit exceeded")
            return case_ids

    @contextmanager
    def _directory_budget(self):
        """Share traversal work across cases and repeated walks in one operation."""
        if self._walk_budget.get() is not None:
            yield
            return
        token = self._walk_budget.set({'directories': 0, 'entries': 0})
        try:
            yield
        finally:
            self._walk_budget.reset(token)

    def _inventory_scope(self):
        return {'scope': 'all single-link regular files; no filename or extension exclusions',
                'atomic_snapshot': False, 'limits': dict(self._limits)}

    def scan_cases_directory(self) -> List[str]:
        """Scan cases directory and return list of case IDs."""
        try:
            self._admit(self.cases_dir, directory=True)
        except FileNotFoundError:
            return []

        case_dirs = []
        for count, item in enumerate(self.cases_dir.iterdir(), 1):
            if count > self._limits['max_files'] + self._limits['max_directories'] + self._limits['max_cases']:
                raise ValueError('Root directory entry limit exceeded')
            if item.name.startswith("case-"):
                metadata = item.lstat()
                if stat.S_ISDIR(metadata.st_mode) or item.is_symlink() or getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
                    self._admit(item, directory=True)
                    case_dirs.append(item.name)
                    if len(case_dirs) > self._limits['max_cases']:
                        raise ValueError("Case observation limit exceeded")

        return sorted(case_dirs)

    def get_case_files(self, case_id: str) -> List[str]:
        """Get all analysis files for a specific case."""
        case_path = self._case_path(case_id)
        require_stopped_case(case_path)
        if not case_path.exists():
            return []

        files = []
        budget = self._walk_budget.get()
        if budget is None: budget = {'directories': 0, 'entries': 0}
        def scan_failed(error):
            raise error
        # Walk through all subdirectories
        for root, dirs, filenames in os.walk(case_path, onerror=scan_failed):
            budget['directories'] += 1; budget['entries'] += len(dirs) + len(filenames)
            if (budget['directories'] > self._limits['max_directories'] or
                    len(Path(root).parts)-len(case_path.parts) > self._limits['max_depth'] or
                    budget['entries'] > self._limits['max_files']+self._limits['max_directories']):
                raise ValueError('Case directory/depth/entry limit exceeded')
            self._admit(root, directory=True)
            for directory in dirs:
                self._admit(Path(root) / directory, directory=True)
            for filename in filenames:
                path = Path(root) / filename
                self._admit(path)
                files.append(str(path))
                if len(files) > self._limits['max_files']:
                    raise ValueError("File observation limit exceeded")

        self._metadata(files)
        return sorted(files)

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate a complete SHA256 digest; propagate open/read failures."""
        before = self._admit(file_path)
        if before.st_size > self._limits['max_file_bytes']:
            raise ValueError("File byte limit exceeded")
        def opening(path, flags):
            return os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with open(file_path, 'rb', opener=opening) as f:
            if self._identity(os.fstat(f.fileno())) != self._identity(before):
                raise OSError("File changed before reading")
            digest = hashlib.sha256()
            consumed = 0
            while chunk := f.read(min(1024 * 1024, self._limits['max_file_bytes'] - consumed + 1)):
                consumed += len(chunk)
                if consumed > self._limits['max_file_bytes']:
                    raise ValueError("File byte limit exceeded during reading")
                digest.update(chunk)
            if (consumed != before.st_size or self._identity(os.fstat(f.fileno())) != self._identity(before) or
                    self._identity(self._admit(file_path)) != self._identity(before)):
                raise OSError("File changed during reading")
            return digest.hexdigest()

    def verify_merkle_integrity(self, case_id: str) -> Tuple[Optional[bool], str]:
        """Verify file integrity using Merkle root if available."""
        case_path = self._case_path(case_id)
        self.get_case_files(case_id)  # Apply the same local source/size admission.
        evidence_dir = case_path / "evidence"
        merkle_index = evidence_dir / "merkle_index.json"
        merkle_root_file = evidence_dir / "merkle_root.bin"

        if not merkle_index.exists() or not merkle_root_file.exists():
            return None, "Evidence index or root missing; integrity not verified"

        try:
            ok = verify_case(case_path)
            return ok, "Case evidence verification passed" if ok else "Case evidence verification failed; inspect paw verify output"

        except Exception as e:
            return None, f"Error verifying Merkle integrity: {e}"

    def check_file_changes(self, case_id: str) -> Dict[str, Any]:
        """Check for file changes in a case directory."""
        with self._scan_lock:
            return self._check_file_changes(case_id)

    def _check_file_changes(self, case_id):
        files = self.get_case_files(case_id)
        metadata = self._metadata(files)
        changes = {
            'case_id': case_id,
            'timestamp': utc_now_iso(),
            'new_files': [],
            'modified_files': [],
            'deleted_files': [],
            'integrity_status': 'unknown',
            'integrity_message': '',
            'inventory': self._inventory_scope()
        }

        # Check Merkle integrity first
        integrity_ok, integrity_msg = self.verify_merkle_integrity(case_id)
        changes['integrity_status'] = 'unknown' if integrity_ok is None else 'ok' if integrity_ok else 'compromised'
        changes['integrity_message'] = integrity_msg

        # Check individual file changes
        current_hashes = {}
        for file_path in files:
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                current_hashes[file_path] = file_hash

                # Check if this is a new file
                if file_path not in self._baseline_hashes:
                    changes['new_files'].append({
                        'path': file_path,
                        'hash': file_hash
                    })
                # Check if file was modified
                elif self._baseline_hashes[file_path] != file_hash:
                    changes['modified_files'].append({
                        'path': file_path,
                        'old_hash': self._baseline_hashes[file_path],
                        'new_hash': file_hash
                    })

        # Check for deleted files
        case_root = (self.cases_dir / case_id).resolve()
        case_baseline = {path:digest for path,digest in self._baseline_hashes.items()
                         if Path(path).resolve().is_relative_to(case_root)}
        for baseline_file in case_baseline:
            if baseline_file not in current_hashes:
                changes['deleted_files'].append({
                    'path': baseline_file,
                    'last_hash': self._baseline_hashes[baseline_file]
                })

        if self._metadata(self.get_case_files(case_id)) != metadata:
            raise OSError("Case files changed during observation")
        for _ in _json_chunks(changes, self._limits['max_output_bytes']): pass
        # Only this instance's completed scan may advance its baseline.
        for path in case_baseline: self._baseline_hashes.pop(path, None)
        self._baseline_hashes.update(current_hashes)

        return changes

    def monitor_all_cases(self) -> List[Dict[str, Any]]:
        """Monitor all case directories for changes."""
        with self._scan_lock, self._directory_budget():
            return self._monitor_all_cases()

    def _monitor_all_cases(self):
        case_ids = self._selection()
        # Admit the entire selection before advancing any in-memory baseline.
        for case_id in case_ids:
            require_stopped_case(self.cases_dir / case_id)
        results = []
        baseline = dict(self._baseline_hashes)
        try:
            for case_id in case_ids:
                changes = self.check_file_changes(case_id)
                if changes['new_files'] or changes['modified_files'] or changes['deleted_files'] or changes['integrity_status'] != 'ok':
                    results.append(changes)
            for _ in _json_chunks(results, self._limits['max_output_bytes']): pass
            for changes in results:
                self._record_file_check(changes['case_id'], changes)
        except Exception:
            self._baseline_hashes.clear()
            self._baseline_hashes.update(baseline)
            raise

        return results

    def _record_file_check(self, case_id: str, changes: Dict[str, Any]) -> None:
        """Emit a console observation; no database persistence is performed."""
        print(f"[file_monitor] Case {case_id}: {len(changes['new_files'])} new, "
              f"{len(changes['modified_files'])} modified, "
              f"{len(changes['deleted_files'])} deleted files. "
              f"Integrity: {changes['integrity_status']}")

    def generate_integrity_report(self) -> Dict[str, Any]:
        """Generate a comprehensive integrity report for all cases."""
        with self._scan_lock, self._directory_budget():
            return self._generate_integrity_report()

    def _generate_integrity_report(self):
        case_ids = self._selection()
        inventory = {case: self._metadata(self.get_case_files(case)) for case in case_ids}
        for case_id in case_ids:
            require_stopped_case(self.cases_dir / case_id)
        report = {
            'timestamp': utc_now_iso(),
            'total_cases': len(case_ids),
            'integrity_summary': {
                'ok': 0,
                'compromised': 0,
                'unknown': 0
            },
            'cases': [],
            'inventory': self._inventory_scope()
        }

        for case_id in case_ids:
            integrity_ok, integrity_msg = self.verify_merkle_integrity(case_id)
            status = 'unknown' if integrity_ok is None else 'ok' if integrity_ok else 'compromised'

            report['integrity_summary'][status] += 1
            report['cases'].append({
                'case_id': case_id,
                'integrity_status': status,
                'integrity_message': integrity_msg,
                'file_count': len(self.get_case_files(case_id))
            })

        if self._selection() != case_ids or any(self._metadata(self.get_case_files(case)) != inventory[case] for case in case_ids):
            raise OSError('Case inventory changed during integrity report')
        for _ in _json_chunks(report, self._limits['max_output_bytes']): pass
        return report
