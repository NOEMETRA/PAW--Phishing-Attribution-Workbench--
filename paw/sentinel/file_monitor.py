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
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any, TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from .database import CampaignDatabase
from ..util.fsutil import ensure_dir
from ..util.timeutil import utc_now_iso
from ..core.verify import verify_case
from ..core.job_registry import require_stopped_case


class FileMonitor:
    """Monitor file integrity and changes in PAW case directories."""

    def __init__(self, cases_dir: str = "cases", database: "CampaignDatabase" = None, *,
                 max_files: int = 10000, max_bytes: int = 1024**3,
                 max_file_bytes: int = 256 * 1024**2, max_cases: int = 1000):
        self._limits = dict(max_files=max_files, max_bytes=max_bytes,
                            max_file_bytes=max_file_bytes, max_cases=max_cases)
        if any(type(value) is not int or value <= 0 for value in self._limits.values()):
            raise ValueError("File observation limits must be positive integers")
        # Bind relative configuration once, without resolving away root links.
        self.cases_dir = Path(cases_dir).absolute()
        # File checks do not read or write the campaign database.
        self.db = database
        self._baseline_hashes: Dict[str, str] = {}
        self._monitored_files: Set[str] = set()
        self._scan_lock = threading.RLock()

    @staticmethod
    def _admit(path, *, directory=False):
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
        case_ids = self.scan_cases_directory()
        count = size = 0
        for case_id in case_ids:
            for identity in self._metadata(self.get_case_files(case_id)).values():
                count += 1; size += identity[3]
                if count > self._limits['max_files'] or size > self._limits['max_bytes']:
                    raise ValueError("File observation selection limit exceeded")
        return case_ids

    def _inventory_scope(self):
        return {'scope': 'regular non-link files; hidden-name/pyc exclusions apply',
                'atomic_snapshot': False, 'limits': dict(self._limits)}

    def scan_cases_directory(self) -> List[str]:
        """Scan cases directory and return list of case IDs."""
        try:
            self._admit(self.cases_dir, directory=True)
        except FileNotFoundError:
            return []

        case_dirs = []
        for item in self.cases_dir.iterdir():
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
        def scan_failed(error):
            raise error
        # Walk through all subdirectories
        for root, dirs, filenames in os.walk(case_path, onerror=scan_failed):
            self._admit(root, directory=True)
            for directory in dirs:
                self._admit(Path(root) / directory, directory=True)
            for filename in filenames:
                # Skip certain file types
                if filename.endswith(('.pyc', '__pycache__')) or filename.startswith('.'):
                    continue
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
        # Only this instance's completed scan may advance its baseline.
        for path in case_baseline: self._baseline_hashes.pop(path, None)
        self._baseline_hashes.update(current_hashes)

        return changes

    def monitor_all_cases(self) -> List[Dict[str, Any]]:
        """Monitor all case directories for changes."""
        with self._scan_lock:
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
        except Exception:
            self._baseline_hashes.clear()
            self._baseline_hashes.update(baseline)
            raise

        for changes in results:
            self._record_file_check(changes['case_id'], changes)

        return results

    def _record_file_check(self, case_id: str, changes: Dict[str, Any]) -> None:
        """Record file check results in database."""
        try:
            # This would extend the CampaignDatabase to include file monitoring
            # For now, we'll just print the results
            print(f"[file_monitor] Case {case_id}: {len(changes['new_files'])} new, "
                  f"{len(changes['modified_files'])} modified, "
                  f"{len(changes['deleted_files'])} deleted files. "
                  f"Integrity: {changes['integrity_status']}")
        except Exception as e:
            print(f"[file_monitor] Error recording check for {case_id}: {e}")

    def generate_integrity_report(self) -> Dict[str, Any]:
        """Generate a comprehensive integrity report for all cases."""
        case_ids = self._selection()
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

        return report
