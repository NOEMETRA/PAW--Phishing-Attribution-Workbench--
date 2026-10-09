# paw/sentinel/file_monitor.py
"""
File integrity monitoring for PAW analysis files.
"""
import os
import time
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path

from .database import CampaignDatabase
from ..util.fsutil import ensure_dir
from ..util.timeutil import utc_now_iso
from ..core.verify import verify_case


class FileMonitor:
    """Monitor file integrity and changes in PAW case directories."""

    def __init__(self, cases_dir: str = "cases", database: CampaignDatabase = None):
        self.cases_dir = Path(cases_dir)
        self.db = database or CampaignDatabase()
        self._baseline_hashes: Dict[str, str] = {}
        self._monitored_files: Set[str] = set()

    def scan_cases_directory(self) -> List[str]:
        """Scan cases directory and return list of case IDs."""
        if not self.cases_dir.exists():
            return []

        case_dirs = []
        for item in self.cases_dir.iterdir():
            if item.is_dir() and item.name.startswith("case-"):
                case_dirs.append(item.name)

        return sorted(case_dirs)

    def get_case_files(self, case_id: str) -> List[str]:
        """Get all analysis files for a specific case."""
        case_path = self.cases_dir / case_id
        if not case_path.exists():
            return []

        files = []
        # Walk through all subdirectories
        for root, dirs, filenames in os.walk(case_path):
            for filename in filenames:
                # Skip certain file types
                if filename.endswith(('.pyc', '__pycache__')) or filename.startswith('.'):
                    continue
                path = Path(root) / filename
                if not path.is_symlink(): files.append(str(path))

        return sorted(files)

    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of a file."""
        try:
            with open(file_path, 'rb') as f:
                digest = hashlib.sha256()
                while chunk := f.read(1024 * 1024): digest.update(chunk)
                return digest.hexdigest()
        except (IOError, OSError):
            return None

    def verify_merkle_integrity(self, case_id: str) -> Tuple[Optional[bool], str]:
        """Verify file integrity using Merkle root if available."""
        case_path = self.cases_dir / case_id
        evidence_dir = case_path / "evidence"
        merkle_index = evidence_dir / "merkle_index.json"
        merkle_root_file = evidence_dir / "merkle_root.bin"

        if not merkle_index.exists() or not merkle_root_file.exists():
            return None, "Evidence index or root missing; integrity not verified"

        try:
            ok = verify_case(case_path)
            return ok, "Case evidence verification passed" if ok else "Case evidence verification failed; inspect paw verify output"

        except Exception as e:
            return False, f"Error verifying Merkle integrity: {e}"

    def check_file_changes(self, case_id: str) -> Dict[str, Any]:
        """Check for file changes in a case directory."""
        files = self.get_case_files(case_id)
        changes = {
            'case_id': case_id,
            'timestamp': utc_now_iso(),
            'new_files': [],
            'modified_files': [],
            'deleted_files': [],
            'integrity_status': 'unknown',
            'integrity_message': ''
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

        # Update baseline with current state
        for path in case_baseline: self._baseline_hashes.pop(path, None)
        self._baseline_hashes.update(current_hashes)

        return changes

    def monitor_all_cases(self) -> List[Dict[str, Any]]:
        """Monitor all case directories for changes."""
        case_ids = self.scan_cases_directory()
        results = []

        for case_id in case_ids:
            try:
                changes = self.check_file_changes(case_id)
                if changes['new_files'] or changes['modified_files'] or changes['deleted_files'] or changes['integrity_status'] != 'ok':
                    results.append(changes)
                    self._record_file_check(case_id, changes)
            except Exception as e:
                print(f"[file_monitor] Error checking case {case_id}: {e}")

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
        case_ids = self.scan_cases_directory()
        report = {
            'timestamp': utc_now_iso(),
            'total_cases': len(case_ids),
            'integrity_summary': {
                'ok': 0,
                'compromised': 0,
                'unknown': 0
            },
            'cases': []
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
