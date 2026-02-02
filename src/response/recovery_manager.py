"""Restoration utilities for the backup system.

Supports:
- Restoring individual files or entire directories
- Point-in-time recovery
- Restore all files modified by a specific process
- Batch restoration
- Integrity verification via SHA-256
"""

import hashlib
import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from src.response.snapshot_service import SnapshotService, file_sha256

logger = logging.getLogger(__name__)


@dataclass
class RestoreResult:
    original_path: str
    backup_path: str
    success: bool
    integrity_ok: bool | None  # None if hash was unavailable
    error: str | None = None


class RecoveryManager:
    """Handles file restoration from the backup vault."""

    def __init__(self, snapshot_service: SnapshotService):
        self.snapshot = snapshot_service

    def restore_file(self, backup_id: int) -> RestoreResult:
        """Restore a single file by its backup ID."""
        record = self.snapshot.get_backup_by_id(backup_id)
        if not record:
            return RestoreResult(
                original_path="", backup_path="",
                success=False, integrity_ok=None,
                error=f"Backup ID {backup_id} not found",
            )
        return self._do_restore(record)

    def restore_by_path(self, original_path: str, latest: bool = True) -> list[RestoreResult]:
        """Restore backups for a specific original path.

        If ``latest`` is True, only the most recent backup is restored.
        Otherwise all available versions are restored to timestamped names.
        """
        backups = self.snapshot.get_backups(original_path=original_path)
        if not backups:
            return [RestoreResult(
                original_path=original_path, backup_path="",
                success=False, integrity_ok=None,
                error="No backups found",
            )]
        if latest:
            backups = [backups[0]]  # already sorted newest-first
        return [self._do_restore(b) for b in backups]

    def restore_by_process(self, process_name: str) -> list[RestoreResult]:
        """Restore all files that were backed up due to a specific process."""
        backups = self.snapshot.get_backups(process_name=process_name)
        if not backups:
            return [RestoreResult(
                original_path="", backup_path="",
                success=False, integrity_ok=None,
                error=f"No backups for process {process_name}",
            )]

        # Deduplicate: keep only the latest backup per original_path
        seen: dict[str, dict] = {}
        for b in backups:
            if b["original_path"] not in seen:
                seen[b["original_path"]] = b
        return [self._do_restore(b) for b in seen.values()]

    def restore_point_in_time(self, since: str) -> list[RestoreResult]:
        """Restore all files backed up since a given ISO timestamp."""
        backups = self.snapshot.get_backups(since=since, limit=10000)
        if not backups:
            return []
        seen: dict[str, dict] = {}
        for b in backups:
            if b["original_path"] not in seen:
                seen[b["original_path"]] = b
        return [self._do_restore(b) for b in seen.values()]

    def verify_backup(self, backup_id: int) -> bool | None:
        """Check whether a backup file still matches its recorded SHA-256.

        Returns True/False, or None if hash is unavailable.
        """
        record = self.snapshot.get_backup_by_id(backup_id)
        if not record:
            return None
        stored_hash = record.get("file_hash")
        if not stored_hash:
            return None
        current_hash = file_sha256(record["backup_path"])
        return current_hash == stored_hash

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _do_restore(self, record: dict) -> RestoreResult:
        backup_path = record["backup_path"]
        original_path = record["original_path"]

        if not os.path.isfile(backup_path):
            return RestoreResult(
                original_path=original_path, backup_path=backup_path,
                success=False, integrity_ok=None,
                error="Backup file missing from vault",
            )

        # Verify integrity before restoring
        stored_hash = record.get("file_hash")
        integrity_ok = None
        if stored_hash:
            current_hash = file_sha256(backup_path)
            integrity_ok = (current_hash == stored_hash)
            if not integrity_ok:
                return RestoreResult(
                    original_path=original_path, backup_path=backup_path,
                    success=False, integrity_ok=False,
                    error="Integrity check failed: hash mismatch",
                )

        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.copy2(backup_path, original_path)
        except OSError as exc:
            return RestoreResult(
                original_path=original_path, backup_path=backup_path,
                success=False, integrity_ok=integrity_ok,
                error=str(exc),
            )

        logger.info("Restored %s from %s", original_path, backup_path)
        return RestoreResult(
            original_path=original_path, backup_path=backup_path,
            success=True, integrity_ok=integrity_ok,
        )
