"""Backup orchestration.

Coordinates snapshot creation and retention enforcement. Intended to be
called from the file monitor layer on every file modification event.
"""

import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from src.response.backup_config import RETENTION_HOURS, SNAPSHOT_DIR_FORMAT
from src.response.snapshot_service import SnapshotService
from src.response.recovery_manager import RecoveryManager

logger = logging.getLogger(__name__)


class BackupManager:
    """High-level backup orchestrator.

    Usage::

        mgr = BackupManager(vault_path="/secure/vault")
        mgr.backup_file("/home/user/doc.txt", reason="suspicious", process_name="evil.exe")
        results = mgr.recovery.restore_by_path("/home/user/doc.txt")
        mgr.enforce_retention()
    """

    def __init__(self, vault_path: str = None, retention_hours: int = RETENTION_HOURS):
        self.snapshot = SnapshotService(vault_path=vault_path)
        self.recovery = RecoveryManager(self.snapshot)
        self.retention_hours = retention_hours

    def backup_file(
        self,
        original_path: str,
        reason: str = "routine",
        process_name: str | None = None,
    ) -> dict | None:
        """Create a backup snapshot of a single file.

        Returns the snapshot metadata dict or None on failure.
        """
        return self.snapshot.create_snapshot(
            original_path=original_path,
            reason=reason,
            process_name=process_name,
        )

    def enforce_retention(self):
        """Delete snapshot directories older than the retention window.

        Also removes their rows from index.db.
        """
        cutoff = datetime.now() - timedelta(hours=self.retention_hours)
        cutoff_str = cutoff.isoformat()

        # Remove database records
        conn = self.snapshot._get_connection()
        old_rows = conn.execute(
            "SELECT backup_path FROM backups WHERE timestamp < ?", (cutoff_str,)
        ).fetchall()
        conn.execute("DELETE FROM backups WHERE timestamp < ?", (cutoff_str,))
        conn.commit()

        # Remove snapshot directories that are now empty or entirely stale
        removed_dirs: set[str] = set()
        for row in old_rows:
            bp = row["backup_path"]
            parent = os.path.dirname(bp)
            try:
                if os.path.isfile(bp):
                    os.remove(bp)
            except OSError:
                pass
            removed_dirs.add(parent)

        for d in removed_dirs:
            try:
                # Remove directory if empty (or only metadata.json left)
                remaining = os.listdir(d)
                if not remaining or remaining == ["metadata.json"]:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass

        if old_rows:
            logger.info("Retention cleanup: removed %d old backup(s)", len(old_rows))

    def close(self):
        self.snapshot.close()
