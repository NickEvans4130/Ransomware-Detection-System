"""File versioning logic.

Creates point-in-time snapshots of individual files into the backup vault,
organised by timestamp directories with flattened filenames and metadata.

Backup structure (from docs):
    backup_vault/
    +-- 2025-02-01_14-30-00/
    |   +-- C_Users_student_Documents_report.docx
    |   +-- C_Users_student_Desktop_photo.jpg
    |   +-- metadata.json
    +-- 2025-02-01_14-31-15/
    |   +-- ...
    +-- index.db
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import sqlite3
import stat
import threading
from datetime import datetime
from pathlib import Path

from src.response.backup_config import (
    DEFAULT_VAULT_PATH,
    SNAPSHOT_DIR_FORMAT,
    VAULT_DIR_MODE,
    VAULT_FILE_MODE,
)

logger = logging.getLogger(__name__)


def file_sha256(path: str) -> str | None:
    """Return hex SHA-256 digest of a file, or None if unreadable."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def flatten_path(original_path: str) -> str:
    """Convert an absolute path to a flat filename safe for any OS.

    /home/user/Documents/report.docx  ->  home_user_Documents_report.docx
    C:\\Users\\student\\file.txt       ->  C_Users_student_file.txt
    """
    normed = os.path.normpath(original_path)
    # Strip leading separator(s) and drive letter colon
    normed = normed.replace(":", "").lstrip(os.sep).lstrip("/")
    return normed.replace(os.sep, "_").replace("/", "_")


class SnapshotService:
    """Creates and manages file snapshots inside the backup vault."""

    def __init__(self, vault_path: str = None):
        self.vault_path = Path(vault_path or DEFAULT_VAULT_PATH)
        self._ensure_vault()
        self.db_path = self.vault_path / "index.db"
        self._local = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # Vault setup
    # ------------------------------------------------------------------

    def _ensure_vault(self):
        self.vault_path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self.vault_path), VAULT_DIR_MODE)
        except OSError:
            logger.debug("Could not set vault permissions (may be on Windows)")

    # ------------------------------------------------------------------
    # Index database (schema from docs)
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), timeout=10)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY,
                original_path TEXT,
                backup_path TEXT,
                timestamp DATETIME,
                file_hash TEXT,
                reason TEXT,
                process_name TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_backups_original
                ON backups(original_path);
            CREATE INDEX IF NOT EXISTS idx_backups_timestamp
                ON backups(timestamp);
            CREATE INDEX IF NOT EXISTS idx_backups_process
                ON backups(process_name);
        """)
        conn.commit()

    # ------------------------------------------------------------------
    # Snapshot creation
    # ------------------------------------------------------------------

    def create_snapshot(
        self,
        original_path: str,
        reason: str = "routine",
        process_name: str | None = None,
        timestamp: datetime | None = None,
    ) -> dict | None:
        """Copy a file into the vault and record metadata.

        Returns a dict with backup details or None if the source is
        unreadable.
        """
        if not os.path.isfile(original_path):
            logger.debug("Skipping non-file: %s", original_path)
            return None

        ts = timestamp or datetime.now()
        snapshot_dir = self.vault_path / ts.strftime(SNAPSHOT_DIR_FORMAT)
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(snapshot_dir), VAULT_DIR_MODE)
        except OSError:
            pass

        flat_name = flatten_path(original_path)
        dest = snapshot_dir / flat_name

        # Handle duplicate names within the same second
        counter = 1
        while dest.exists():
            stem, ext = os.path.splitext(flat_name)
            dest = snapshot_dir / f"{stem}_{counter}{ext}"
            counter += 1

        try:
            shutil.copy2(original_path, str(dest))
        except OSError as exc:
            logger.error("Failed to back up %s: %s", original_path, exc)
            return None

        try:
            os.chmod(str(dest), VAULT_FILE_MODE)
        except OSError:
            pass

        file_hash = file_sha256(str(dest))

        # Write / update metadata.json inside the snapshot directory
        self._write_snapshot_metadata(snapshot_dir, original_path, flat_name,
                                      ts, file_hash, reason, process_name)

        # Record in index.db
        backup_path_str = str(dest)
        conn = self._get_connection()
        conn.execute(
            """INSERT INTO backups
               (original_path, backup_path, timestamp, file_hash, reason, process_name)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (original_path, backup_path_str, ts.isoformat(), file_hash,
             reason, process_name),
        )
        conn.commit()

        logger.info("Backed up %s -> %s (hash=%s)", original_path, backup_path_str,
                     file_hash[:12] if file_hash else "N/A")

        return {
            "original_path": original_path,
            "backup_path": backup_path_str,
            "timestamp": ts.isoformat(),
            "file_hash": file_hash,
            "reason": reason,
            "process_name": process_name,
        }

    @staticmethod
    def _write_snapshot_metadata(
        snapshot_dir: Path,
        original_path: str,
        flat_name: str,
        ts: datetime,
        file_hash: str | None,
        reason: str,
        process_name: str | None,
    ):
        meta_path = snapshot_dir / "metadata.json"
        entries = []
        if meta_path.exists():
            try:
                entries = json.loads(meta_path.read_text())
            except (json.JSONDecodeError, OSError):
                entries = []

        entries.append({
            "original_path": original_path,
            "backup_filename": flat_name,
            "timestamp": ts.isoformat(),
            "sha256": file_hash,
            "reason": reason,
            "process_name": process_name,
        })
        meta_path.write_text(json.dumps(entries, indent=2))

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_backups(
        self,
        original_path: str | None = None,
        process_name: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        conn = self._get_connection()
        query = "SELECT * FROM backups WHERE 1=1"
        params: list = []
        if original_path:
            query += " AND original_path = ?"
            params.append(original_path)
        if process_name:
            query += " AND process_name = ?"
            params.append(process_name)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_backup_by_id(self, backup_id: int) -> dict | None:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM backups WHERE id = ?", (backup_id,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
