"""Entropy change detection logic.

Maintains a baseline entropy database, compares before/after values on file
modification events, and flags suspicious entropy spikes (delta > threshold).
"""

import sqlite3
import threading
import logging
from datetime import datetime
from pathlib import Path

from src.analysis.entropy_analyzer import calculate_file_entropy

logger = logging.getLogger(__name__)

DEFAULT_DELTA_THRESHOLD = 2.0
HIGH_ENTROPY_ABSOLUTE = 7.5


class EntropyBaseline:
    """Thread-safe store for per-file entropy baselines."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "connection") or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                str(self.db_path), timeout=10
            )
            self._local.connection.row_factory = sqlite3.Row
            self._local.connection.execute("PRAGMA journal_mode=WAL")
            self._local.connection.execute("PRAGMA synchronous=NORMAL")
        return self._local.connection

    def _init_db(self):
        conn = self._get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS entropy_baselines (
                file_path TEXT PRIMARY KEY,
                entropy REAL NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entropy_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                entropy_before REAL,
                entropy_after REAL NOT NULL,
                delta REAL NOT NULL,
                suspicious INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON entropy_alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_suspicious
                ON entropy_alerts(suspicious);
        """)
        conn.commit()

    def get_baseline(self, file_path: str) -> float | None:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT entropy FROM entropy_baselines WHERE file_path = ?",
            (file_path,),
        ).fetchone()
        return row["entropy"] if row else None

    def set_baseline(self, file_path: str, entropy: float):
        conn = self._get_connection()
        conn.execute(
            """INSERT INTO entropy_baselines (file_path, entropy, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(file_path) DO UPDATE
               SET entropy = excluded.entropy, updated_at = excluded.updated_at""",
            (file_path, entropy, datetime.now().isoformat()),
        )
        conn.commit()

    def remove_baseline(self, file_path: str):
        conn = self._get_connection()
        conn.execute(
            "DELETE FROM entropy_baselines WHERE file_path = ?", (file_path,)
        )
        conn.commit()

    def log_alert(
        self,
        file_path: str,
        entropy_before: float | None,
        entropy_after: float,
        delta: float,
        suspicious: bool,
    ) -> int:
        conn = self._get_connection()
        cursor = conn.execute(
            """INSERT INTO entropy_alerts
               (timestamp, file_path, entropy_before, entropy_after, delta, suspicious)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                file_path,
                entropy_before,
                entropy_after,
                delta,
                int(suspicious),
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def get_alerts(self, suspicious_only: bool = False, limit: int = 100) -> list[dict]:
        conn = self._get_connection()
        query = "SELECT * FROM entropy_alerts"
        params: list = []
        if suspicious_only:
            query += " WHERE suspicious = 1"
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def close(self):
        if hasattr(self._local, "connection") and self._local.connection:
            self._local.connection.close()
            self._local.connection = None


class EntropyDetector:
    """Detects suspicious entropy changes on file modification events."""

    def __init__(
        self,
        baseline_db_path: str,
        delta_threshold: float = DEFAULT_DELTA_THRESHOLD,
    ):
        self.baseline = EntropyBaseline(baseline_db_path)
        self.delta_threshold = delta_threshold
        self._cache: dict[str, float] = {}

    def analyze_file(self, file_path: str) -> dict | None:
        """Calculate entropy and compare against baseline.

        Returns a result dict with keys:
            file_path, entropy_before, entropy_after, delta, suspicious
        or None if the file cannot be read.
        """
        entropy_after = calculate_file_entropy(file_path)
        if entropy_after is None:
            return None

        # Check cache first, then database baseline
        entropy_before = self._cache.get(file_path)
        if entropy_before is None:
            entropy_before = self.baseline.get_baseline(file_path)

        delta = (entropy_after - entropy_before) if entropy_before is not None else 0.0
        suspicious = (
            delta >= self.delta_threshold
            or (entropy_before is None and entropy_after >= HIGH_ENTROPY_ABSOLUTE)
        )

        # Update baseline and cache
        self.baseline.set_baseline(file_path, entropy_after)
        self._cache[file_path] = entropy_after

        if suspicious:
            self.baseline.log_alert(
                file_path=file_path,
                entropy_before=entropy_before,
                entropy_after=entropy_after,
                delta=delta,
                suspicious=True,
            )
            logger.warning(
                "Suspicious entropy: %s (%.2f -> %.2f, delta=%.2f)",
                file_path,
                entropy_before or 0.0,
                entropy_after,
                delta,
            )
        else:
            self.baseline.log_alert(
                file_path=file_path,
                entropy_before=entropy_before,
                entropy_after=entropy_after,
                delta=delta,
                suspicious=False,
            )

        return {
            "file_path": file_path,
            "entropy_before": entropy_before,
            "entropy_after": entropy_after,
            "delta": delta,
            "suspicious": suspicious,
        }

    def on_file_created(self, file_path: str) -> dict | None:
        """Record initial baseline entropy for a new file."""
        entropy = calculate_file_entropy(file_path)
        if entropy is None:
            return None
        self.baseline.set_baseline(file_path, entropy)
        self._cache[file_path] = entropy
        suspicious = entropy >= HIGH_ENTROPY_ABSOLUTE
        if suspicious:
            self.baseline.log_alert(
                file_path=file_path,
                entropy_before=None,
                entropy_after=entropy,
                delta=0.0,
                suspicious=True,
            )
        return {
            "file_path": file_path,
            "entropy_before": None,
            "entropy_after": entropy,
            "delta": 0.0,
            "suspicious": suspicious,
        }

    def on_file_deleted(self, file_path: str):
        """Remove baseline for a deleted file."""
        self._cache.pop(file_path, None)
        self.baseline.remove_baseline(file_path)

    def close(self):
        self.baseline.close()
