"""Event logging module for storing file system events in SQLite."""

import sqlite3
import threading
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class EventLogger:
    """Thread-safe SQLite logger for file system events."""

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
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_extension TEXT,
                old_path TEXT,
                file_size_before INTEGER,
                file_size_after INTEGER,
                process_id INTEGER,
                process_name TEXT,
                is_directory INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON file_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type
                ON file_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_path
                ON file_events(file_path);
            CREATE INDEX IF NOT EXISTS idx_events_process
                ON file_events(process_id);
        """)
        conn.commit()
        logger.info("Database initialized at %s", self.db_path)

    def log_event(
        self,
        event_type: str,
        file_path: str,
        file_extension: str = None,
        old_path: str = None,
        file_size_before: int = None,
        file_size_after: int = None,
        process_id: int = None,
        process_name: str = None,
        is_directory: bool = False,
    ) -> int:
        """Insert a file event record. Returns the row ID."""
        timestamp = datetime.now().isoformat()
        conn = self._get_connection()
        cursor = conn.execute(
            """
            INSERT INTO file_events (
                timestamp, event_type, file_path, file_extension,
                old_path, file_size_before, file_size_after,
                process_id, process_name, is_directory
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_type,
                file_path,
                file_extension,
                old_path,
                file_size_before,
                file_size_after,
                process_id,
                process_name,
                int(is_directory),
            ),
        )
        conn.commit()
        logger.debug(
            "Logged %s event for %s (pid=%s)", event_type, file_path, process_id
        )
        return cursor.lastrowid

    def get_events(
        self,
        since: str = None,
        event_type: str = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query events with optional filters."""
        conn = self._get_connection()
        query = "SELECT * FROM file_events WHERE 1=1"
        params = []

        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def close(self):
        if hasattr(self._local, "connection") and self._local.connection:
            self._local.connection.close()
            self._local.connection = None
