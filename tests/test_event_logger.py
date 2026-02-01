"""Tests for the EventLogger database module."""

import os
import tempfile
import threading

import pytest

from src.database.event_logger import EventLogger


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_events.db")


@pytest.fixture
def logger(db_path):
    el = EventLogger(db_path)
    yield el
    el.close()


class TestDatabaseInit:
    def test_creates_database_file(self, db_path):
        el = EventLogger(db_path)
        assert os.path.exists(db_path)
        el.close()

    def test_creates_parent_directories(self, tmp_path):
        db_path = str(tmp_path / "nested" / "dir" / "events.db")
        el = EventLogger(db_path)
        assert os.path.exists(db_path)
        el.close()

    def test_schema_has_required_columns(self, logger, db_path):
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.execute("PRAGMA table_info(file_events)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {
            "id", "timestamp", "event_type", "file_path", "file_extension",
            "old_path", "file_size_before", "file_size_after",
            "process_id", "process_name", "is_directory",
        }
        assert required.issubset(columns)

    def test_indexes_exist(self, logger, db_path):
        import sqlite3
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        ).fetchall()
        conn.close()
        index_names = {r[0] for r in rows}
        assert "idx_events_timestamp" in index_names
        assert "idx_events_type" in index_names
        assert "idx_events_path" in index_names
        assert "idx_events_process" in index_names


class TestLogEvent:
    def test_log_created_event(self, logger):
        row_id = logger.log_event(
            event_type="created",
            file_path="/tmp/test.txt",
            file_extension=".txt",
            file_size_after=1024,
            process_id=1234,
            process_name="python",
        )
        assert row_id == 1
        events = logger.get_events(limit=1)
        assert len(events) == 1
        assert events[0]["event_type"] == "created"
        assert events[0]["file_path"] == "/tmp/test.txt"

    def test_log_modified_event_with_sizes(self, logger):
        logger.log_event(
            event_type="modified",
            file_path="/tmp/test.txt",
            file_size_before=1024,
            file_size_after=2048,
            process_id=5678,
            process_name="vim",
        )
        events = logger.get_events(event_type="modified")
        assert events[0]["file_size_before"] == 1024
        assert events[0]["file_size_after"] == 2048

    def test_log_deleted_event(self, logger):
        logger.log_event(
            event_type="deleted",
            file_path="/tmp/gone.txt",
            file_size_before=512,
        )
        events = logger.get_events(event_type="deleted")
        assert len(events) == 1
        assert events[0]["file_size_after"] is None

    def test_log_moved_event_with_old_path(self, logger):
        logger.log_event(
            event_type="moved",
            file_path="/tmp/new_name.txt",
            old_path="/tmp/old_name.txt",
        )
        events = logger.get_events(event_type="moved")
        assert events[0]["old_path"] == "/tmp/old_name.txt"
        assert events[0]["file_path"] == "/tmp/new_name.txt"

    def test_log_extension_changed_event(self, logger):
        logger.log_event(
            event_type="extension_changed",
            file_path="/tmp/file.encrypted",
            file_extension=".encrypted",
            old_path="/tmp/file.docx",
        )
        events = logger.get_events(event_type="extension_changed")
        assert events[0]["file_extension"] == ".encrypted"

    def test_timestamp_is_set_automatically(self, logger):
        logger.log_event(event_type="created", file_path="/tmp/t.txt")
        events = logger.get_events(limit=1)
        assert events[0]["timestamp"] is not None
        assert "T" in events[0]["timestamp"]  # ISO format

    def test_is_directory_flag(self, logger):
        logger.log_event(
            event_type="created",
            file_path="/tmp/newdir",
            is_directory=True,
        )
        events = logger.get_events(limit=1)
        assert events[0]["is_directory"] == 1

    def test_nullable_fields_default_to_none(self, logger):
        logger.log_event(event_type="created", file_path="/tmp/bare.txt")
        events = logger.get_events(limit=1)
        e = events[0]
        assert e["file_extension"] is None
        assert e["old_path"] is None
        assert e["file_size_before"] is None
        assert e["file_size_after"] is None
        assert e["process_id"] is None
        assert e["process_name"] is None


class TestGetEvents:
    def test_filter_by_event_type(self, logger):
        logger.log_event(event_type="created", file_path="/a")
        logger.log_event(event_type="modified", file_path="/b")
        logger.log_event(event_type="created", file_path="/c")

        created = logger.get_events(event_type="created")
        assert len(created) == 2
        assert all(e["event_type"] == "created" for e in created)

    def test_filter_by_since(self, logger):
        logger.log_event(event_type="created", file_path="/a")
        events = logger.get_events(since="2000-01-01T00:00:00")
        assert len(events) >= 1

        events = logger.get_events(since="2099-01-01T00:00:00")
        assert len(events) == 0

    def test_limit(self, logger):
        for i in range(10):
            logger.log_event(event_type="created", file_path=f"/file{i}")
        events = logger.get_events(limit=3)
        assert len(events) == 3

    def test_order_is_newest_first(self, logger):
        import time
        logger.log_event(event_type="created", file_path="/first")
        time.sleep(0.01)
        logger.log_event(event_type="created", file_path="/second")
        events = logger.get_events(limit=2)
        assert events[0]["file_path"] == "/second"
        assert events[1]["file_path"] == "/first"


class TestThreadSafety:
    def test_concurrent_writes(self, db_path):
        el = EventLogger(db_path)
        errors = []

        def writer(n):
            try:
                for i in range(20):
                    el.log_event(event_type="created", file_path=f"/thread{n}/file{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        el_check = EventLogger(db_path)
        events = el_check.get_events(limit=200)
        el_check.close()
        el.close()

        assert len(errors) == 0
        assert len(events) == 80
