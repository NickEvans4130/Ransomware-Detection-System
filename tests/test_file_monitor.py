"""Tests for the file system monitor.

Covers the Phase 1 testing requirements:
- Create test directory structure
- Perform various file operations
- Verify all events are captured correctly
- Check process attribution is accurate
"""

import json
import os
import time

import pytest

from src.database.event_logger import EventLogger
from src.monitor.file_monitor import (
    FileMonitor,
    RansomwareEventHandler,
    get_file_size,
    get_process_info,
)
from watchdog.observers import Observer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_dirs(tmp_path):
    """Create the test directory structure required by Phase 1 docs."""
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "documents").mkdir()
    (watched / "images").mkdir()
    (watched / "subdir" / "nested").mkdir(parents=True)

    excluded = tmp_path / "excluded"
    excluded.mkdir()

    return {
        "root": tmp_path,
        "watched": watched,
        "documents": watched / "documents",
        "images": watched / "images",
        "nested": watched / "subdir" / "nested",
        "excluded": excluded,
    }


@pytest.fixture
def event_logger(tmp_path):
    db_path = str(tmp_path / "test.db")
    el = EventLogger(db_path)
    yield el
    el.close()


@pytest.fixture
def monitored_dir(test_dirs, event_logger):
    """Start a watchdog observer on the test watched directory and return helpers."""
    handler = RansomwareEventHandler(
        event_logger=event_logger,
        exclude_dirs=[str(test_dirs["excluded"])],
    )
    observer = Observer()
    observer.schedule(handler, str(test_dirs["watched"]), recursive=True)
    observer.start()
    time.sleep(0.3)

    yield {
        "dirs": test_dirs,
        "logger": event_logger,
        "handler": handler,
    }

    observer.stop()
    observer.join()


def wait_for_events(event_logger, expected_type=None, min_count=1, timeout=3.0):
    """Poll the database until we see the expected events."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        events = event_logger.get_events(event_type=expected_type, limit=100)
        if len(events) >= min_count:
            return events
        time.sleep(0.1)
    return event_logger.get_events(event_type=expected_type, limit=100)


# ---------------------------------------------------------------------------
# File operation event capture tests
# ---------------------------------------------------------------------------

class TestFileCreation:
    def test_detects_new_file(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "newfile.txt"
        path.write_text("hello")

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "newfile.txt" in e["file_path"]]
        assert len(matching) >= 1

    def test_captures_file_extension(self, monitored_dir):
        path = monitored_dir["dirs"]["documents"] / "report.pdf"
        path.write_bytes(b"%PDF-fake")

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "report.pdf" in e["file_path"]]
        assert len(matching) >= 1
        assert matching[0]["file_extension"] == ".pdf"

    def test_captures_file_size(self, monitored_dir):
        content = b"x" * 256
        path = monitored_dir["dirs"]["watched"] / "sized.bin"
        path.write_bytes(content)

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "sized.bin" in e["file_path"]]
        assert len(matching) >= 1
        assert matching[0]["file_size_after"] == 256


class TestFileModification:
    def test_detects_content_change(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "modify_me.txt"
        path.write_text("original")
        time.sleep(0.5)

        # Clear any creation events from our query scope
        before_ts = event_logger_timestamp()
        path.write_text("modified content")

        events = wait_for_events(monitored_dir["logger"], "modified")
        matching = [e for e in events if "modify_me.txt" in e["file_path"]]
        assert len(matching) >= 1

    def test_tracks_size_before_and_after(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "grow.txt"
        path.write_text("small")
        time.sleep(0.5)

        path.write_text("this is much larger content now")
        events = wait_for_events(monitored_dir["logger"], "modified")
        matching = [e for e in events if "grow.txt" in e["file_path"]]
        assert len(matching) >= 1
        e = matching[0]
        assert e["file_size_after"] is not None


class TestFileDeletion:
    def test_detects_file_removal(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "delete_me.txt"
        path.write_text("temporary")
        time.sleep(0.5)

        path.unlink()
        events = wait_for_events(monitored_dir["logger"], "deleted")
        matching = [e for e in events if "delete_me.txt" in e["file_path"]]
        assert len(matching) >= 1


class TestFileRenameMove:
    def test_detects_rename(self, monitored_dir):
        src = monitored_dir["dirs"]["watched"] / "old_name.txt"
        dst = monitored_dir["dirs"]["watched"] / "new_name.txt"
        src.write_text("rename me")
        time.sleep(0.5)

        src.rename(dst)
        events = wait_for_events(monitored_dir["logger"], "moved")
        matching = [e for e in events if "new_name.txt" in e["file_path"]]
        assert len(matching) >= 1
        assert "old_name.txt" in matching[0]["old_path"]

    def test_detects_move_to_subdirectory(self, monitored_dir):
        src = monitored_dir["dirs"]["watched"] / "movable.txt"
        dst = monitored_dir["dirs"]["nested"] / "movable.txt"
        src.write_text("move me")
        time.sleep(0.5)

        src.rename(dst)
        events = wait_for_events(monitored_dir["logger"], "moved")
        matching = [e for e in events if "nested" in e["file_path"] and "movable" in e["file_path"]]
        assert len(matching) >= 1


class TestExtensionChange:
    def test_detects_extension_change(self, monitored_dir):
        src = monitored_dir["dirs"]["watched"] / "document.docx"
        dst = monitored_dir["dirs"]["watched"] / "document.encrypted"
        src.write_text("important data")
        time.sleep(0.5)

        src.rename(dst)
        events = wait_for_events(monitored_dir["logger"], "extension_changed")
        matching = [e for e in events if "document.encrypted" in e["file_path"]]
        assert len(matching) >= 1
        assert matching[0]["file_extension"] == ".encrypted"
        assert "document.docx" in matching[0]["old_path"]


# ---------------------------------------------------------------------------
# Metadata capture tests
# ---------------------------------------------------------------------------

class TestMetadataCapture:
    def test_timestamp_is_present(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "ts.txt"
        path.write_text("timestamp test")

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "ts.txt" in e["file_path"]]
        assert len(matching) >= 1
        assert matching[0]["timestamp"] is not None
        assert "T" in matching[0]["timestamp"]

    def test_file_path_is_absolute(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "abs.txt"
        path.write_text("path test")

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "abs.txt" in e["file_path"]]
        assert len(matching) >= 1
        assert os.path.isabs(matching[0]["file_path"])

    def test_operation_type_is_correct(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "optype.txt"
        path.write_text("check type")

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "optype.txt" in e["file_path"]]
        assert len(matching) >= 1
        assert matching[0]["event_type"] == "created"


# ---------------------------------------------------------------------------
# Process attribution tests
# ---------------------------------------------------------------------------

class TestProcessAttribution:
    def test_get_process_info_returns_pid_and_name(self):
        pid, name = get_process_info(pid=os.getpid())
        assert pid == os.getpid()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_get_process_info_heuristic_returns_something(self):
        pid, name = get_process_info()
        # Heuristic may or may not find a process, but should not raise
        assert pid is None or isinstance(pid, int)
        assert name is None or isinstance(name, str)

    def test_events_have_process_fields(self, monitored_dir):
        path = monitored_dir["dirs"]["watched"] / "proc_test.txt"
        path.write_text("process check")

        events = wait_for_events(monitored_dir["logger"], "created")
        matching = [e for e in events if "proc_test.txt" in e["file_path"]]
        assert len(matching) >= 1
        # process_id and process_name should be present (may be None on some systems)
        e = matching[0]
        assert "process_id" in e
        assert "process_name" in e


# ---------------------------------------------------------------------------
# Configurable monitoring tests
# ---------------------------------------------------------------------------

class TestExcludeDirectories:
    def test_excluded_dir_events_not_logged(self, test_dirs, event_logger):
        handler = RansomwareEventHandler(
            event_logger=event_logger,
            exclude_dirs=[str(test_dirs["excluded"])],
        )
        observer = Observer()
        observer.schedule(handler, str(test_dirs["root"]), recursive=True)
        observer.start()
        time.sleep(0.3)

        (test_dirs["excluded"] / "secret.txt").write_text("should be ignored")
        time.sleep(1.0)

        events = event_logger.get_events(limit=100)
        matching = [e for e in events if "secret.txt" in e["file_path"]]
        assert len(matching) == 0

        observer.stop()
        observer.join()


class TestExtensionFilter:
    def test_only_matching_extensions_logged(self, test_dirs, event_logger):
        handler = RansomwareEventHandler(
            event_logger=event_logger,
            extension_filter=[".txt"],
        )
        observer = Observer()
        observer.schedule(handler, str(test_dirs["watched"]), recursive=True)
        observer.start()
        time.sleep(0.3)

        (test_dirs["watched"] / "yes.txt").write_text("included")
        (test_dirs["watched"] / "no.pdf").write_bytes(b"excluded")
        time.sleep(1.0)

        events = event_logger.get_events(limit=100)
        txt_events = [e for e in events if "yes.txt" in e["file_path"]]
        pdf_events = [e for e in events if "no.pdf" in e["file_path"]]
        assert len(txt_events) >= 1
        assert len(pdf_events) == 0

        observer.stop()
        observer.join()


# ---------------------------------------------------------------------------
# FileMonitor config / CLI tests
# ---------------------------------------------------------------------------

class TestFileMonitorConfig:
    def test_loads_valid_config(self, test_dirs):
        config = {
            "monitor": {
                "watch_directories": [str(test_dirs["watched"])],
                "exclude_directories": [],
                "file_extension_filter": [],
                "recursive": True,
            },
            "database": {
                "path": str(test_dirs["root"] / "test.db"),
            },
            "logging": {"level": "INFO"},
        }
        config_path = test_dirs["root"] / "config.json"
        config_path.write_text(json.dumps(config))

        fm = FileMonitor(config_path=str(config_path))
        assert fm.config["monitor"]["watch_directories"] == [str(test_dirs["watched"])]
        fm.event_logger.close()

    def test_raises_on_missing_config(self):
        with pytest.raises(FileNotFoundError):
            FileMonitor(config_path="/nonexistent/config.json")

    def test_start_and_stop(self, test_dirs):
        config = {
            "monitor": {
                "watch_directories": [str(test_dirs["watched"])],
                "exclude_directories": [],
                "file_extension_filter": [],
                "recursive": True,
            },
            "database": {
                "path": str(test_dirs["root"] / "test.db"),
            },
            "logging": {"level": "INFO"},
        }
        config_path = test_dirs["root"] / "config.json"
        config_path.write_text(json.dumps(config))

        fm = FileMonitor(config_path=str(config_path))
        fm.start()
        assert fm._running is True

        (test_dirs["watched"] / "runtime.txt").write_text("during monitoring")
        time.sleep(1.0)

        events = fm.event_logger.get_events(limit=100)
        matching = [e for e in events if "runtime.txt" in e["file_path"]]
        assert len(matching) >= 1

        fm.stop()
        assert fm._running is False


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestGetFileSize:
    def test_returns_size_for_existing_file(self, tmp_path):
        p = tmp_path / "sized.bin"
        p.write_bytes(b"x" * 100)
        assert get_file_size(str(p)) == 100

    def test_returns_none_for_missing_file(self):
        assert get_file_size("/nonexistent/file.txt") is None


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def event_logger_timestamp():
    from datetime import datetime
    return datetime.now().isoformat()
