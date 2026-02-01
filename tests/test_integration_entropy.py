"""Integration tests: file monitor + entropy analysis pipeline.

Verifies the full Phase 1+2 pipeline where file system events trigger
entropy baseline tracking, change detection, and suspicious spike alerting.

Tests use the exact file types from the Phase 2 docs:
  .txt, .docx, .pdf, .jpg, .zip
plus simulated encryption and password-protected ZIP scenarios.
"""

import json
import os
import random
import time
import zipfile

import pytest
from watchdog.observers import Observer

from src.database.event_logger import EventLogger
from src.analysis.entropy_detector import EntropyDetector, HIGH_ENTROPY_ABSOLUTE
from src.monitor.file_monitor import RansomwareEventHandler, FileMonitor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_dirs(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    return {"root": tmp_path, "watched": watched}


@pytest.fixture
def integrated_monitor(test_dirs):
    """Start a fully integrated monitor with entropy detection enabled."""
    db_path = str(test_dirs["root"] / "events.db")
    baseline_path = str(test_dirs["root"] / "baselines.db")

    event_logger = EventLogger(db_path)
    entropy_detector = EntropyDetector(baseline_path)
    handler = RansomwareEventHandler(
        event_logger=event_logger,
        entropy_detector=entropy_detector,
    )

    observer = Observer()
    observer.schedule(handler, str(test_dirs["watched"]), recursive=True)
    observer.start()
    time.sleep(0.3)

    yield {
        "dirs": test_dirs,
        "event_logger": event_logger,
        "entropy_detector": entropy_detector,
        "handler": handler,
    }

    observer.stop()
    observer.join()
    entropy_detector.close()
    event_logger.close()


def wait_for_events(event_logger, event_type=None, min_count=1, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        events = event_logger.get_events(event_type=event_type, limit=200)
        if len(events) >= min_count:
            return events
        time.sleep(0.1)
    return event_logger.get_events(event_type=event_type, limit=200)


# ---------------------------------------------------------------------------
# Baseline tracking on create
# ---------------------------------------------------------------------------

class TestBaselineOnCreate:
    def test_txt_baseline_recorded(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "readme.txt"
        p.write_text("Normal text file content.\n" * 50)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.3)

        det = integrated_monitor["entropy_detector"]
        baseline = det.baseline.get_baseline(str(p))
        assert baseline is not None
        assert 3.0 <= baseline <= 5.5

    def test_docx_baseline_recorded(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "report.docx"
        with zipfile.ZipFile(str(p), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("word/document.xml",
                         "<w:document><w:body><w:p><w:r><w:t>Content</w:t>"
                         "</w:r></w:p></w:body></w:document>")

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.3)

        baseline = integrated_monitor["entropy_detector"].baseline.get_baseline(str(p))
        assert baseline is not None
        assert 4.0 <= baseline <= 7.5

    def test_pdf_baseline_recorded(self, integrated_monitor):
        pdf_bytes = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF"
        )
        p = integrated_monitor["dirs"]["watched"] / "doc.pdf"
        p.write_bytes(pdf_bytes)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.3)

        baseline = integrated_monitor["entropy_detector"].baseline.get_baseline(str(p))
        assert baseline is not None
        assert 3.5 <= baseline <= 6.5

    def test_jpg_baseline_recorded(self, integrated_monitor):
        random.seed(99)
        header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        body = bytes(random.randint(0, 255) for _ in range(1024))
        p = integrated_monitor["dirs"]["watched"] / "photo.jpg"
        p.write_bytes(header + body)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.3)

        baseline = integrated_monitor["entropy_detector"].baseline.get_baseline(str(p))
        assert baseline is not None
        assert 5.0 <= baseline <= 8.0

    def test_zip_baseline_recorded(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "archive.zip"
        with zipfile.ZipFile(str(p), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.txt", "Some data content here\n" * 200)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.3)

        baseline = integrated_monitor["entropy_detector"].baseline.get_baseline(str(p))
        assert baseline is not None
        assert 4.0 <= baseline <= 8.0


# ---------------------------------------------------------------------------
# Change detection on modify (delta > 2.0 threshold)
# ---------------------------------------------------------------------------

class TestEntropyChangeDetection:
    def test_txt_encrypted_triggers_alert(self, integrated_monitor):
        """Simulate ransomware encrypting a .txt file."""
        p = integrated_monitor["dirs"]["watched"] / "important.txt"
        p.write_text("This is my important document.\n" * 100)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        # Overwrite with random bytes (simulated encryption)
        random.seed(42)
        p.write_bytes(bytes(random.randint(0, 255) for _ in range(1024)))

        wait_for_events(integrated_monitor["event_logger"], "modified")
        time.sleep(0.5)

        alerts = integrated_monitor["entropy_detector"].baseline.get_alerts(
            suspicious_only=True
        )
        matching = [a for a in alerts if "important.txt" in a["file_path"]]
        assert len(matching) >= 1
        assert matching[0]["delta"] >= 2.0

    def test_docx_encrypted_triggers_alert(self, integrated_monitor):
        """Simulate ransomware encrypting a .docx file."""
        p = integrated_monitor["dirs"]["watched"] / "report.docx"
        with zipfile.ZipFile(str(p), "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("word/document.xml",
                         "<w:document><w:body>" + "<w:p><w:r><w:t>Line</w:t></w:r></w:p>" * 100
                         + "</w:body></w:document>")

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        random.seed(7)
        p.write_bytes(bytes(random.randint(0, 255) for _ in range(2048)))

        wait_for_events(integrated_monitor["event_logger"], "modified")
        time.sleep(0.5)

        alerts = integrated_monitor["entropy_detector"].baseline.get_alerts(
            suspicious_only=True
        )
        matching = [a for a in alerts if "report.docx" in a["file_path"]]
        assert len(matching) >= 1

    def test_normal_edit_no_alert(self, integrated_monitor):
        """Normal text edit should not trigger a suspicious alert."""
        p = integrated_monitor["dirs"]["watched"] / "notes.txt"
        p.write_text("Meeting notes from today.\n" * 50)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        p.write_text("Meeting notes from today.\nUpdated with action items.\n" * 50)

        wait_for_events(integrated_monitor["event_logger"], "modified")
        time.sleep(0.5)

        alerts = integrated_monitor["entropy_detector"].baseline.get_alerts(
            suspicious_only=True
        )
        matching = [a for a in alerts if "notes.txt" in a["file_path"]]
        assert len(matching) == 0


# ---------------------------------------------------------------------------
# Baseline cleanup on delete
# ---------------------------------------------------------------------------

class TestBaselineCleanupOnDelete:
    def test_deleted_file_baseline_removed(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "temp.txt"
        p.write_text("temporary data")

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        det = integrated_monitor["entropy_detector"]
        assert det.baseline.get_baseline(str(p)) is not None

        p.unlink()

        wait_for_events(integrated_monitor["event_logger"], "deleted")
        time.sleep(0.5)

        assert det.baseline.get_baseline(str(p)) is None


# ---------------------------------------------------------------------------
# Cache verification
# ---------------------------------------------------------------------------

class TestEntropyCache:
    def test_cache_populated_on_create(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "cached.txt"
        p.write_text("cache test content\n" * 40)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.3)

        det = integrated_monitor["entropy_detector"]
        assert str(p) in det._cache

    def test_cache_updated_on_modify(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "evolve.txt"
        p.write_text("initial content\n" * 40)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        det = integrated_monitor["entropy_detector"]
        initial_cached = det._cache.get(str(p))

        p.write_text("different content with more variety xyz 123!@#\n" * 40)

        wait_for_events(integrated_monitor["event_logger"], "modified")
        time.sleep(0.5)

        updated_cached = det._cache.get(str(p))
        assert updated_cached is not None
        # Cache value should reflect the new content
        assert updated_cached != initial_cached or initial_cached is None

    def test_cache_cleared_on_delete(self, integrated_monitor):
        p = integrated_monitor["dirs"]["watched"] / "vanish.txt"
        p.write_text("soon to be gone")

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        det = integrated_monitor["entropy_detector"]
        assert str(p) in det._cache

        p.unlink()

        wait_for_events(integrated_monitor["event_logger"], "deleted")
        time.sleep(0.5)

        assert str(p) not in det._cache


# ---------------------------------------------------------------------------
# Password-protected ZIP (legitimate encrypted file)
# ---------------------------------------------------------------------------

class TestLegitimateEncryptedFiles:
    def test_password_zip_created_flagged_high_entropy(self, integrated_monitor):
        """A new file with near-random content (like a password-protected ZIP)
        should be flagged on creation if entropy >= 7.5."""
        random.seed(77)
        body = bytes(random.randint(0, 255) for _ in range(2048))
        p = integrated_monitor["dirs"]["watched"] / "protected.zip"
        p.write_bytes(b"PK\x03\x04" + body)

        wait_for_events(integrated_monitor["event_logger"], "created")
        time.sleep(0.5)

        det = integrated_monitor["entropy_detector"]
        baseline = det.baseline.get_baseline(str(p))
        assert baseline is not None
        assert baseline >= HIGH_ENTROPY_ABSOLUTE

        alerts = det.baseline.get_alerts(suspicious_only=True)
        matching = [a for a in alerts if "protected.zip" in a["file_path"]]
        assert len(matching) >= 1


# ---------------------------------------------------------------------------
# FileMonitor class integration (config-driven)
# ---------------------------------------------------------------------------

class TestFileMonitorIntegration:
    def test_full_config_driven_pipeline(self, test_dirs):
        config = {
            "monitor": {
                "watch_directories": [str(test_dirs["watched"])],
                "exclude_directories": [],
                "file_extension_filter": [],
                "recursive": True,
            },
            "entropy": {
                "baseline_db_path": str(test_dirs["root"] / "ent.db"),
                "delta_threshold": 2.0,
            },
            "database": {
                "path": str(test_dirs["root"] / "ev.db"),
            },
            "logging": {"level": "INFO"},
        }
        config_path = test_dirs["root"] / "config.json"
        config_path.write_text(json.dumps(config))

        fm = FileMonitor(config_path=str(config_path))
        assert fm.entropy_detector is not None

        fm.start()
        try:
            p = test_dirs["watched"] / "pipeline.txt"
            p.write_text("Hello world.\n" * 100)
            time.sleep(1.0)

            baseline = fm.entropy_detector.baseline.get_baseline(str(p))
            assert baseline is not None

            random.seed(0)
            p.write_bytes(bytes(random.randint(0, 255) for _ in range(1024)))
            time.sleep(1.0)

            alerts = fm.entropy_detector.baseline.get_alerts(suspicious_only=True)
            matching = [a for a in alerts if "pipeline.txt" in a["file_path"]]
            assert len(matching) >= 1
        finally:
            fm.stop()
