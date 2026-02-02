"""Phase 7: Performance Tests.

Verifies the system meets the documented performance targets:
    - Detection latency: <2 seconds
    - Backup overhead: <100ms per file
    - Database query performance: fast under load
    - Dashboard response times: fast API responses
"""

import json
import os
import time
import threading

import pytest

from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.entropy_analyzer import shannon_entropy, calculate_file_entropy
from src.analysis.entropy_detector import EntropyDetector
from src.database.event_logger import EventLogger
from src.response.backup_manager import BackupManager
from src.response.response_engine import ResponseEngine
from src.dashboard.app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def perf_workspace(tmp_path):
    """Workspace optimised for performance measurements."""
    db_path = str(tmp_path / "events.db")
    vault = str(tmp_path / "vault")
    ent_db = str(tmp_path / "ent.db")
    config_path = str(tmp_path / "config.json")

    config = {
        "monitor": {"watch_directories": [], "exclude_directories": [],
                     "file_extension_filter": [], "recursive": True},
        "database": {"path": db_path},
        "entropy": {"baseline_db_path": ent_db, "delta_threshold": 2.0},
        "logging": {"level": "WARNING"},
    }
    with open(config_path, "w") as f:
        json.dump(config, f)

    el = EventLogger(db_path)
    bm = BackupManager(vault)
    entropy = EntropyDetector(ent_db)
    re = ResponseEngine(bm, safe_mode=False, enable_desktop_alerts=False)
    ba = BehaviorAnalyzer(time_window=60)

    yield {
        "event_logger": el,
        "backup_manager": bm,
        "entropy_detector": entropy,
        "response_engine": re,
        "behavior_analyzer": ba,
        "config_path": config_path,
        "tmp_path": tmp_path,
    }

    el.close()
    bm.close()
    entropy.close()


# ---------------------------------------------------------------------------
# Detection Latency (<2 seconds)
# ---------------------------------------------------------------------------

class TestDetectionLatency:
    def test_single_event_analysis_latency(self, perf_workspace):
        """Single event processing should be well under 2 seconds."""
        ba = perf_workspace["behavior_analyzer"]
        start = time.time()
        for i in range(100):
            ba.process_event(
                event_type="modified",
                file_path=f"/data/f{i}.txt",
                process_id=1,
                process_name="test",
                entropy_delta=3.0,
            )
        elapsed = time.time() - start
        assert elapsed < 2.0, f"100 events took {elapsed:.3f}s, expected <2s"

    def test_threat_detection_latency(self, perf_workspace):
        """Full threat detection pipeline should complete within 2 seconds."""
        ba = perf_workspace["behavior_analyzer"]
        start = time.time()

        # Simulate enough events to trigger CRITICAL
        for i in range(50):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/f{i}.txt",
                process_id=1,
                process_name="evil",
                entropy_delta=4.0,
            )

        score = ba.get_score(1)
        elapsed = time.time() - start

        assert elapsed < 2.0, f"Detection took {elapsed:.3f}s"
        assert score is not None
        assert score.action_required is True

    def test_entropy_calculation_latency(self, perf_workspace):
        """Shannon entropy on a 1KB block should be fast."""
        data = os.urandom(1024)
        start = time.time()
        for _ in range(1000):
            shannon_entropy(data)
        elapsed = time.time() - start
        per_call = elapsed / 1000
        assert per_call < 0.002, f"Entropy calc: {per_call*1000:.2f}ms per call"

    def test_file_entropy_latency(self, perf_workspace):
        """File entropy calculation should be fast."""
        tmp = perf_workspace["tmp_path"]
        f = tmp / "perf.txt"
        f.write_bytes(os.urandom(10240))
        start = time.time()
        for _ in range(100):
            calculate_file_entropy(str(f))
        elapsed = time.time() - start
        per_call = elapsed / 100
        assert per_call < 0.020, f"File entropy: {per_call*1000:.2f}ms per call"

    def test_entropy_detector_latency(self, perf_workspace):
        """EntropyDetector.analyze_file should be fast."""
        det = perf_workspace["entropy_detector"]
        tmp = perf_workspace["tmp_path"]
        f = tmp / "detect_perf.txt"
        f.write_bytes(os.urandom(4096))
        start = time.time()
        for _ in range(50):
            det.analyze_file(str(f))
        elapsed = time.time() - start
        per_call = elapsed / 50
        assert per_call < 0.040, f"Detector: {per_call*1000:.2f}ms per call"


# ---------------------------------------------------------------------------
# Backup Overhead (<100ms per file)
# ---------------------------------------------------------------------------

class TestBackupOverhead:
    def test_single_file_backup_latency(self, perf_workspace):
        """Single file backup should be under 100ms."""
        bm = perf_workspace["backup_manager"]
        tmp = perf_workspace["tmp_path"]

        f = tmp / "backup_perf.txt"
        f.write_text("benchmark data " * 100)  # ~1.5KB

        start = time.time()
        bm.backup_file(str(f))
        elapsed = time.time() - start
        assert elapsed < 0.100, f"Backup took {elapsed*1000:.1f}ms, expected <100ms"

    def test_batch_backup_throughput(self, perf_workspace):
        """Batch backup: average per-file should be under 100ms."""
        bm = perf_workspace["backup_manager"]
        tmp = perf_workspace["tmp_path"]

        files = []
        for i in range(50):
            f = tmp / f"batch_{i}.txt"
            f.write_text(f"data {i} " * 100)
            files.append(str(f))

        start = time.time()
        for fpath in files:
            bm.backup_file(fpath)
        elapsed = time.time() - start
        per_file = elapsed / 50
        assert per_file < 0.100, \
            f"Avg backup: {per_file*1000:.1f}ms per file, expected <100ms"

    def test_larger_file_backup(self, perf_workspace):
        """Larger files (100KB) should still be reasonably fast."""
        bm = perf_workspace["backup_manager"]
        tmp = perf_workspace["tmp_path"]

        f = tmp / "large.bin"
        f.write_bytes(os.urandom(102400))  # 100KB

        start = time.time()
        bm.backup_file(str(f))
        elapsed = time.time() - start
        assert elapsed < 0.500, f"100KB backup took {elapsed*1000:.1f}ms"

    def test_restore_latency(self, perf_workspace):
        """Single file restore should be fast."""
        bm = perf_workspace["backup_manager"]
        tmp = perf_workspace["tmp_path"]

        f = tmp / "restore_perf.txt"
        f.write_text("restore me")
        bm.backup_file(str(f))
        backups = bm.snapshot.get_backups(original_path=str(f))
        f.write_text("changed")

        start = time.time()
        bm.recovery.restore_file(backups[0]["id"])
        elapsed = time.time() - start
        assert elapsed < 0.100, f"Restore took {elapsed*1000:.1f}ms"


# ---------------------------------------------------------------------------
# Database Query Performance
# ---------------------------------------------------------------------------

class TestDatabasePerformance:
    def test_event_insert_throughput(self, perf_workspace):
        """Should handle rapid event inserts."""
        el = perf_workspace["event_logger"]
        start = time.time()
        for i in range(500):
            el.log_event(event_type="modified", file_path=f"/f{i}.txt",
                         process_id=1)
        elapsed = time.time() - start
        per_insert = elapsed / 500
        assert per_insert < 0.010, \
            f"Insert: {per_insert*1000:.2f}ms per event"

    def test_event_query_after_bulk_insert(self, perf_workspace):
        """Queries should be fast even with many events."""
        el = perf_workspace["event_logger"]
        for i in range(1000):
            el.log_event(event_type="modified", file_path=f"/f{i}.txt",
                         process_id=i % 10)

        start = time.time()
        events = el.get_events(limit=50)
        elapsed = time.time() - start
        assert elapsed < 0.050, f"Query took {elapsed*1000:.1f}ms"
        assert len(events) == 50

    def test_event_query_with_filter(self, perf_workspace):
        """Filtered queries should use indexes."""
        el = perf_workspace["event_logger"]
        for i in range(500):
            etype = "created" if i % 2 == 0 else "modified"
            el.log_event(event_type=etype, file_path=f"/f{i}.txt")

        start = time.time()
        events = el.get_events(event_type="created", limit=50)
        elapsed = time.time() - start
        assert elapsed < 0.050, f"Filtered query took {elapsed*1000:.1f}ms"

    def test_backup_index_query(self, perf_workspace):
        """Backup index queries should be fast after bulk inserts."""
        bm = perf_workspace["backup_manager"]
        tmp = perf_workspace["tmp_path"]

        for i in range(100):
            f = tmp / f"idx_{i}.txt"
            f.write_text(f"data {i}")
            bm.backup_file(str(f), process_name="proc")

        start = time.time()
        backups = bm.snapshot.get_backups(process_name="proc", limit=50)
        elapsed = time.time() - start
        assert elapsed < 0.050, f"Backup query took {elapsed*1000:.1f}ms"
        assert len(backups) == 50

    def test_concurrent_reads_and_writes(self, perf_workspace):
        """Database should handle concurrent readers and writers."""
        el = perf_workspace["event_logger"]
        errors = []

        def writer():
            try:
                for i in range(100):
                    el.log_event(event_type="modified",
                                 file_path=f"/w{i}.txt")
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(50):
                    el.get_events(limit=10)
            except Exception as e:
                errors.append(e)

        threads = (
            [threading.Thread(target=writer) for _ in range(3)] +
            [threading.Thread(target=reader) for _ in range(3)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Dashboard Response Times
# ---------------------------------------------------------------------------

class TestDashboardPerformance:
    @pytest.fixture
    def client(self, perf_workspace):
        el = perf_workspace["event_logger"]
        bm = perf_workspace["backup_manager"]
        re = perf_workspace["response_engine"]
        ba = perf_workspace["behavior_analyzer"]

        # Seed some data
        for i in range(100):
            el.log_event(event_type="modified", file_path=f"/f{i}.txt")

        app = create_app(
            config_path=perf_workspace["config_path"],
            event_logger=el,
            backup_manager=bm,
            response_engine=re,
            behavior_analyzer=ba,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_status_endpoint_latency(self, client):
        start = time.time()
        for _ in range(50):
            client.get("/api/status")
        elapsed = time.time() - start
        per_call = elapsed / 50
        assert per_call < 0.050, f"Status: {per_call*1000:.1f}ms per call"

    def test_events_endpoint_latency(self, client):
        start = time.time()
        for _ in range(50):
            client.get("/api/events?limit=50")
        elapsed = time.time() - start
        per_call = elapsed / 50
        assert per_call < 0.050, f"Events: {per_call*1000:.1f}ms per call"

    def test_config_endpoint_latency(self, client):
        start = time.time()
        for _ in range(50):
            client.get("/api/config")
        elapsed = time.time() - start
        per_call = elapsed / 50
        assert per_call < 0.020, f"Config: {per_call*1000:.1f}ms per call"

    def test_threats_endpoint_latency(self, client):
        start = time.time()
        for _ in range(50):
            client.get("/api/threats")
        elapsed = time.time() - start
        per_call = elapsed / 50
        assert per_call < 0.050, f"Threats: {per_call*1000:.1f}ms per call"

    def test_backups_endpoint_latency(self, client):
        start = time.time()
        for _ in range(50):
            client.get("/api/backups")
        elapsed = time.time() - start
        per_call = elapsed / 50
        assert per_call < 0.050, f"Backups: {per_call*1000:.1f}ms per call"
