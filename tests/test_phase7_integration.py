"""Phase 7 Integration Tests.

Tests the full pipeline: detection -> response -> recovery.
Also covers multi-process scenarios, concurrent file operations,
and edge cases (locked files, missing directories).
"""

import json
import os
import time
import threading

import pytest

from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.analysis.entropy_analyzer import calculate_file_entropy
from src.analysis.entropy_detector import EntropyDetector
from src.analysis.threat_scoring import ThreatScore
from src.database.event_logger import EventLogger
from src.response.backup_manager import BackupManager
from src.response.response_engine import ResponseEngine, escalation_level
from src.response.recovery_workflow import RecoveryWorkflow
from src.dashboard.app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path):
    """Create a full workspace with all services wired together."""
    db_path = str(tmp_path / "events.db")
    vault_path = str(tmp_path / "vault")
    ent_db = str(tmp_path / "ent.db")
    config_path = str(tmp_path / "config.json")

    config = {
        "monitor": {"watch_directories": [], "exclude_directories": [],
                     "file_extension_filter": [], "recursive": True},
        "database": {"path": db_path},
        "entropy": {"baseline_db_path": ent_db, "delta_threshold": 2.0},
        "logging": {"level": "INFO"},
    }
    with open(config_path, "w") as f:
        json.dump(config, f)

    el = EventLogger(db_path)
    bm = BackupManager(vault_path=vault_path)
    entropy = EntropyDetector(ent_db)
    re = ResponseEngine(bm, safe_mode=False, enable_desktop_alerts=False)
    ba = BehaviorAnalyzer(
        time_window=60,
        mass_modify_threshold=5,
        entropy_spike_min_files=2,
        on_threat=lambda ts: re.respond(ts),
    )

    yield {
        "event_logger": el,
        "backup_manager": bm,
        "entropy_detector": entropy,
        "response_engine": re,
        "behavior_analyzer": ba,
        "config_path": config_path,
        "tmp_path": tmp_path,
        "vault_path": vault_path,
    }

    el.close()
    bm.close()
    entropy.close()


# ---------------------------------------------------------------------------
# Full Pipeline: Detection -> Response -> Recovery
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_detection_triggers_response(self, workspace):
        """Simulate ransomware-like activity, verify detection triggers response."""
        ba = workspace["behavior_analyzer"]
        re = workspace["response_engine"]

        # Simulate rapid file modifications from temp dir with entropy spikes
        for i in range(10):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/file{i}.txt",
                process_id=1000,
                process_name="suspicious.exe",
                entropy_delta=3.5,
            )

        # The on_threat callback should have triggered a response
        assert len(re.response_log) > 0
        last = re.response_log[-1]
        assert last.escalation_level >= 3

    def test_full_backup_and_recovery(self, workspace):
        """Create files, back them up, simulate damage, restore."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        # Create original files
        files = []
        for i in range(5):
            f = tmp / f"doc{i}.txt"
            f.write_text(f"Original content {i}")
            files.append(f)
            bm.backup_file(str(f), process_name="ransomware_sim")

        # Simulate encryption (overwrite)
        for f in files:
            f.write_bytes(os.urandom(256))

        # Verify files are corrupted
        for f in files:
            assert f.read_text(errors="replace") != f"Original content {files.index(f)}"

        # Restore all files affected by the process
        results = bm.recovery.restore_by_process("ransomware_sim")
        succeeded = sum(1 for r in results if r.success)
        assert succeeded == 5

        # Verify content restored
        for i, f in enumerate(files):
            assert f.read_text() == f"Original content {i}"

    def test_detection_to_backup_to_restore(self, workspace):
        """End-to-end: detect -> backup -> damage -> restore via API."""
        ba = workspace["behavior_analyzer"]
        bm = workspace["backup_manager"]
        re = workspace["response_engine"]
        tmp = workspace["tmp_path"]

        # Create and backup a file
        f = tmp / "important.txt"
        f.write_text("critical data")
        bm.backup_file(str(f), process_name="evil.exe")

        # Simulate detection of ransomware
        for i in range(10):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/file{i}.txt",
                process_id=2000,
                process_name="evil.exe",
                entropy_delta=4.0,
            )

        # Response should have been triggered
        assert len(re.response_log) > 0

        # Simulate file corruption
        f.write_bytes(os.urandom(128))

        # Recovery workflow
        wf = RecoveryWorkflow(bm)
        results = wf.auto_restore("evil.exe")
        assert any(r.success for r in results)
        assert f.read_text() == "critical data"

    def test_incident_report_generated_for_level4(self, workspace):
        """Verify Level 4 response generates an incident report."""
        bm = workspace["backup_manager"]
        re = workspace["response_engine"]

        threat = ThreatScore(
            process_id=99999, process_name="ransomware",
            score=95, level="CRITICAL",
            triggered_indicators={"mass_modification": "50 files",
                                  "entropy_spike": "10 files"},
            action_required=True,
        )
        result = re.respond(threat)
        assert result.escalation_level == 4
        assert result.incident_report is not None
        report_json = result.incident_report.to_json()
        data = json.loads(report_json)
        assert data["threat_score"] == 95


# ---------------------------------------------------------------------------
# Multi-Process Scenarios
# ---------------------------------------------------------------------------

class TestMultiProcess:
    def test_independent_process_tracking(self, workspace):
        """Two processes with different behavior should have independent scores."""
        ba = workspace["behavior_analyzer"]

        # Normal process
        for i in range(3):
            ba.process_event(
                event_type="modified", file_path=f"/home/user/doc{i}.txt",
                process_id=100, process_name="word",
            )

        # Suspicious process
        for i in range(10):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/f{i}.txt",
                process_id=200, process_name="evil",
                entropy_delta=4.0,
            )

        score_normal = ba.get_score(100)
        score_evil = ba.get_score(200)
        assert score_normal.score < score_evil.score
        assert score_normal.action_required is False
        assert score_evil.action_required is True

    def test_multiple_threats_logged(self, workspace):
        """Multiple processes crossing threshold should all be logged."""
        re = workspace["response_engine"]

        for pid in [300, 301, 302]:
            threat = ThreatScore(pid, f"proc{pid}", 80, "CRITICAL",
                                 {"test": "d"}, True)
            re.respond(threat)

        log = re.response_log
        pids = [r.threat_score.process_id for r in log]
        assert 300 in pids and 301 in pids and 302 in pids


# ---------------------------------------------------------------------------
# Concurrent Operations
# ---------------------------------------------------------------------------

class TestConcurrency:
    def test_concurrent_event_logging(self, workspace):
        """Multiple threads logging events simultaneously."""
        el = workspace["event_logger"]
        errors = []

        def log_batch(thread_id):
            try:
                for i in range(50):
                    el.log_event(
                        event_type="modified",
                        file_path=f"/t{thread_id}/f{i}.txt",
                        process_id=thread_id,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_batch, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        events = el.get_events(limit=1000)
        assert len(events) == 250  # 5 threads * 50 events

    def test_concurrent_backups(self, workspace):
        """Multiple threads creating backups simultaneously."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]
        errors = []

        def backup_batch(thread_id):
            try:
                for i in range(10):
                    f = tmp / f"t{thread_id}_f{i}.txt"
                    f.write_text(f"data-{thread_id}-{i}")
                    bm.backup_file(str(f), process_name=f"thread{thread_id}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=backup_batch, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        backups = bm.snapshot.get_backups(limit=1000)
        assert len(backups) == 40  # 4 threads * 10 files

    def test_concurrent_behavior_analysis(self, workspace):
        """Multiple threads feeding events to the behavior analyzer."""
        ba = workspace["behavior_analyzer"]
        errors = []

        def analyze_batch(pid):
            try:
                for i in range(20):
                    ba.process_event(
                        event_type="modified",
                        file_path=f"/dir{pid}/f{i}.txt",
                        process_id=pid,
                        process_name=f"proc{pid}",
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=analyze_batch, args=(p,))
                   for p in range(500, 505)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        scores = ba.get_all_scores()
        assert len(scores) >= 5


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_backup_missing_parent_directory(self, workspace):
        """Restore when the original parent directory was deleted."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        subdir = tmp / "deep" / "nested"
        subdir.mkdir(parents=True)
        f = subdir / "file.txt"
        f.write_text("deep file")
        bm.backup_file(str(f))

        # Delete entire tree
        import shutil
        shutil.rmtree(str(tmp / "deep"))
        assert not f.exists()

        # Restore should recreate parent directories
        backups = bm.snapshot.get_backups(original_path=str(f))
        result = bm.recovery.restore_file(backups[0]["id"])
        assert result.success is True
        assert f.read_text() == "deep file"

    def test_restore_with_corrupted_backup(self, workspace):
        """Verify integrity check catches tampered backup."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        f = tmp / "tamper.txt"
        f.write_text("original content")
        bm.backup_file(str(f))
        backups = bm.snapshot.get_backups(original_path=str(f))

        # Tamper with the backup file
        backup_path = backups[0]["backup_path"]
        with open(backup_path, "w") as bf:
            bf.write("TAMPERED")

        # Restore should fail integrity check
        result = bm.recovery.restore_file(backups[0]["id"])
        assert result.success is False
        assert result.integrity_ok is False

    def test_empty_file_backup_restore(self, workspace):
        """Empty files should be backed up and restored correctly."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        f = tmp / "empty.txt"
        f.write_bytes(b"")
        bm.backup_file(str(f))
        f.write_text("now has content")

        backups = bm.snapshot.get_backups(original_path=str(f))
        result = bm.recovery.restore_file(backups[0]["id"])
        assert result.success is True
        assert f.read_bytes() == b""

    def test_large_filename_handling(self, workspace):
        """Long filenames that stay within OS limits should work."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        # Use a name that's long but within the 255-char filesystem limit
        # after flattening (path separators become underscores)
        long_name = "a" * 100 + ".txt"
        f = tmp / long_name
        f.write_text("long name file")
        bm.backup_file(str(f))
        backups = bm.snapshot.get_backups()
        assert len(backups) == 1

    def test_special_characters_in_path(self, workspace):
        """Paths with spaces and special chars should work."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        d = tmp / "dir with spaces"
        d.mkdir()
        f = d / "file (copy).txt"
        f.write_text("special chars")
        bm.backup_file(str(f))
        f.write_text("changed")

        backups = bm.snapshot.get_backups(original_path=str(f))
        result = bm.recovery.restore_file(backups[0]["id"])
        assert result.success is True
        assert f.read_text() == "special chars"

    def test_zero_score_no_actions(self, workspace):
        """Score of 0 should produce no alerts or process actions."""
        re = workspace["response_engine"]
        threat = ThreatScore(1, "safe", 0, "NORMAL", {}, False)
        result = re.respond(threat)
        assert result.escalation_level == 0
        assert len(result.actions_taken) == 0
        assert len(result.alerts_sent) == 0
        assert len(result.process_actions) == 0


# ---------------------------------------------------------------------------
# Dashboard Integration
# ---------------------------------------------------------------------------

class TestDashboardIntegration:
    def test_api_reflects_backend_state(self, workspace):
        """Dashboard API should reflect real service state."""
        el = workspace["event_logger"]
        bm = workspace["backup_manager"]
        re = workspace["response_engine"]
        ba = workspace["behavior_analyzer"]

        # Add some data
        el.log_event(event_type="created", file_path="/test.txt")
        threat = ThreatScore(1, "proc", 60, "LIKELY", {"t": "d"}, False)
        re.respond(threat)

        app = create_app(
            config_path=workspace["config_path"],
            event_logger=el,
            backup_manager=bm,
            response_engine=re,
            behavior_analyzer=ba,
        )
        app.config["TESTING"] = True

        with app.test_client() as c:
            # Events endpoint
            evts = c.get("/api/events").get_json()
            assert evts["total"] >= 1

            # Threats endpoint
            threats = c.get("/api/threats").get_json()
            assert threats["total"] >= 1

            # Status endpoint
            status = c.get("/api/status").get_json()
            assert status["status"] == "running"

    def test_restore_via_api(self, workspace):
        """Test file restoration through the dashboard API."""
        bm = workspace["backup_manager"]
        tmp = workspace["tmp_path"]

        f = tmp / "api_restore.txt"
        f.write_text("original")
        bm.backup_file(str(f), process_name="evil")
        f.write_text("corrupted")

        app = create_app(
            config_path=workspace["config_path"],
            event_logger=workspace["event_logger"],
            backup_manager=bm,
            response_engine=workspace["response_engine"],
            behavior_analyzer=workspace["behavior_analyzer"],
        )
        app.config["TESTING"] = True

        with app.test_client() as c:
            resp = c.post("/api/restore",
                          json={"process_name": "evil"},
                          content_type="application/json")
            data = resp.get_json()
            assert data["succeeded"] >= 1
            assert f.read_text() == "original"

    def test_config_roundtrip_via_api(self, workspace):
        """Config update via API should persist and return correctly."""
        app = create_app(
            config_path=workspace["config_path"],
            event_logger=workspace["event_logger"],
            backup_manager=workspace["backup_manager"],
            response_engine=workspace["response_engine"],
            behavior_analyzer=workspace["behavior_analyzer"],
        )
        app.config["TESTING"] = True

        with app.test_client() as c:
            c.put("/api/config",
                  json={"monitor": {"recursive": False}},
                  content_type="application/json")
            data = c.get("/api/config").get_json()
            assert data["monitor"]["recursive"] is False
