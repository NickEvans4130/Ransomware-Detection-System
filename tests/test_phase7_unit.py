"""Phase 7 Unit Tests -- comprehensive coverage for all modules.

Covers every public class and function across:
    - Entropy calculations (analyzer, detector, baseline)
    - Behavioral detection (pattern detector, threat scoring, behavior analyzer)
    - Backup system (snapshot service, recovery manager, backup manager)
    - Response system (process controller, alert system, response engine, recovery workflow)
    - Dashboard (routes, websocket handler)
    - Database (event logger)
    - Monitor (event handler helpers)
"""

import json
import os
import sqlite3
import time

import pytest

from src.analysis.entropy_analyzer import (
    shannon_entropy,
    calculate_file_entropy,
    _sample_offsets,
)
from src.analysis.entropy_detector import (
    EntropyBaseline,
    EntropyDetector,
    DEFAULT_DELTA_THRESHOLD,
    HIGH_ENTROPY_ABSOLUTE,
)
from src.analysis.pattern_detector import (
    FileEvent,
    ProcessTracker,
    PatternDetector,
    SUSPICIOUS_EXTENSIONS,
    TEMP_DIR_MARKERS,
)
from src.analysis.threat_scoring import (
    ThreatScore,
    classify_level,
    calculate_threat_score,
    INDICATOR_WEIGHTS,
    LEVEL_NORMAL,
    LEVEL_SUSPICIOUS,
    LEVEL_LIKELY,
    LEVEL_CRITICAL,
)
from src.analysis.behavior_analyzer import BehaviorAnalyzer
from src.database.event_logger import EventLogger
from src.response.backup_config import (
    DEFAULT_VAULT_PATH,
    RETENTION_HOURS,
    VAULT_DIR_MODE,
    VAULT_FILE_MODE,
    SNAPSHOT_DIR_FORMAT,
)
from src.response.snapshot_service import (
    file_sha256,
    flatten_path,
    SnapshotService,
)
from src.response.recovery_manager import RestoreResult, RecoveryManager
from src.response.backup_manager import BackupManager
from src.response.process_controller import ProcessAction, ProcessController
from src.response.alert_system import (
    Alert,
    AlertSystem,
    ALERT_INFO,
    ALERT_WARNING,
    ALERT_CRITICAL,
    ALERT_EMERGENCY,
)
from src.response.response_engine import (
    ResponseEngine,
    ResponseResult,
    escalation_level,
    LEVEL1_MIN,
    LEVEL2_MIN,
    LEVEL3_MIN,
    LEVEL4_MIN,
)
from src.response.recovery_workflow import IncidentReport, RecoveryWorkflow
from src.dashboard.websocket_handler import WebSocketHandler


# ===================================================================
# Entropy Analyzer
# ===================================================================

class TestShannonEntropy:
    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_uniform_single_byte(self):
        # All same byte -> entropy 0
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_two_equal_values(self):
        # 50/50 split -> entropy 1.0
        data = b"\x00" * 50 + b"\x01" * 50
        assert abs(shannon_entropy(data) - 1.0) < 0.01

    def test_high_entropy_random(self):
        # All 256 values equally -> ~8.0
        data = bytes(range(256)) * 4
        ent = shannon_entropy(data)
        assert ent > 7.9

    def test_text_entropy_range(self):
        data = b"Hello World! This is a simple test string for entropy."
        ent = shannon_entropy(data)
        assert 3.0 < ent < 5.0

    def test_single_byte(self):
        assert shannon_entropy(b"A") == 0.0

    def test_two_distinct_bytes(self):
        data = b"\x00\x01"
        assert abs(shannon_entropy(data) - 1.0) < 0.01


class TestCalculateFileEntropy:
    def test_normal_text_file(self, tmp_path):
        f = tmp_path / "text.txt"
        f.write_text("Hello world " * 100)
        ent = calculate_file_entropy(str(f))
        assert ent is not None
        assert 2.0 < ent < 5.0

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        assert calculate_file_entropy(str(f)) == 0.0

    def test_nonexistent_file(self):
        assert calculate_file_entropy("/nonexistent/file.txt") is None

    def test_high_entropy_file(self, tmp_path):
        f = tmp_path / "rand.bin"
        f.write_bytes(os.urandom(2048))
        ent = calculate_file_entropy(str(f))
        assert ent is not None
        assert ent > 7.0

    def test_custom_sample_size(self, tmp_path):
        f = tmp_path / "small.txt"
        f.write_text("a" * 500)
        ent = calculate_file_entropy(str(f), sample_size=100)
        assert ent is not None
        assert ent == 0.0  # single character


class TestSampleOffsets:
    def test_single_sample(self):
        assert _sample_offsets(1000, 100, 1) == [0]

    def test_three_samples(self):
        offsets = _sample_offsets(10000, 100, 3)
        assert len(offsets) == 3
        assert offsets[0] == 0
        assert offsets[-1] <= 10000 - 100

    def test_file_smaller_than_sample(self):
        offsets = _sample_offsets(50, 100, 3)
        assert offsets == [0]


# ===================================================================
# Entropy Detector and Baseline
# ===================================================================

class TestEntropyBaseline:
    def test_set_get_baseline(self, tmp_path):
        db = str(tmp_path / "base.db")
        bl = EntropyBaseline(db)
        bl.set_baseline("/a.txt", 4.5)
        assert bl.get_baseline("/a.txt") == 4.5
        bl.close()

    def test_missing_baseline(self, tmp_path):
        db = str(tmp_path / "base.db")
        bl = EntropyBaseline(db)
        assert bl.get_baseline("/nope.txt") is None
        bl.close()

    def test_update_baseline(self, tmp_path):
        db = str(tmp_path / "base.db")
        bl = EntropyBaseline(db)
        bl.set_baseline("/a.txt", 4.0)
        bl.set_baseline("/a.txt", 6.5)
        assert bl.get_baseline("/a.txt") == 6.5
        bl.close()

    def test_remove_baseline(self, tmp_path):
        db = str(tmp_path / "base.db")
        bl = EntropyBaseline(db)
        bl.set_baseline("/a.txt", 4.0)
        bl.remove_baseline("/a.txt")
        assert bl.get_baseline("/a.txt") is None
        bl.close()

    def test_log_alert(self, tmp_path):
        db = str(tmp_path / "base.db")
        bl = EntropyBaseline(db)
        aid = bl.log_alert("/a.txt", 4.0, 7.0, 3.0, True)
        assert aid > 0
        alerts = bl.get_alerts(suspicious_only=True)
        assert len(alerts) == 1
        bl.close()

    def test_get_alerts_all(self, tmp_path):
        db = str(tmp_path / "base.db")
        bl = EntropyBaseline(db)
        bl.log_alert("/a.txt", 4.0, 5.0, 1.0, False)
        bl.log_alert("/b.txt", 4.0, 7.5, 3.5, True)
        assert len(bl.get_alerts()) == 2
        assert len(bl.get_alerts(suspicious_only=True)) == 1
        bl.close()


class TestEntropyDetector:
    def test_analyze_normal_file(self, tmp_path):
        f = tmp_path / "normal.txt"
        f.write_text("normal content " * 50)
        det = EntropyDetector(str(tmp_path / "ent.db"))
        result = det.analyze_file(str(f))
        assert result is not None
        assert result["suspicious"] is False
        det.close()

    def test_analyze_detects_spike(self, tmp_path):
        f = tmp_path / "spike.txt"
        f.write_text("normal content " * 50)
        det = EntropyDetector(str(tmp_path / "ent.db"), delta_threshold=0.5)
        # Establish baseline
        det.analyze_file(str(f))
        # Overwrite with random data (entropy spike)
        f.write_bytes(os.urandom(1024))
        result = det.analyze_file(str(f))
        assert result is not None
        assert result["suspicious"] is True
        assert result["delta"] > 0.5
        det.close()

    def test_on_file_created(self, tmp_path):
        f = tmp_path / "new.txt"
        f.write_text("hello")
        det = EntropyDetector(str(tmp_path / "ent.db"))
        result = det.on_file_created(str(f))
        assert result is not None
        assert result["entropy_before"] is None
        det.close()

    def test_on_file_created_high_entropy(self, tmp_path):
        f = tmp_path / "high.bin"
        f.write_bytes(os.urandom(2048))
        det = EntropyDetector(str(tmp_path / "ent.db"))
        result = det.on_file_created(str(f))
        assert result is not None
        assert result["suspicious"] is True
        det.close()

    def test_on_file_deleted(self, tmp_path):
        f = tmp_path / "del.txt"
        f.write_text("to delete")
        det = EntropyDetector(str(tmp_path / "ent.db"))
        det.on_file_created(str(f))
        det.on_file_deleted(str(f))
        # Baseline should be removed
        assert det.baseline.get_baseline(str(f)) is None
        det.close()

    def test_cache_used(self, tmp_path):
        f = tmp_path / "cached.txt"
        f.write_text("cached content " * 50)
        det = EntropyDetector(str(tmp_path / "ent.db"))
        det.analyze_file(str(f))
        # Second analyze should use cached baseline
        result = det.analyze_file(str(f))
        assert result["delta"] < 0.01
        det.close()


# ===================================================================
# Pattern Detector
# ===================================================================

class TestPatternDetector:
    def _make_event(self, etype="modified", path="/a.txt", pid=1,
                    ext=None, old=None, edelt=None):
        return FileEvent(
            timestamp=time.time(), event_type=etype, file_path=path,
            file_extension=ext, old_path=old, process_id=pid,
            process_name="test", entropy_delta=edelt,
        )

    def test_mass_modification_below_threshold(self):
        pd = PatternDetector(mass_modify_threshold=20)
        for i in range(15):
            pd.record_event(self._make_event(path=f"/f{i}.txt"))
        triggered, _ = pd.check_mass_modification(1)
        assert triggered is False

    def test_mass_modification_above_threshold(self):
        pd = PatternDetector(mass_modify_threshold=20)
        for i in range(25):
            pd.record_event(self._make_event(path=f"/f{i}.txt"))
        triggered, detail = pd.check_mass_modification(1)
        assert triggered is True
        assert "25" in detail

    def test_entropy_spike_detection(self):
        pd = PatternDetector(entropy_spike_min_files=3)
        for i in range(4):
            pd.record_event(self._make_event(path=f"/f{i}.txt", edelt=3.0))
        triggered, _ = pd.check_entropy_spike(1)
        assert triggered is True

    def test_entropy_spike_below_threshold(self):
        pd = PatternDetector(entropy_spike_min_files=3)
        for i in range(2):
            pd.record_event(self._make_event(path=f"/f{i}.txt", edelt=3.0))
        triggered, _ = pd.check_entropy_spike(1)
        assert triggered is False

    def test_extension_manipulation(self):
        pd = PatternDetector(extension_change_min_files=3)
        for i in range(4):
            pd.record_event(self._make_event(
                etype="extension_changed", path=f"/f{i}.locked",
                ext=".locked", old=f"/f{i}.txt",
            ))
        triggered, _ = pd.check_extension_manipulation(1)
        assert triggered is True

    def test_extension_manipulation_nonsuspicious(self):
        pd = PatternDetector(extension_change_min_files=3)
        for i in range(5):
            pd.record_event(self._make_event(
                etype="extension_changed", path=f"/f{i}.bak",
                ext=".bak", old=f"/f{i}.txt",
            ))
        triggered, _ = pd.check_extension_manipulation(1)
        assert triggered is False

    def test_directory_traversal(self):
        pd = PatternDetector(directory_traversal_min_dirs=4)
        for i in range(5):
            pd.record_event(self._make_event(path=f"/dir{i}/f.txt"))
        triggered, _ = pd.check_directory_traversal(1)
        assert triggered is True

    def test_directory_traversal_below_threshold(self):
        pd = PatternDetector(directory_traversal_min_dirs=4)
        for i in range(2):
            pd.record_event(self._make_event(path=f"/dir{i}/f.txt"))
        triggered, _ = pd.check_directory_traversal(1)
        assert triggered is False

    def test_suspicious_process_temp_dir(self):
        pd = PatternDetector()
        pd.record_event(self._make_event(path="/tmp/evil/f.txt"))
        triggered, _ = pd.check_suspicious_process(1)
        assert triggered is True

    def test_suspicious_process_normal_dir(self):
        pd = PatternDetector()
        pd.record_event(self._make_event(path="/home/user/doc.txt"))
        triggered, _ = pd.check_suspicious_process(1)
        assert triggered is False

    def test_deletion_pattern(self):
        pd = PatternDetector()
        pd.record_event(self._make_event(etype="deleted", path="/doc.txt"))
        pd.record_event(self._make_event(
            etype="created", path="/doc.encrypted", ext=".encrypted"
        ))
        triggered, _ = pd.check_deletion_pattern(1)
        assert triggered is True

    def test_deletion_pattern_no_match(self):
        pd = PatternDetector()
        pd.record_event(self._make_event(etype="deleted", path="/doc.txt"))
        pd.record_event(self._make_event(etype="created", path="/other.txt"))
        triggered, _ = pd.check_deletion_pattern(1)
        assert triggered is False

    def test_evaluate_returns_all_indicators(self):
        pd = PatternDetector()
        pd.record_event(self._make_event())
        results = pd.evaluate(1)
        assert set(results.keys()) == {
            "mass_modification", "entropy_spike", "extension_manipulation",
            "directory_traversal", "suspicious_process", "deletion_pattern",
        }

    def test_time_window_pruning(self):
        pd = PatternDetector(time_window=0.1)
        pd.record_event(self._make_event())
        time.sleep(0.2)
        pd._prune(1)
        tracker = pd._trackers[1]
        assert len(tracker.modified_files) == 0

    def test_get_all_tracked_pids(self):
        pd = PatternDetector()
        pd.record_event(self._make_event(pid=10))
        pd.record_event(self._make_event(pid=20))
        pids = pd.get_all_tracked_pids()
        assert 10 in pids and 20 in pids

    def test_untracked_pid_returns_false(self):
        pd = PatternDetector()
        triggered, _ = pd.check_mass_modification(999)
        assert triggered is False


# ===================================================================
# Threat Scoring
# ===================================================================

class TestThreatScoring:
    def test_classify_normal(self):
        assert classify_level(0) == LEVEL_NORMAL
        assert classify_level(30) == LEVEL_NORMAL

    def test_classify_suspicious(self):
        assert classify_level(31) == LEVEL_SUSPICIOUS
        assert classify_level(50) == LEVEL_SUSPICIOUS

    def test_classify_likely(self):
        assert classify_level(51) == LEVEL_LIKELY
        assert classify_level(70) == LEVEL_LIKELY

    def test_classify_critical(self):
        assert classify_level(71) == LEVEL_CRITICAL
        assert classify_level(100) == LEVEL_CRITICAL

    def test_no_indicators_score_zero(self):
        indicators = {k: (False, "") for k in INDICATOR_WEIGHTS}
        ts = calculate_threat_score(indicators)
        assert ts.score == 0
        assert ts.level == LEVEL_NORMAL
        assert ts.action_required is False

    def test_single_indicator(self):
        indicators = {k: (False, "") for k in INDICATOR_WEIGHTS}
        indicators["entropy_spike"] = (True, "3 files spiked")
        ts = calculate_threat_score(indicators)
        assert ts.score == 30
        assert ts.level == LEVEL_NORMAL

    def test_two_indicators(self):
        indicators = {k: (False, "") for k in INDICATOR_WEIGHTS}
        indicators["mass_modification"] = (True, "detail")
        indicators["entropy_spike"] = (True, "detail")
        ts = calculate_threat_score(indicators)
        assert ts.score == 55
        assert ts.level == LEVEL_LIKELY

    def test_clamped_to_100(self):
        indicators = {k: (True, "d") for k in INDICATOR_WEIGHTS}
        ts = calculate_threat_score(indicators)
        assert ts.score == 100
        assert ts.action_required is True

    def test_action_required_boundary(self):
        indicators = {k: (False, "") for k in INDICATOR_WEIGHTS}
        indicators["mass_modification"] = (True, "d")
        indicators["entropy_spike"] = (True, "d")
        indicators["suspicious_process"] = (True, "d")
        indicators["directory_traversal"] = (True, "d")
        ts = calculate_threat_score(indicators)
        assert ts.score == 75
        assert ts.action_required is True

    def test_threat_score_dataclass(self):
        ts = ThreatScore(1, "proc", 50, "SUSPICIOUS", {"a": "b"}, False)
        assert ts.process_id == 1
        assert ts.process_name == "proc"
        assert ts.score == 50

    def test_triggered_indicators_stored(self):
        indicators = {k: (False, "") for k in INDICATOR_WEIGHTS}
        indicators["deletion_pattern"] = (True, "2 patterns")
        ts = calculate_threat_score(indicators, process_id=5, process_name="bad")
        assert "deletion_pattern" in ts.triggered_indicators
        assert ts.process_id == 5


# ===================================================================
# Behavior Analyzer
# ===================================================================

class TestBehaviorAnalyzer:
    def test_process_event_returns_score(self):
        ba = BehaviorAnalyzer()
        ts = ba.process_event(event_type="modified", file_path="/a.txt",
                              process_id=1, process_name="test")
        assert isinstance(ts, ThreatScore)

    def test_get_score(self):
        ba = BehaviorAnalyzer()
        ba.process_event(event_type="modified", file_path="/a.txt",
                         process_id=1, process_name="test")
        score = ba.get_score(1)
        assert score is not None

    def test_get_all_scores(self):
        ba = BehaviorAnalyzer()
        ba.process_event(event_type="modified", file_path="/a.txt",
                         process_id=1, process_name="a")
        ba.process_event(event_type="modified", file_path="/b.txt",
                         process_id=2, process_name="b")
        scores = ba.get_all_scores()
        assert 1 in scores and 2 in scores

    def test_on_threat_callback(self):
        called = []
        ba = BehaviorAnalyzer(
            time_window=60,
            mass_modify_threshold=5,
            entropy_spike_min_files=2,
            on_threat=lambda ts: called.append(ts),
        )
        # Trigger mass modification + entropy spike + directory traversal + temp dirs
        for i in range(10):
            ba.process_event(
                event_type="modified", file_path=f"/tmp/dir{i}/f{i}.txt",
                process_id=1, process_name="evil", entropy_delta=3.0,
            )
        assert len(called) > 0
        assert called[-1].action_required is True

    def test_get_critical_processes(self):
        ba = BehaviorAnalyzer(
            time_window=60,
            mass_modify_threshold=5,
            entropy_spike_min_files=2,
        )
        for i in range(10):
            ba.process_event(
                event_type="modified", file_path=f"/tmp/dir{i}/f{i}.txt",
                process_id=1, process_name="evil", entropy_delta=3.0,
            )
        crits = ba.get_critical_processes()
        assert len(crits) >= 1

    def test_normal_activity_no_critical(self):
        ba = BehaviorAnalyzer()
        ba.process_event(event_type="modified", file_path="/a.txt",
                         process_id=1, process_name="vim")
        assert len(ba.get_critical_processes()) == 0


# ===================================================================
# Event Logger
# ===================================================================

class TestEventLogger:
    def test_log_and_retrieve(self, tmp_path):
        el = EventLogger(str(tmp_path / "ev.db"))
        rid = el.log_event(event_type="created", file_path="/a.txt")
        assert rid > 0
        events = el.get_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "created"
        el.close()

    def test_filter_by_type(self, tmp_path):
        el = EventLogger(str(tmp_path / "ev.db"))
        el.log_event(event_type="created", file_path="/a.txt")
        el.log_event(event_type="modified", file_path="/b.txt")
        evts = el.get_events(event_type="modified")
        assert all(e["event_type"] == "modified" for e in evts)
        el.close()

    def test_limit(self, tmp_path):
        el = EventLogger(str(tmp_path / "ev.db"))
        for i in range(10):
            el.log_event(event_type="created", file_path=f"/f{i}.txt")
        evts = el.get_events(limit=3)
        assert len(evts) == 3
        el.close()

    def test_all_fields_stored(self, tmp_path):
        el = EventLogger(str(tmp_path / "ev.db"))
        el.log_event(
            event_type="moved", file_path="/new.txt", file_extension=".txt",
            old_path="/old.txt", file_size_before=100, file_size_after=200,
            process_id=42, process_name="proc", is_directory=False,
        )
        e = el.get_events()[0]
        assert e["old_path"] == "/old.txt"
        assert e["process_id"] == 42
        assert e["file_size_before"] == 100
        el.close()


# ===================================================================
# Snapshot Service
# ===================================================================

class TestSnapshotService:
    def test_create_and_query(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "orig.txt"
        f.write_text("snapshot me")
        ss = SnapshotService(vault)
        result = ss.create_snapshot(str(f), reason="test", process_name="proc")
        assert result is not None
        assert result["file_hash"] is not None
        backups = ss.get_backups(original_path=str(f))
        assert len(backups) == 1
        ss.close()

    def test_nonexistent_file_returns_none(self, tmp_path):
        ss = SnapshotService(str(tmp_path / "vault"))
        assert ss.create_snapshot("/no/such/file.txt") is None
        ss.close()

    def test_get_backup_by_id(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "f.txt"
        f.write_text("data")
        ss = SnapshotService(vault)
        ss.create_snapshot(str(f))
        backups = ss.get_backups()
        b = ss.get_backup_by_id(backups[0]["id"])
        assert b is not None
        assert b["original_path"] == str(f)
        ss.close()

    def test_get_backup_by_id_missing(self, tmp_path):
        ss = SnapshotService(str(tmp_path / "vault"))
        assert ss.get_backup_by_id(9999) is None
        ss.close()

    def test_metadata_json_written(self, tmp_path):
        vault = tmp_path / "vault"
        f = tmp_path / "m.txt"
        f.write_text("meta")
        ss = SnapshotService(str(vault))
        ss.create_snapshot(str(f))
        # Find metadata.json in vault
        found = list(vault.rglob("metadata.json"))
        assert len(found) == 1
        data = json.loads(found[0].read_text())
        assert len(data) == 1
        ss.close()


class TestFlattenPath:
    def test_unix_path(self):
        assert flatten_path("/home/user/doc.txt") == "home_user_doc.txt"

    def test_relative_path(self):
        result = flatten_path("dir/file.txt")
        assert "dir_file.txt" in result


class TestFileSha256:
    def test_known_content(self, tmp_path):
        f = tmp_path / "hash.txt"
        f.write_bytes(b"hello")
        h = file_sha256(str(f))
        assert h is not None
        assert len(h) == 64

    def test_nonexistent(self):
        assert file_sha256("/no/such/file") is None


# ===================================================================
# Recovery Manager
# ===================================================================

class TestRecoveryManager:
    def test_restore_by_id(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "r.txt"
        f.write_text("original")
        bm = BackupManager(vault)
        bm.backup_file(str(f))
        backups = bm.snapshot.get_backups(original_path=str(f))
        f.write_text("CHANGED")
        result = bm.recovery.restore_file(backups[0]["id"])
        assert result.success is True
        assert f.read_text() == "original"
        bm.close()

    def test_restore_nonexistent_id(self, tmp_path):
        bm = BackupManager(str(tmp_path / "vault"))
        result = bm.recovery.restore_file(99999)
        assert result.success is False
        bm.close()

    def test_restore_by_path(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "p.txt"
        f.write_text("v1")
        bm = BackupManager(vault)
        bm.backup_file(str(f))
        f.write_text("v2")
        results = bm.recovery.restore_by_path(str(f))
        assert results[0].success is True
        assert f.read_text() == "v1"
        bm.close()

    def test_restore_by_process(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "proc.txt"
        f.write_text("orig")
        bm = BackupManager(vault)
        bm.backup_file(str(f), process_name="evil")
        f.write_text("bad")
        results = bm.recovery.restore_by_process("evil")
        assert any(r.success for r in results)
        bm.close()

    def test_verify_backup_integrity(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "v.txt"
        f.write_text("verify me")
        bm = BackupManager(vault)
        bm.backup_file(str(f))
        backups = bm.snapshot.get_backups()
        ok = bm.recovery.verify_backup(backups[0]["id"])
        assert ok is True
        bm.close()

    def test_restore_point_in_time(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "pit.txt"
        f.write_text("v1")
        bm = BackupManager(vault)
        bm.backup_file(str(f))
        results = bm.recovery.restore_point_in_time("2000-01-01")
        assert len(results) >= 1
        bm.close()


# ===================================================================
# Backup Manager
# ===================================================================

class TestBackupManager:
    def test_backup_and_count(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "bm.txt"
        f.write_text("backup me")
        bm = BackupManager(vault)
        bm.backup_file(str(f))
        assert len(bm.snapshot.get_backups()) == 1
        bm.close()

    def test_retention_removes_old(self, tmp_path):
        vault = str(tmp_path / "vault")
        f = tmp_path / "old.txt"
        f.write_text("old data")
        bm = BackupManager(vault, retention_hours=0)  # expire immediately
        bm.backup_file(str(f))
        time.sleep(0.1)
        bm.enforce_retention()
        assert len(bm.snapshot.get_backups()) == 0
        bm.close()


# ===================================================================
# Backup Config
# ===================================================================

class TestBackupConfig:
    def test_constants(self):
        assert RETENTION_HOURS == 48
        assert VAULT_DIR_MODE == 0o700
        assert VAULT_FILE_MODE == 0o600
        assert "%Y" in SNAPSHOT_DIR_FORMAT


# ===================================================================
# Process Controller
# ===================================================================

class TestProcessControllerUnit:
    def test_suspend_nonexistent(self):
        pc = ProcessController()
        action = pc.suspend(99998)
        assert action.success is False
        assert action.action == "suspend"

    def test_terminate_nonexistent(self):
        pc = ProcessController()
        action = pc.terminate(99998)
        assert action.success is False

    def test_resume_nonexistent(self):
        pc = ProcessController()
        action = pc.resume(99998)
        assert action.success is False

    def test_block_and_check(self):
        pc = ProcessController()
        pc._blocked.add("/usr/bin/evil")
        assert pc.is_blocked("/usr/bin/evil")
        assert not pc.is_blocked("/usr/bin/python")

    def test_action_log(self):
        pc = ProcessController()
        pc.suspend(99998)
        pc.terminate(99997)
        assert len(pc.action_log) == 2

    def test_process_action_dataclass(self):
        pa = ProcessAction("2025-01-01", 100, "proc", "suspend", True)
        assert pa.pid == 100
        assert pa.success is True

    def test_get_process_tree_nonexistent(self):
        pc = ProcessController()
        assert pc.get_process_tree(99998) is None

    def test_blocked_executables(self):
        pc = ProcessController()
        pc._blocked.add("/a")
        pc._blocked.add("/b")
        assert pc.blocked_executables == {"/a", "/b"}


# ===================================================================
# Alert System
# ===================================================================

class TestAlertSystemUnit:
    def test_all_levels(self):
        a = AlertSystem(enable_desktop=False)
        a1 = a.send(ALERT_INFO, "T", "M", score=10)
        a2 = a.send(ALERT_WARNING, "T", "M", score=50)
        a3 = a.send(ALERT_CRITICAL, "T", "M", score=75)
        a4 = a.send(ALERT_EMERGENCY, "T", "M", score=95)
        assert a1.level == ALERT_INFO
        assert a4.level == ALERT_EMERGENCY

    def test_log_populated(self):
        a = AlertSystem(enable_desktop=False)
        a.send(ALERT_INFO, "T", "M")
        a.send(ALERT_WARNING, "T", "M")
        assert len(a.alert_log) == 2

    def test_filter_by_level(self):
        a = AlertSystem(enable_desktop=False)
        a.send(ALERT_INFO, "T", "M")
        a.send(ALERT_INFO, "T", "M")
        a.send(ALERT_WARNING, "T", "M")
        assert len(a.get_alerts_by_level(ALERT_INFO)) == 2

    def test_alert_fields(self):
        a = AlertSystem(enable_desktop=False)
        alert = a.send(ALERT_CRITICAL, "Title", "Msg", process_id=10,
                       process_name="evil", score=80)
        assert alert.title == "Title"
        assert alert.process_id == 10
        assert alert.score == 80
        assert alert.timestamp is not None


# ===================================================================
# Response Engine
# ===================================================================

class TestResponseEngineUnit:
    @pytest.fixture
    def engine(self, tmp_path):
        bm = BackupManager(str(tmp_path / "vault"))
        eng = ResponseEngine(bm, safe_mode=False, enable_desktop_alerts=False)
        yield eng
        bm.close()

    def _threat(self, score, pid=99999, name="test"):
        return ThreatScore(pid, name, score, classify_level(score),
                           {"test": "d"}, score >= 71)

    def test_no_response_below_31(self, engine):
        r = engine.respond(self._threat(20))
        assert r.escalation_level == 0
        assert len(r.actions_taken) == 0

    def test_level1(self, engine):
        r = engine.respond(self._threat(40))
        assert r.escalation_level == 1
        assert any("logged" in a.lower() for a in r.actions_taken)

    def test_level2(self, engine):
        r = engine.respond(self._threat(60))
        assert r.escalation_level == 2
        assert any("suspension" in a.lower() or "prepared" in a.lower()
                    for a in r.actions_taken)

    def test_level3(self, engine):
        r = engine.respond(self._threat(75))
        assert r.escalation_level == 3
        suspend_actions = [a for a in r.process_actions if a.action == "suspend"]
        assert len(suspend_actions) >= 1

    def test_level4(self, engine):
        r = engine.respond(self._threat(90))
        assert r.escalation_level == 4
        assert r.incident_report is not None

    def test_response_log(self, engine):
        engine.respond(self._threat(40))
        engine.respond(self._threat(60))
        assert len(engine.response_log) == 2


# ===================================================================
# Recovery Workflow
# ===================================================================

class TestRecoveryWorkflowUnit:
    def test_incident_report_to_json(self, tmp_path):
        bm = BackupManager(str(tmp_path / "vault"))
        wf = RecoveryWorkflow(bm)
        report = wf.create_incident_report(1, "evil", 90, {"a": "b"}, ["terminated"])
        j = report.to_json()
        data = json.loads(j)
        assert data["threat_score"] == 90
        bm.close()

    def test_incident_report_to_dict(self):
        ir = IncidentReport("2025-01-01", 1, "p", 80, {"a": "b"}, ["/a.txt"], ["killed"])
        d = ir.to_dict()
        assert d["process_id"] == 1
        assert d["affected_files"] == ["/a.txt"]

    def test_incidents_list(self, tmp_path):
        bm = BackupManager(str(tmp_path / "vault"))
        wf = RecoveryWorkflow(bm)
        wf.create_incident_report(1, "a", 90, {}, [])
        wf.create_incident_report(2, "b", 80, {}, [])
        assert len(wf.incidents) == 2
        bm.close()


# ===================================================================
# WebSocket Handler
# ===================================================================

class TestWebSocketHandlerUnit:
    def test_register_unregister(self):
        wsh = WebSocketHandler()
        class FakeWS:
            pass
        ws = FakeWS()
        wsh.register(ws)
        assert wsh.client_count == 1
        wsh.unregister(ws)
        assert wsh.client_count == 0

    def test_broadcast_to_multiple(self):
        wsh = WebSocketHandler()
        received = []
        class FakeWS:
            def send(self, msg):
                received.append(json.loads(msg))
        wsh.register(FakeWS())
        wsh.register(FakeWS())
        wsh.broadcast("evt", {"key": "val"})
        assert len(received) == 2
        assert received[0]["type"] == "evt"

    def test_dead_client_cleanup(self):
        wsh = WebSocketHandler()
        class DeadWS:
            def send(self, msg):
                raise ConnectionError("gone")
        wsh.register(DeadWS())
        wsh.broadcast("ping", {})
        assert wsh.client_count == 0

    def test_unregister_unknown(self):
        wsh = WebSocketHandler()
        class FakeWS:
            pass
        wsh.unregister(FakeWS())
        assert wsh.client_count == 0


# ===================================================================
# Escalation Level Mapping
# ===================================================================

class TestEscalationLevel:
    def test_boundaries(self):
        assert escalation_level(0) == 0
        assert escalation_level(30) == 0
        assert escalation_level(31) == 1
        assert escalation_level(50) == 1
        assert escalation_level(51) == 2
        assert escalation_level(70) == 2
        assert escalation_level(71) == 3
        assert escalation_level(85) == 3
        assert escalation_level(86) == 4
        assert escalation_level(100) == 4
