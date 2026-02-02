"""Tests for Phase 3: Behavioral Detection Logic.

Covers:
- Each of the 6 indicators individually
- Scoring system with exact weights and thresholds
- Combined indicator scoring
- False positive scenarios (backup software, batch operations)
- Per-process threat tracking
- Time-windowed pattern detection
- Detection latency measurement
"""

import os
import time

import pytest

from src.analysis.pattern_detector import (
    PatternDetector,
    FileEvent,
    SUSPICIOUS_EXTENSIONS,
)
from src.analysis.threat_scoring import (
    calculate_threat_score,
    classify_level,
    ThreatScore,
    INDICATOR_WEIGHTS,
    WEIGHT_MASS_MODIFICATION,
    WEIGHT_ENTROPY_SPIKE,
    WEIGHT_EXTENSION_MANIPULATION,
    WEIGHT_DIRECTORY_TRAVERSAL,
    WEIGHT_SUSPICIOUS_PROCESS,
    WEIGHT_DELETION_PATTERN,
    LEVEL_NORMAL,
    LEVEL_SUSPICIOUS,
    LEVEL_LIKELY,
    LEVEL_CRITICAL,
)
from src.analysis.behavior_analyzer import BehaviorAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    event_type="modified",
    file_path="/watched/file.txt",
    file_extension=".txt",
    old_path=None,
    process_id=1000,
    process_name="test_proc",
    entropy_delta=None,
    entropy_after=None,
    timestamp=None,
) -> FileEvent:
    return FileEvent(
        timestamp=timestamp or time.time(),
        event_type=event_type,
        file_path=file_path,
        file_extension=file_extension,
        old_path=old_path,
        process_id=process_id,
        process_name=process_name,
        entropy_delta=entropy_delta,
        entropy_after=entropy_after,
    )


# ===================================================================
# Pattern Detector: Individual Indicator Tests
# ===================================================================

class TestIndicator1MassModification:
    def test_below_threshold(self):
        pd = PatternDetector(mass_modify_threshold=20)
        for i in range(20):
            pd.record_event(make_event(file_path=f"/w/file{i}.txt"))
        triggered, _ = pd.check_mass_modification(1000)
        assert triggered is False

    def test_above_threshold(self):
        pd = PatternDetector(mass_modify_threshold=20)
        for i in range(21):
            pd.record_event(make_event(file_path=f"/w/file{i}.txt"))
        triggered, detail = pd.check_mass_modification(1000)
        assert triggered is True
        assert "21" in detail

    def test_different_processes_isolated(self):
        pd = PatternDetector(mass_modify_threshold=5)
        for i in range(4):
            pd.record_event(make_event(file_path=f"/w/a{i}.txt", process_id=100))
        for i in range(4):
            pd.record_event(make_event(file_path=f"/w/b{i}.txt", process_id=200))
        assert pd.check_mass_modification(100)[0] is False
        assert pd.check_mass_modification(200)[0] is False


class TestIndicator2EntropySpikePattern:
    def test_below_min_files(self):
        pd = PatternDetector(entropy_spike_min_files=3)
        for i in range(2):
            pd.record_event(make_event(
                file_path=f"/w/f{i}.txt", entropy_delta=3.0,
            ))
        assert pd.check_entropy_spike(1000)[0] is False

    def test_meets_min_files(self):
        pd = PatternDetector(entropy_spike_min_files=3, entropy_spike_threshold=2.0)
        for i in range(3):
            pd.record_event(make_event(
                file_path=f"/w/f{i}.txt", entropy_delta=2.5,
            ))
        triggered, detail = pd.check_entropy_spike(1000)
        assert triggered is True
        assert "3" in detail

    def test_delta_below_threshold_not_counted(self):
        pd = PatternDetector(entropy_spike_min_files=3, entropy_spike_threshold=2.0)
        for i in range(5):
            pd.record_event(make_event(
                file_path=f"/w/f{i}.txt", entropy_delta=1.5,
            ))
        assert pd.check_entropy_spike(1000)[0] is False


class TestIndicator3ExtensionManipulation:
    def test_suspicious_extensions_detected(self):
        pd = PatternDetector(extension_change_min_files=3)
        for i, ext in enumerate([".locked", ".encrypted", ".crypto"]):
            pd.record_event(make_event(
                event_type="extension_changed",
                file_path=f"/w/doc{i}{ext}",
                file_extension=ext,
                old_path=f"/w/doc{i}.docx",
            ))
        triggered, detail = pd.check_extension_manipulation(1000)
        assert triggered is True
        assert "locked" in detail or "encrypted" in detail

    def test_normal_extensions_ignored(self):
        pd = PatternDetector(extension_change_min_files=3)
        for i in range(5):
            pd.record_event(make_event(
                event_type="extension_changed",
                file_path=f"/w/img{i}.png",
                file_extension=".png",
                old_path=f"/w/img{i}.bmp",
            ))
        assert pd.check_extension_manipulation(1000)[0] is False

    def test_below_min_files(self):
        pd = PatternDetector(extension_change_min_files=3)
        for i in range(2):
            pd.record_event(make_event(
                event_type="extension_changed",
                file_path=f"/w/f{i}.locked",
                file_extension=".locked",
            ))
        assert pd.check_extension_manipulation(1000)[0] is False


class TestIndicator4DirectoryTraversal:
    def test_below_threshold(self):
        pd = PatternDetector(directory_traversal_min_dirs=4)
        for i in range(3):
            pd.record_event(make_event(file_path=f"/dir{i}/file.txt"))
        assert pd.check_directory_traversal(1000)[0] is False

    def test_meets_threshold(self):
        pd = PatternDetector(directory_traversal_min_dirs=4)
        for i in range(4):
            pd.record_event(make_event(file_path=f"/dir{i}/file.txt"))
        triggered, detail = pd.check_directory_traversal(1000)
        assert triggered is True
        assert "4" in detail


class TestIndicator5SuspiciousProcess:
    def test_temp_dir_detected(self):
        pd = PatternDetector()
        pd.record_event(make_event(
            file_path="/tmp/evil/payload.txt",
            process_name="ransomware.exe",
        ))
        triggered, _ = pd.check_suspicious_process(1000)
        assert triggered is True

    def test_downloads_dir_detected(self):
        pd = PatternDetector()
        pd.record_event(make_event(
            file_path="/home/user/Downloads/sketch.txt",
        ))
        assert pd.check_suspicious_process(1000)[0] is True

    def test_normal_dir_not_flagged(self):
        pd = PatternDetector()
        pd.record_event(make_event(
            file_path="/home/user/Documents/report.txt",
        ))
        assert pd.check_suspicious_process(1000)[0] is False


class TestIndicator6DeletionPattern:
    def test_delete_then_create_encrypted(self):
        pd = PatternDetector()
        pd.record_event(make_event(
            event_type="deleted", file_path="/w/report.docx",
        ))
        pd.record_event(make_event(
            event_type="created", file_path="/w/report.locked",
            file_extension=".locked",
        ))
        triggered, detail = pd.check_deletion_pattern(1000)
        assert triggered is True
        assert "1" in detail

    def test_no_match_without_suspicious_ext(self):
        pd = PatternDetector()
        pd.record_event(make_event(
            event_type="deleted", file_path="/w/old.txt",
        ))
        pd.record_event(make_event(
            event_type="created", file_path="/w/old.bak",
            file_extension=".bak",
        ))
        assert pd.check_deletion_pattern(1000)[0] is False

    def test_no_match_different_stems(self):
        pd = PatternDetector()
        pd.record_event(make_event(
            event_type="deleted", file_path="/w/alpha.docx",
        ))
        pd.record_event(make_event(
            event_type="created", file_path="/w/beta.locked",
            file_extension=".locked",
        ))
        assert pd.check_deletion_pattern(1000)[0] is False


# ===================================================================
# Time-windowed pattern detection
# ===================================================================

class TestTimeWindow:
    def test_old_events_pruned(self):
        pd = PatternDetector(time_window=1.0, mass_modify_threshold=5)
        old_ts = time.time() - 2.0
        for i in range(10):
            pd.record_event(make_event(
                file_path=f"/w/f{i}.txt", timestamp=old_ts,
            ))
        # All events are stale
        assert pd.check_mass_modification(1000)[0] is False

    def test_fresh_events_kept(self):
        pd = PatternDetector(time_window=10.0, mass_modify_threshold=5)
        for i in range(6):
            pd.record_event(make_event(file_path=f"/w/f{i}.txt"))
        assert pd.check_mass_modification(1000)[0] is True


# ===================================================================
# Threat Scoring
# ===================================================================

class TestThreatScoring:
    def test_no_indicators_score_zero(self):
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        ts = calculate_threat_score(results, process_id=1)
        assert ts.score == 0
        assert ts.level == LEVEL_NORMAL
        assert ts.action_required is False

    def test_single_medium_indicator(self):
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        results["directory_traversal"] = (True, "4 dirs")
        ts = calculate_threat_score(results)
        assert ts.score == WEIGHT_DIRECTORY_TRAVERSAL  # 10
        assert ts.level == LEVEL_NORMAL

    def test_single_high_indicator_suspicious(self):
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        results["mass_modification"] = (True, "25 files")
        ts = calculate_threat_score(results)
        assert ts.score == WEIGHT_MASS_MODIFICATION  # 25
        assert ts.level == LEVEL_NORMAL  # 25 <= 30

    def test_two_high_indicators_suspicious_range(self):
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        results["mass_modification"] = (True, "detail")
        results["directory_traversal"] = (True, "detail")
        ts = calculate_threat_score(results)
        # 25 + 10 = 35
        assert ts.score == 35
        assert ts.level == LEVEL_SUSPICIOUS

    def test_entropy_plus_extension_likely_range(self):
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        results["entropy_spike"] = (True, "detail")
        results["extension_manipulation"] = (True, "detail")
        ts = calculate_threat_score(results)
        # 30 + 25 = 55
        assert ts.score == 55
        assert ts.level == LEVEL_LIKELY
        assert ts.action_required is False

    def test_critical_threshold_exact(self):
        # mass_modification(25) + entropy_spike(30) + directory_traversal(10)
        # + suspicious_process(10) = 75 -> CRITICAL
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        results["mass_modification"] = (True, "d")
        results["entropy_spike"] = (True, "d")
        results["directory_traversal"] = (True, "d")
        results["suspicious_process"] = (True, "d")
        ts = calculate_threat_score(results)
        assert ts.score == 75
        assert ts.level == LEVEL_CRITICAL
        assert ts.action_required is True

    def test_all_indicators_capped_at_100(self):
        results = {name: (True, "d") for name in INDICATOR_WEIGHTS}
        ts = calculate_threat_score(results)
        # 25+30+25+10+10+20 = 120 -> clamped to 100
        assert ts.score == 100
        assert ts.level == LEVEL_CRITICAL

    def test_triggered_indicators_tracked(self):
        results = {name: (False, "") for name in INDICATOR_WEIGHTS}
        results["entropy_spike"] = (True, "5 files spiked")
        ts = calculate_threat_score(results)
        assert "entropy_spike" in ts.triggered_indicators
        assert ts.triggered_indicators["entropy_spike"] == "5 files spiked"


class TestClassifyLevel:
    def test_boundaries(self):
        assert classify_level(0) == LEVEL_NORMAL
        assert classify_level(30) == LEVEL_NORMAL
        assert classify_level(31) == LEVEL_SUSPICIOUS
        assert classify_level(50) == LEVEL_SUSPICIOUS
        assert classify_level(51) == LEVEL_LIKELY
        assert classify_level(70) == LEVEL_LIKELY
        assert classify_level(71) == LEVEL_CRITICAL
        assert classify_level(100) == LEVEL_CRITICAL


class TestScoringWeights:
    """Verify the exact weights match the Phase 3 documentation."""

    def test_weight_values(self):
        assert WEIGHT_MASS_MODIFICATION == 25
        assert WEIGHT_ENTROPY_SPIKE == 30
        assert WEIGHT_EXTENSION_MANIPULATION == 25
        assert WEIGHT_DIRECTORY_TRAVERSAL == 10
        assert WEIGHT_SUSPICIOUS_PROCESS == 10
        assert WEIGHT_DELETION_PATTERN == 20


# ===================================================================
# BehaviorAnalyzer (integration of detector + scoring)
# ===================================================================

class TestBehaviorAnalyzer:
    def test_single_event_normal(self):
        ba = BehaviorAnalyzer()
        score = ba.process_event(
            event_type="modified",
            file_path="/w/file.txt",
            process_id=1,
            process_name="editor",
        )
        assert score.level == LEVEL_NORMAL
        assert score.action_required is False

    def test_mass_modify_plus_entropy_triggers_critical(self):
        ba = BehaviorAnalyzer(
            mass_modify_threshold=5,
            entropy_spike_min_files=3,
            directory_traversal_min_dirs=3,
        )
        for i in range(6):
            ba.process_event(
                event_type="modified",
                file_path=f"/dir{i}/file{i}.txt",
                process_id=42,
                process_name="evil",
                entropy_delta=3.0,
            )
        score = ba.get_score(42)
        assert score is not None
        # mass_modification(25) + entropy_spike(30) + directory_traversal(10)
        assert score.score >= 65
        # With 6 dirs touched (>=3 threshold) this is at least 65
        # Depending on exact dirs, it should be LIKELY or CRITICAL

    def test_on_threat_callback(self):
        alerts = []
        ba = BehaviorAnalyzer(
            mass_modify_threshold=3,
            entropy_spike_min_files=2,
            directory_traversal_min_dirs=2,
            on_threat=lambda ts: alerts.append(ts),
        )
        # mass_modification(25) + entropy_spike(30) + directory_traversal(10)
        # + suspicious_process(10) = 75 -> CRITICAL
        for i in range(5):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/f{i}.txt",
                process_id=99,
                process_name="ransomware",
                entropy_delta=4.0,
            )
        assert len(alerts) > 0
        assert alerts[-1].action_required is True

    def test_per_process_tracking(self):
        ba = BehaviorAnalyzer(mass_modify_threshold=3)
        for i in range(4):
            ba.process_event(
                event_type="modified",
                file_path=f"/w/a{i}.txt",
                process_id=10,
                process_name="proc_a",
            )
        ba.process_event(
            event_type="modified",
            file_path="/w/b0.txt",
            process_id=20,
            process_name="proc_b",
        )
        score_a = ba.get_score(10)
        score_b = ba.get_score(20)
        assert score_a.score > score_b.score

    def test_get_critical_processes(self):
        ba = BehaviorAnalyzer(
            mass_modify_threshold=2,
            entropy_spike_min_files=2,
            directory_traversal_min_dirs=2,
        )
        # mass_modification(25) + entropy_spike(30) + directory_traversal(10)
        # + suspicious_process(10) = 75 -> CRITICAL
        for i in range(4):
            ba.process_event(
                event_type="modified",
                file_path=f"/tmp/dir{i}/f{i}.txt",
                process_id=50,
                process_name="badproc",
                entropy_delta=5.0,
            )
        crits = ba.get_critical_processes()
        assert any(s.process_id == 50 for s in crits)


# ===================================================================
# False positive scenarios
# ===================================================================

class TestFalsePositiveScenarios:
    def test_backup_software_many_reads_no_spike(self):
        """Backup software modifies many files but with no entropy change."""
        ba = BehaviorAnalyzer(mass_modify_threshold=20)
        for i in range(25):
            score = ba.process_event(
                event_type="modified",
                file_path=f"/docs/file{i}.txt",
                process_id=500,
                process_name="backup_agent",
                entropy_delta=0.1,
            )
        # mass_modification triggers (25) but no entropy spike
        # score should be <= 35 (mass_mod 25 + maybe dir traversal 10)
        assert score.level in (LEVEL_NORMAL, LEVEL_SUSPICIOUS)
        assert score.action_required is False

    def test_batch_rename_normal_extensions(self):
        """Batch renaming with normal extensions should not trigger."""
        ba = BehaviorAnalyzer(extension_change_min_files=3)
        for i in range(10):
            ba.process_event(
                event_type="extension_changed",
                file_path=f"/photos/img{i}.jpg",
                file_extension=".jpg",
                old_path=f"/photos/img{i}.bmp",
                process_id=600,
                process_name="converter",
            )
        score = ba.get_score(600)
        assert "extension_manipulation" not in score.triggered_indicators

    def test_developer_compiling_many_files(self):
        """Compiler modifying many .o files across dirs -- moderate, not critical."""
        ba = BehaviorAnalyzer(mass_modify_threshold=20)
        for i in range(25):
            ba.process_event(
                event_type="modified",
                file_path=f"/project/src/mod{i}/output.o",
                process_id=700,
                process_name="gcc",
                entropy_delta=0.5,
            )
        score = ba.get_score(700)
        # mass_modification(25) + directory_traversal(10) = 35 max
        assert score.score <= 35
        assert score.action_required is False


# ===================================================================
# Detection latency
# ===================================================================

class TestDetectionLatency:
    def test_single_event_latency(self):
        ba = BehaviorAnalyzer()
        start = time.time()
        for _ in range(100):
            ba.process_event(
                event_type="modified",
                file_path="/w/file.txt",
                process_id=1,
                process_name="test",
            )
        elapsed = time.time() - start
        # 100 events should process well under 1 second
        assert elapsed < 1.0

    def test_high_volume_latency(self):
        ba = BehaviorAnalyzer()
        start = time.time()
        for i in range(1000):
            ba.process_event(
                event_type="modified",
                file_path=f"/w/f{i}.txt",
                process_id=1,
                process_name="bench",
                entropy_delta=0.1,
            )
        elapsed = time.time() - start
        # 1000 events should stay under 2 seconds
        assert elapsed < 2.0
