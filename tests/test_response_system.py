"""Tests for Phase 5: Automated Response System.

Covers (from docs testing section):
- Test each escalation level (Levels 1-4)
- Verify process suspension works
- Test rollback on simulated encryption
- User experience testing (alert clarity)
- Safe mode: user confirmation before auto-actions
- Recovery workflow
- Incident report generation
"""

import os

import pytest

from src.analysis.threat_scoring import ThreatScore
from src.response.backup_manager import BackupManager
from src.response.process_controller import ProcessController
from src.response.alert_system import (
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
    LEVEL1_MIN, LEVEL1_MAX,
    LEVEL2_MIN, LEVEL2_MAX,
    LEVEL3_MIN, LEVEL3_MAX,
    LEVEL4_MIN, LEVEL4_MAX,
)
from src.response.recovery_workflow import RecoveryWorkflow, IncidentReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_threat(score, pid=1000, name="test_proc", indicators=None):
    return ThreatScore(
        process_id=pid,
        process_name=name,
        score=score,
        level="TEST",
        triggered_indicators=indicators or {"test": "detail"},
        action_required=score >= 71,
    )


@pytest.fixture
def vault(tmp_path):
    return str(tmp_path / "vault")


@pytest.fixture
def source_dir(tmp_path):
    d = tmp_path / "source"
    d.mkdir()
    return d


@pytest.fixture
def backup_mgr(vault):
    mgr = BackupManager(vault_path=vault)
    yield mgr
    mgr.close()


@pytest.fixture
def engine(backup_mgr):
    return ResponseEngine(
        backup_manager=backup_mgr,
        safe_mode=False,
        enable_desktop_alerts=False,
    )


@pytest.fixture
def safe_engine(backup_mgr):
    return ResponseEngine(
        backup_manager=backup_mgr,
        safe_mode=True,
        enable_desktop_alerts=False,
    )


# ---------------------------------------------------------------------------
# Escalation level mapping
# ---------------------------------------------------------------------------

class TestEscalationLevelMapping:
    def test_score_0_no_escalation(self):
        assert escalation_level(0) == 0
        assert escalation_level(30) == 0

    def test_level1_range(self):
        assert escalation_level(31) == 1
        assert escalation_level(50) == 1

    def test_level2_range(self):
        assert escalation_level(51) == 2
        assert escalation_level(70) == 2

    def test_level3_range(self):
        assert escalation_level(71) == 3
        assert escalation_level(85) == 3

    def test_level4_range(self):
        assert escalation_level(86) == 4
        assert escalation_level(100) == 4


# ---------------------------------------------------------------------------
# Level 1: Monitor (31-50)
# ---------------------------------------------------------------------------

class TestLevel1Monitor:
    def test_logs_detailed_activity(self, engine):
        result = engine.respond(make_threat(40))
        assert result.escalation_level == 1
        assert any("logged" in a.lower() for a in result.actions_taken)

    def test_increases_monitoring(self, engine):
        result = engine.respond(make_threat(35))
        assert any("monitoring" in a.lower() for a in result.actions_taken)

    def test_sends_non_intrusive_alert(self, engine):
        result = engine.respond(make_threat(45))
        assert len(result.alerts_sent) >= 1
        assert result.alerts_sent[0].level == ALERT_INFO

    def test_no_process_actions(self, engine):
        result = engine.respond(make_threat(40))
        assert len(result.process_actions) == 0


# ---------------------------------------------------------------------------
# Level 2: Warn (51-70)
# ---------------------------------------------------------------------------

class TestLevel2Warn:
    def test_creates_backup_snapshots(self, engine, source_dir):
        f = source_dir / "warn.txt"
        f.write_text("backup me")
        result = engine.respond(make_threat(60), affected_files=[str(f)])
        assert result.escalation_level == 2
        assert any("backup" in a.lower() for a in result.actions_taken)

    def test_sends_prominent_warning(self, engine):
        result = engine.respond(make_threat(55))
        warnings = [a for a in result.alerts_sent if a.level == ALERT_WARNING]
        assert len(warnings) >= 1

    def test_prepares_for_suspension(self, engine):
        result = engine.respond(make_threat(65))
        assert any("prepared" in a.lower() or "suspension" in a.lower()
                    for a in result.actions_taken)

    def test_logs_process_tree(self, engine):
        # Use our own PID so the process exists
        threat = make_threat(60, pid=os.getpid(), name="pytest")
        result = engine.respond(threat)
        assert any("process tree" in a.lower() for a in result.actions_taken)

    def test_no_process_suspension(self, engine):
        result = engine.respond(make_threat(60))
        # No suspend/terminate actions at Level 2
        assert all(a.action not in ("suspend", "terminate")
                    for a in result.process_actions)


# ---------------------------------------------------------------------------
# Level 3: Quarantine (71-85)
# ---------------------------------------------------------------------------

class TestLevel3Quarantine:
    def test_suspends_process(self, engine):
        # Use a non-existent PID to avoid suspending the test runner.
        # Verify the suspend action is attempted and recorded.
        result = engine.respond(make_threat(75, pid=99998, name="fake"))
        assert result.escalation_level == 3
        suspend_actions = [a for a in result.process_actions if a.action == "suspend"]
        assert len(suspend_actions) >= 1

    def test_creates_emergency_backups(self, engine, source_dir):
        f = source_dir / "emergency.txt"
        f.write_text("save me")
        result = engine.respond(make_threat(80), affected_files=[str(f)])
        assert any("emergency" in a.lower() for a in result.actions_taken)

    def test_blocks_writes(self, engine):
        result = engine.respond(make_threat(75))
        assert any("blocked" in a.lower() or "writes" in a.lower()
                    for a in result.actions_taken)

    def test_sends_critical_alert(self, engine):
        result = engine.respond(make_threat(75))
        crits = [a for a in result.alerts_sent if a.level == ALERT_CRITICAL]
        assert len(crits) >= 1

    def test_no_termination_at_level3(self, engine):
        result = engine.respond(make_threat(75))
        term_actions = [a for a in result.process_actions if a.action == "terminate"]
        assert len(term_actions) == 0


# ---------------------------------------------------------------------------
# Level 4: Terminate (86-100)
# ---------------------------------------------------------------------------

class TestLevel4Terminate:
    def test_terminates_process(self, engine):
        # We can't actually kill our own process, so check the action was attempted
        result = engine.respond(make_threat(90, pid=99999, name="fake"))
        assert result.escalation_level == 4
        term_actions = [a for a in result.process_actions if a.action == "terminate"]
        assert len(term_actions) >= 1

    def test_blocks_executable(self, engine):
        result = engine.respond(make_threat(95, pid=99999, name="fake"))
        block_actions = [a for a in result.process_actions if a.action == "block"]
        assert len(block_actions) >= 1

    def test_initiates_rollback(self, engine, backup_mgr, source_dir):
        f = source_dir / "rollback.txt"
        f.write_text("original")
        backup_mgr.backup_file(str(f), process_name="ransomware")
        f.write_text("ENCRYPTED")

        result = engine.respond(make_threat(90, pid=99999, name="ransomware"))
        assert any("rollback" in a.lower() for a in result.actions_taken)
        assert f.read_text() == "original"

    def test_generates_incident_report(self, engine):
        result = engine.respond(make_threat(90, pid=99999, name="fake"))
        assert result.incident_report is not None
        assert result.incident_report.threat_score == 90

    def test_sends_emergency_alert(self, engine):
        result = engine.respond(make_threat(95, pid=99999, name="fake"))
        emergencies = [a for a in result.alerts_sent if a.level == ALERT_EMERGENCY]
        assert len(emergencies) >= 1


# ---------------------------------------------------------------------------
# Safe mode
# ---------------------------------------------------------------------------

class TestSafeMode:
    def test_level3_requires_confirmation(self, safe_engine):
        result = safe_engine.respond(make_threat(75))
        assert result.pending_confirmation is True
        assert any("safe mode" in a.lower() for a in result.actions_taken)
        # No process actions yet
        assert len(result.process_actions) == 0

    def test_confirm_executes_pending(self, safe_engine):
        safe_engine.respond(make_threat(75, pid=99999, name="fake"))
        confirmed = safe_engine.confirm()
        assert confirmed is not None
        assert confirmed.pending_confirmation is False
        assert any("confirmed" in a.lower() for a in confirmed.actions_taken)
        # Now process actions should exist
        assert len(confirmed.process_actions) >= 1

    def test_deny_cancels_pending(self, safe_engine):
        safe_engine.respond(make_threat(80))
        denied = safe_engine.deny()
        assert denied is not None
        assert any("denied" in a.lower() for a in denied.actions_taken)
        assert safe_engine.pending is None

    def test_level4_safe_mode_requires_confirmation(self, safe_engine):
        result = safe_engine.respond(make_threat(90))
        assert result.pending_confirmation is True

    def test_confirm_level4_terminates_and_reports(self, safe_engine):
        safe_engine.respond(make_threat(90, pid=99999, name="fake"))
        confirmed = safe_engine.confirm()
        assert confirmed is not None
        term_actions = [a for a in confirmed.process_actions if a.action == "terminate"]
        assert len(term_actions) >= 1
        assert confirmed.incident_report is not None

    def test_levels_1_2_not_blocked_by_safe_mode(self, safe_engine):
        r1 = safe_engine.respond(make_threat(40))
        assert r1.pending_confirmation is False
        r2 = safe_engine.respond(make_threat(60))
        assert r2.pending_confirmation is False

    def test_confirm_with_nothing_pending(self, safe_engine):
        assert safe_engine.confirm() is None


# ---------------------------------------------------------------------------
# Alert system
# ---------------------------------------------------------------------------

class TestAlertSystem:
    def test_alert_levels(self):
        alerts = AlertSystem(enable_desktop=False)
        a1 = alerts.send(ALERT_INFO, "Test", "msg", score=35)
        a2 = alerts.send(ALERT_WARNING, "Test", "msg", score=55)
        a3 = alerts.send(ALERT_CRITICAL, "Test", "msg", score=75)
        a4 = alerts.send(ALERT_EMERGENCY, "Test", "msg", score=90)
        assert a1.level == ALERT_INFO
        assert a2.level == ALERT_WARNING
        assert a3.level == ALERT_CRITICAL
        assert a4.level == ALERT_EMERGENCY

    def test_alert_log_populated(self):
        alerts = AlertSystem(enable_desktop=False)
        alerts.send(ALERT_INFO, "T", "M")
        alerts.send(ALERT_WARNING, "T", "M")
        assert len(alerts.alert_log) == 2

    def test_get_alerts_by_level(self):
        alerts = AlertSystem(enable_desktop=False)
        alerts.send(ALERT_INFO, "T", "M")
        alerts.send(ALERT_WARNING, "T", "M")
        alerts.send(ALERT_INFO, "T", "M")
        assert len(alerts.get_alerts_by_level(ALERT_INFO)) == 2

    def test_alert_fields(self):
        alerts = AlertSystem(enable_desktop=False)
        a = alerts.send(ALERT_CRITICAL, "Title", "Message", process_id=42,
                        process_name="bad", score=80)
        assert a.title == "Title"
        assert a.message == "Message"
        assert a.process_id == 42
        assert a.score == 80
        assert a.timestamp is not None


# ---------------------------------------------------------------------------
# Process controller
# ---------------------------------------------------------------------------

class TestProcessController:
    def test_action_log_populated(self):
        pc = ProcessController()
        pc.suspend(99999)  # will fail, pid doesn't exist
        assert len(pc.action_log) == 1
        assert pc.action_log[0].success is False

    def test_block_and_check(self):
        pc = ProcessController()
        # Can't actually block a fake PID, but check the mechanism
        pc._blocked.add("/usr/bin/fake_malware")
        assert pc.is_blocked("/usr/bin/fake_malware")
        assert not pc.is_blocked("/usr/bin/python")

    def test_blocked_executables_property(self):
        pc = ProcessController()
        pc._blocked.add("/a")
        pc._blocked.add("/b")
        assert pc.blocked_executables == {"/a", "/b"}


# ---------------------------------------------------------------------------
# Recovery workflow
# ---------------------------------------------------------------------------

class TestRecoveryWorkflow:
    def test_get_affected_files(self, backup_mgr, source_dir):
        f1 = source_dir / "a.txt"
        f2 = source_dir / "b.txt"
        f1.write_text("A")
        f2.write_text("B")
        backup_mgr.backup_file(str(f1), process_name="evil")
        backup_mgr.backup_file(str(f2), process_name="evil")

        wf = RecoveryWorkflow(backup_mgr)
        affected = wf.get_affected_files("evil")
        assert len(affected) == 2

    def test_auto_restore(self, backup_mgr, source_dir):
        f = source_dir / "restore.txt"
        f.write_text("original")
        backup_mgr.backup_file(str(f), process_name="evil")
        f.write_text("ENCRYPTED")

        wf = RecoveryWorkflow(backup_mgr)
        results = wf.auto_restore("evil")
        assert any(r.success for r in results)
        assert f.read_text() == "original"

    def test_restore_selected(self, backup_mgr, source_dir):
        f = source_dir / "sel.txt"
        f.write_text("select me")
        backup_mgr.backup_file(str(f))
        backups = backup_mgr.snapshot.get_backups(original_path=str(f))
        f.write_text("GONE")

        wf = RecoveryWorkflow(backup_mgr)
        results = wf.restore_selected([backups[0]["id"]])
        assert results[0].success is True
        assert f.read_text() == "select me"

    def test_incident_report(self, backup_mgr, source_dir):
        f = source_dir / "inc.txt"
        f.write_text("incident")
        backup_mgr.backup_file(str(f), process_name="malware")

        wf = RecoveryWorkflow(backup_mgr)
        report = wf.create_incident_report(
            process_id=999,
            process_name="malware",
            threat_score=92,
            triggered_indicators={"entropy_spike": "5 files"},
            actions_taken=["terminated", "blocked"],
        )
        assert report.threat_score == 92
        assert "inc.txt" in str(report.affected_files)
        assert report.to_json()  # verify serialization works

    def test_incidents_stored(self, backup_mgr):
        wf = RecoveryWorkflow(backup_mgr)
        wf.create_incident_report(1, "p", 50, {}, [])
        wf.create_incident_report(2, "q", 80, {}, [])
        assert len(wf.incidents) == 2


# ---------------------------------------------------------------------------
# Score 0-30: No response
# ---------------------------------------------------------------------------

class TestNoResponse:
    def test_normal_score_no_actions(self, engine):
        result = engine.respond(make_threat(20))
        assert result.escalation_level == 0
        assert len(result.actions_taken) == 0
        assert len(result.alerts_sent) == 0
        assert len(result.process_actions) == 0


# ---------------------------------------------------------------------------
# Response log
# ---------------------------------------------------------------------------

class TestResponseLog:
    def test_log_populated(self, engine):
        engine.respond(make_threat(0))
        engine.respond(make_threat(40))
        engine.respond(make_threat(60))
        assert len(engine.response_log) == 3
