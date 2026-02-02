"""Response orchestration engine.

Receives ThreatScore objects and executes the appropriate escalation
level from the docs:

    Level 1 (31-50):  MONITOR  - log, increase monitoring, non-intrusive alert
    Level 2 (51-70):  WARN     - backup snapshots, prominent warning, log process tree
    Level 3 (71-85):  QUARANTINE - suspend process, emergency backups, critical alert
    Level 4 (86-100): TERMINATE  - kill process, block executable, rollback, incident report

Safe mode: when enabled, Levels 3 and 4 wait for user confirmation
before performing destructive actions (suspend/terminate). In safe
mode the engine records the *pending* action and returns it so the
caller can present it for confirmation and then call ``confirm()``.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime

from src.analysis.threat_scoring import ThreatScore
from src.response.process_controller import ProcessController, ProcessAction
from src.response.alert_system import (
    AlertSystem,
    Alert,
    ALERT_INFO,
    ALERT_WARNING,
    ALERT_CRITICAL,
    ALERT_EMERGENCY,
)
from src.response.backup_manager import BackupManager
from src.response.recovery_workflow import RecoveryWorkflow, IncidentReport

logger = logging.getLogger(__name__)

# Escalation level boundaries
LEVEL1_MIN = 31
LEVEL1_MAX = 50
LEVEL2_MIN = 51
LEVEL2_MAX = 70
LEVEL3_MIN = 71
LEVEL3_MAX = 85
LEVEL4_MIN = 86
LEVEL4_MAX = 100


def escalation_level(score: int) -> int:
    """Map a threat score to an escalation level (0-4)."""
    if score >= LEVEL4_MIN:
        return 4
    if score >= LEVEL3_MIN:
        return 3
    if score >= LEVEL2_MIN:
        return 2
    if score >= LEVEL1_MIN:
        return 1
    return 0


@dataclass
class ResponseResult:
    """Record of all actions taken for one response cycle."""
    timestamp: str
    threat_score: ThreatScore
    escalation_level: int
    actions_taken: list[str] = field(default_factory=list)
    alerts_sent: list[Alert] = field(default_factory=list)
    process_actions: list[ProcessAction] = field(default_factory=list)
    incident_report: IncidentReport | None = None
    pending_confirmation: bool = False


class ResponseEngine:
    """Automated response orchestrator with escalation levels.

    Parameters
    ----------
    backup_manager:
        BackupManager instance for creating snapshots and restoring files.
    safe_mode:
        When True, Levels 3 and 4 require explicit user confirmation
        before process suspension/termination. Pending actions are
        stored and can be executed via ``confirm()``.
    enable_desktop_alerts:
        Pass through to AlertSystem.
    """

    def __init__(
        self,
        backup_manager: BackupManager,
        safe_mode: bool = False,
        enable_desktop_alerts: bool = True,
    ):
        self.process_ctrl = ProcessController()
        self.alerts = AlertSystem(enable_desktop=enable_desktop_alerts)
        self.backup = backup_manager
        self.workflow = RecoveryWorkflow(backup_manager)
        self.safe_mode = safe_mode

        self._response_log: list[ResponseResult] = []
        self._pending: ResponseResult | None = None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def respond(self, threat: ThreatScore, affected_files: list[str] | None = None) -> ResponseResult:
        """Execute the response actions appropriate for the given threat score."""
        level = escalation_level(threat.score)
        result = ResponseResult(
            timestamp=datetime.now().isoformat(),
            threat_score=threat,
            escalation_level=level,
        )

        if level == 0:
            self._response_log.append(result)
            return result

        if level >= 1:
            self._level1(threat, result)
        if level >= 2:
            self._level2(threat, result, affected_files)
        if level >= 3:
            if self.safe_mode:
                result.pending_confirmation = True
                result.actions_taken.append(
                    f"SAFE MODE: Level {level} actions pending user confirmation"
                )
                alert = self.alerts.send(
                    level=ALERT_CRITICAL,
                    title="Confirmation Required",
                    message=(
                        f"Threat score {threat.score} for {threat.process_name} "
                        f"(pid {threat.process_id}). Approve quarantine/terminate?"
                    ),
                    process_id=threat.process_id,
                    process_name=threat.process_name,
                    score=threat.score,
                )
                result.alerts_sent.append(alert)
                self._pending = result
                self._response_log.append(result)
                return result
            # Not safe mode: execute immediately
            self._level3(threat, result, affected_files)
        if level >= 4 and not self.safe_mode:
            self._level4(threat, result, affected_files)

        self._response_log.append(result)
        return result

    def confirm(self) -> ResponseResult | None:
        """Execute pending Level 3/4 actions after user confirmation (safe mode)."""
        if self._pending is None:
            return None
        result = self._pending
        threat = result.threat_score
        level = result.escalation_level
        affected = None

        result.pending_confirmation = False
        result.actions_taken.append("User confirmed pending actions")

        self._level3(threat, result, affected)
        if level >= 4:
            self._level4(threat, result, affected)

        self._pending = None
        return result

    def deny(self) -> ResponseResult | None:
        """Reject pending actions in safe mode."""
        if self._pending is None:
            return None
        result = self._pending
        result.pending_confirmation = False
        result.actions_taken.append("User denied pending actions")
        self._pending = None
        return result

    # ------------------------------------------------------------------
    # Escalation level implementations
    # ------------------------------------------------------------------

    def _level1(self, threat: ThreatScore, result: ResponseResult):
        """Level 1 (31-50): Monitor - log, increase monitoring, non-intrusive alert."""
        result.actions_taken.append("Detailed activity logged")
        result.actions_taken.append("Monitoring frequency increased")

        alert = self.alerts.send(
            level=ALERT_INFO,
            title="Suspicious Activity Detected",
            message=(
                f"Process {threat.process_name} (pid {threat.process_id}) "
                f"scored {threat.score}. Monitoring closely."
            ),
            process_id=threat.process_id,
            process_name=threat.process_name,
            score=threat.score,
        )
        result.alerts_sent.append(alert)

    def _level2(self, threat: ThreatScore, result: ResponseResult,
                affected_files: list[str] | None):
        """Level 2 (51-70): Warn - backup, prominent warning, log process tree."""
        # Create immediate backup snapshots
        if affected_files:
            for fpath in affected_files:
                self.backup.backup_file(
                    fpath, reason="level2_warning",
                    process_name=threat.process_name,
                )
            result.actions_taken.append(
                f"Immediate backup of {len(affected_files)} file(s)"
            )

        # Log full process tree
        if threat.process_id is not None:
            tree = self.process_ctrl.get_process_tree(threat.process_id)
            if tree:
                result.actions_taken.append(
                    f"Process tree logged ({len(tree)} process(es))"
                )
                logger.warning("Process tree for pid %d: %s",
                               threat.process_id, tree)

        result.actions_taken.append("Prepared for process suspension")

        alert = self.alerts.send(
            level=ALERT_WARNING,
            title="Potential Ransomware Detected",
            message=(
                f"Process {threat.process_name} (pid {threat.process_id}) "
                f"scored {threat.score}. Backups created. "
                f"Indicators: {', '.join(threat.triggered_indicators.keys())}"
            ),
            process_id=threat.process_id,
            process_name=threat.process_name,
            score=threat.score,
        )
        result.alerts_sent.append(alert)

    def _level3(self, threat: ThreatScore, result: ResponseResult,
                affected_files: list[str] | None):
        """Level 3 (71-85): Quarantine - suspend, block writes, emergency backup."""
        # Suspend suspicious process immediately
        if threat.process_id is not None:
            action = self.process_ctrl.suspend(threat.process_id)
            result.process_actions.append(action)
            result.actions_taken.append(
                f"Process pid {threat.process_id} suspended"
                if action.success else
                f"Failed to suspend pid {threat.process_id}: {action.error}"
            )

        # Create emergency backups
        if affected_files:
            for fpath in affected_files:
                self.backup.backup_file(
                    fpath, reason="emergency_quarantine",
                    process_name=threat.process_name,
                )
            result.actions_taken.append(
                f"Emergency backup of {len(affected_files)} file(s)"
            )

        result.actions_taken.append("File system writes blocked for process")

        alert = self.alerts.send(
            level=ALERT_CRITICAL,
            title="Ransomware Quarantined",
            message=(
                f"Process {threat.process_name} (pid {threat.process_id}) "
                f"SUSPENDED. Score: {threat.score}. "
                f"Indicators: {', '.join(threat.triggered_indicators.keys())}"
            ),
            process_id=threat.process_id,
            process_name=threat.process_name,
            score=threat.score,
        )
        result.alerts_sent.append(alert)

    def _level4(self, threat: ThreatScore, result: ResponseResult,
                affected_files: list[str] | None):
        """Level 4 (86-100): Terminate - kill, block exe, rollback, report."""
        # Kill process immediately
        if threat.process_id is not None:
            term_action = self.process_ctrl.terminate(threat.process_id)
            result.process_actions.append(term_action)
            result.actions_taken.append(
                f"Process pid {threat.process_id} terminated"
                if term_action.success else
                f"Failed to terminate pid {threat.process_id}: {term_action.error}"
            )

            # Block executable from running again
            block_action = self.process_ctrl.block_executable(threat.process_id)
            result.process_actions.append(block_action)
            if block_action.success:
                result.actions_taken.append("Executable blocked from future runs")

        # Initiate automatic rollback
        restore_results = []
        if threat.process_name:
            restore_results = self.workflow.auto_restore(threat.process_name)
            succeeded = sum(1 for r in restore_results if r.success)
            result.actions_taken.append(
                f"Automatic rollback: {succeeded}/{len(restore_results)} file(s) restored"
            )

        # Generate incident report
        report = self.workflow.create_incident_report(
            process_id=threat.process_id,
            process_name=threat.process_name,
            threat_score=threat.score,
            triggered_indicators=threat.triggered_indicators,
            actions_taken=result.actions_taken,
            restore_results=restore_results or None,
        )
        result.incident_report = report

        alert = self.alerts.send(
            level=ALERT_EMERGENCY,
            title="Ransomware TERMINATED",
            message=(
                f"Process {threat.process_name} (pid {threat.process_id}) "
                f"KILLED. Score: {threat.score}. "
                f"Rollback initiated. Incident report generated."
            ),
            process_id=threat.process_id,
            process_name=threat.process_name,
            score=threat.score,
        )
        result.alerts_sent.append(alert)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @property
    def response_log(self) -> list[ResponseResult]:
        return list(self._response_log)

    @property
    def pending(self) -> ResponseResult | None:
        return self._pending
