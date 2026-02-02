"""Guided recovery workflow.

Implements the recovery workflow from the docs:
  1. Threat detected -> process quarantined
  2. User notified with threat details
  3. Show list of affected files
  4. Offer restoration options:
     - Auto-restore all affected files
     - Manual selection (returns list for caller to choose from)
     - Create report only

Also generates incident reports for Level 4 escalation.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime

from src.response.backup_manager import BackupManager
from src.response.recovery_manager import RestoreResult

logger = logging.getLogger(__name__)


@dataclass
class IncidentReport:
    """Full incident report for Level 4 / post-incident review."""
    timestamp: str
    process_id: int | None
    process_name: str | None
    threat_score: int
    triggered_indicators: dict[str, str]
    affected_files: list[str]
    actions_taken: list[str]
    restore_results: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "threat_score": self.threat_score,
            "triggered_indicators": self.triggered_indicators,
            "affected_files": self.affected_files,
            "actions_taken": self.actions_taken,
            "restore_results": self.restore_results,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class RecoveryWorkflow:
    """Orchestrates the guided recovery process."""

    def __init__(self, backup_manager: BackupManager):
        self.backup = backup_manager
        self._incidents: list[IncidentReport] = []

    def get_affected_files(self, process_name: str) -> list[dict]:
        """Return backups associated with a process (step 3: show affected files)."""
        return self.backup.snapshot.get_backups(process_name=process_name, limit=10000)

    def auto_restore(self, process_name: str) -> list[RestoreResult]:
        """Auto-restore all files affected by a specific process."""
        return self.backup.recovery.restore_by_process(process_name)

    def restore_selected(self, backup_ids: list[int]) -> list[RestoreResult]:
        """Restore manually selected backups by their IDs."""
        return [self.backup.recovery.restore_file(bid) for bid in backup_ids]

    def create_incident_report(
        self,
        process_id: int | None,
        process_name: str | None,
        threat_score: int,
        triggered_indicators: dict[str, str],
        actions_taken: list[str],
        restore_results: list[RestoreResult] | None = None,
    ) -> IncidentReport:
        """Generate a full incident report (Level 4 requirement)."""
        affected = []
        if process_name:
            affected = [b["original_path"]
                        for b in self.get_affected_files(process_name)]

        rr_dicts = []
        if restore_results:
            rr_dicts = [
                {
                    "original_path": r.original_path,
                    "success": r.success,
                    "integrity_ok": r.integrity_ok,
                    "error": r.error,
                }
                for r in restore_results
            ]

        report = IncidentReport(
            timestamp=datetime.now().isoformat(),
            process_id=process_id,
            process_name=process_name,
            threat_score=threat_score,
            triggered_indicators=triggered_indicators,
            affected_files=affected,
            actions_taken=actions_taken,
            restore_results=rr_dicts,
        )
        self._incidents.append(report)
        logger.warning("Incident report generated for pid=%s (%s), score=%d",
                        process_id, process_name, threat_score)
        return report

    @property
    def incidents(self) -> list[IncidentReport]:
        return list(self._incidents)
