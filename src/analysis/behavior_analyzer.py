"""Main behavioral detection engine.

Receives file events (from the monitor layer), feeds them into the
PatternDetector for per-process time-windowed analysis, then runs
the ThreatScoring algorithm and emits results.

This is the single entry-point that the file monitor calls for every event.
"""

import logging
import time

from src.analysis.pattern_detector import PatternDetector, FileEvent
from src.analysis.threat_scoring import (
    ThreatScore,
    calculate_threat_score,
    THRESHOLD_CRITICAL,
)

logger = logging.getLogger(__name__)


class BehaviorAnalyzer:
    """Real-time behavioral analysis engine.

    Parameters
    ----------
    time_window:
        Seconds to keep events for pattern aggregation (default 10).
    mass_modify_threshold:
        Files modified by a single process before triggering indicator 1.
    entropy_spike_threshold:
        Minimum entropy delta to count as a spike (indicator 2).
    entropy_spike_min_files:
        How many spiked files before indicator 2 triggers.
    extension_change_min_files:
        How many suspicious extension renames before indicator 3 triggers.
    directory_traversal_min_dirs:
        Directories touched before indicator 4 triggers.
    on_threat:
        Optional callback invoked with a ``ThreatScore`` whenever a process
        reaches the CRITICAL level (score >= 71).
    """

    def __init__(
        self,
        time_window: float = 10.0,
        mass_modify_threshold: int = 20,
        entropy_spike_threshold: float = 2.0,
        entropy_spike_min_files: int = 3,
        extension_change_min_files: int = 3,
        directory_traversal_min_dirs: int = 4,
        on_threat=None,
    ):
        self.detector = PatternDetector(
            time_window=time_window,
            mass_modify_threshold=mass_modify_threshold,
            entropy_spike_threshold=entropy_spike_threshold,
            entropy_spike_min_files=entropy_spike_min_files,
            extension_change_min_files=extension_change_min_files,
            directory_traversal_min_dirs=directory_traversal_min_dirs,
        )
        self.on_threat = on_threat
        # Most recent ThreatScore per pid, for external queries
        self._latest_scores: dict[int | None, ThreatScore] = {}

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def process_event(
        self,
        event_type: str,
        file_path: str,
        file_extension: str | None = None,
        old_path: str | None = None,
        process_id: int | None = None,
        process_name: str | None = None,
        entropy_delta: float | None = None,
        entropy_after: float | None = None,
    ) -> ThreatScore:
        """Ingest a single file-system event and return the updated threat score.

        This method is designed to be called in real-time from the monitor
        layer for every captured event.
        """
        event = FileEvent(
            timestamp=time.time(),
            event_type=event_type,
            file_path=file_path,
            file_extension=file_extension,
            old_path=old_path,
            process_id=process_id,
            process_name=process_name,
            entropy_delta=entropy_delta,
            entropy_after=entropy_after,
        )

        self.detector.record_event(event)
        indicators = self.detector.evaluate(process_id)

        score = calculate_threat_score(
            indicators,
            process_id=process_id,
            process_name=process_name,
        )

        self._latest_scores[process_id] = score

        if score.action_required and self.on_threat:
            self.on_threat(score)

        return score

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_score(self, pid: int | None) -> ThreatScore | None:
        """Return the most recent threat score for a process."""
        return self._latest_scores.get(pid)

    def get_all_scores(self) -> dict[int | None, ThreatScore]:
        """Return latest scores for all tracked processes."""
        return dict(self._latest_scores)

    def get_critical_processes(self) -> list[ThreatScore]:
        """Return scores for all processes currently at CRITICAL level."""
        return [s for s in self._latest_scores.values() if s.action_required]
