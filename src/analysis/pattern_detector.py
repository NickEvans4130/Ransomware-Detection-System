"""Pattern detection logic for ransomware behavioral indicators.

Tracks per-process file events within a sliding time window and evaluates
each of the six documented indicators:

Primary:
  1. Mass file modification (>20 files in <10s by single process)
  2. Entropy spike pattern (multiple files with delta > 2.0)
  3. Extension manipulation (mass renaming to suspicious extensions)
  4. Directory traversal (activity across multiple directories)

Secondary:
  5. Suspicious process characteristics (temp/download folder execution)
  6. File deletion patterns (original deleted after encrypted copy)
"""

import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

SUSPICIOUS_EXTENSIONS = frozenset({
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc", ".ransom",
    ".rnsmwr", ".cerber", ".locky", ".zepto", ".odin", ".thor",
    ".aesir", ".zzzzz", ".wallet", ".petya", ".cry", ".wncry",
    ".wcry", ".wanna", ".xtbl", ".onion",
})

TEMP_DIR_MARKERS = frozenset({
    "temp", "tmp", "downloads", "appdata", "local",
})


@dataclass
class FileEvent:
    """Lightweight event record for in-memory pattern analysis."""
    timestamp: float
    event_type: str
    file_path: str
    file_extension: str | None = None
    old_path: str | None = None
    process_id: int | None = None
    process_name: str | None = None
    entropy_delta: float | None = None
    entropy_after: float | None = None


@dataclass
class ProcessTracker:
    """Accumulated event data for a single process within the time window."""
    process_id: int | None = None
    process_name: str | None = None
    modified_files: list[FileEvent] = field(default_factory=list)
    created_files: list[FileEvent] = field(default_factory=list)
    deleted_files: list[FileEvent] = field(default_factory=list)
    renamed_files: list[FileEvent] = field(default_factory=list)
    extension_changed_files: list[FileEvent] = field(default_factory=list)
    directories_touched: set[str] = field(default_factory=set)


class PatternDetector:
    """Evaluates behavioral indicators from a stream of file events.

    Events are grouped per-process and kept within a configurable time window.
    """

    def __init__(
        self,
        time_window: float = 10.0,
        mass_modify_threshold: int = 20,
        entropy_spike_threshold: float = 2.0,
        entropy_spike_min_files: int = 3,
        extension_change_min_files: int = 3,
        directory_traversal_min_dirs: int = 4,
    ):
        self.time_window = time_window
        self.mass_modify_threshold = mass_modify_threshold
        self.entropy_spike_threshold = entropy_spike_threshold
        self.entropy_spike_min_files = entropy_spike_min_files
        self.extension_change_min_files = extension_change_min_files
        self.directory_traversal_min_dirs = directory_traversal_min_dirs

        # process_id -> ProcessTracker
        self._trackers: dict[int | None, ProcessTracker] = defaultdict(ProcessTracker)
        # process_id -> list[FileEvent] (chronological)
        self._events: dict[int | None, list[FileEvent]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def record_event(self, event: FileEvent):
        """Record a new file event and prune stale entries."""
        pid = event.process_id
        self._events[pid].append(event)
        self._prune(pid)

        tracker = self._trackers[pid]
        tracker.process_id = pid
        tracker.process_name = event.process_name

        parent_dir = os.path.dirname(event.file_path)
        tracker.directories_touched.add(parent_dir)

        if event.event_type == "modified":
            tracker.modified_files.append(event)
        elif event.event_type == "created":
            tracker.created_files.append(event)
        elif event.event_type == "deleted":
            tracker.deleted_files.append(event)
        elif event.event_type == "moved":
            tracker.renamed_files.append(event)
        elif event.event_type == "extension_changed":
            tracker.extension_changed_files.append(event)

    def _prune(self, pid: int | None):
        """Remove events older than the time window."""
        cutoff = time.time() - self.time_window
        events = self._events[pid]
        while events and events[0].timestamp < cutoff:
            events.pop(0)

        tracker = self._trackers[pid]
        tracker.modified_files = [e for e in tracker.modified_files if e.timestamp >= cutoff]
        tracker.created_files = [e for e in tracker.created_files if e.timestamp >= cutoff]
        tracker.deleted_files = [e for e in tracker.deleted_files if e.timestamp >= cutoff]
        tracker.renamed_files = [e for e in tracker.renamed_files if e.timestamp >= cutoff]
        tracker.extension_changed_files = [
            e for e in tracker.extension_changed_files if e.timestamp >= cutoff
        ]
        # Rebuild directories_touched from surviving events
        tracker.directories_touched = {
            os.path.dirname(e.file_path) for e in self._events[pid]
        }

    # ------------------------------------------------------------------
    # Indicator evaluation  (returns triggered: bool, details: str)
    # ------------------------------------------------------------------

    def check_mass_modification(self, pid: int | None) -> tuple[bool, str]:
        """Indicator 1: >threshold files modified in <time_window by single process."""
        tracker = self._trackers.get(pid)
        if not tracker:
            return False, ""
        count = len(tracker.modified_files)
        if count > self.mass_modify_threshold:
            return True, f"{count} files modified in window by pid {pid}"
        return False, ""

    def check_entropy_spike(self, pid: int | None) -> tuple[bool, str]:
        """Indicator 2: Multiple files with entropy increase > threshold."""
        tracker = self._trackers.get(pid)
        if not tracker:
            return False, ""
        spikes = [
            e for e in tracker.modified_files
            if e.entropy_delta is not None and e.entropy_delta >= self.entropy_spike_threshold
        ]
        if len(spikes) >= self.entropy_spike_min_files:
            return True, f"{len(spikes)} files with entropy spike by pid {pid}"
        return False, ""

    def check_extension_manipulation(self, pid: int | None) -> tuple[bool, str]:
        """Indicator 3: Mass renaming with suspicious extensions."""
        tracker = self._trackers.get(pid)
        if not tracker:
            return False, ""
        suspicious = [
            e for e in tracker.extension_changed_files
            if e.file_extension and e.file_extension.lower() in SUSPICIOUS_EXTENSIONS
        ]
        if len(suspicious) >= self.extension_change_min_files:
            exts = {e.file_extension for e in suspicious}
            return True, f"{len(suspicious)} files renamed to {exts} by pid {pid}"
        return False, ""

    def check_directory_traversal(self, pid: int | None) -> tuple[bool, str]:
        """Indicator 4: Activity across multiple directories."""
        tracker = self._trackers.get(pid)
        if not tracker:
            return False, ""
        count = len(tracker.directories_touched)
        if count >= self.directory_traversal_min_dirs:
            return True, f"{count} directories touched by pid {pid}"
        return False, ""

    def check_suspicious_process(self, pid: int | None) -> tuple[bool, str]:
        """Indicator 5: Process executed from temp/download folders."""
        tracker = self._trackers.get(pid)
        if not tracker or not tracker.process_name:
            return False, ""
        # Check if any event's process path contains temp directory markers
        # We use directories_touched as a proxy; in production we'd check
        # the process executable path via psutil.
        events = self._events.get(pid, [])
        if not events:
            return False, ""
        # Check based on process name heuristics and directories
        for marker in TEMP_DIR_MARKERS:
            for d in tracker.directories_touched:
                if marker in d.lower():
                    return True, f"Process pid {pid} ({tracker.process_name}) active in temp-like dir"
        return False, ""

    def check_deletion_pattern(self, pid: int | None) -> tuple[bool, str]:
        """Indicator 6: Originals deleted after encrypted copies created."""
        tracker = self._trackers.get(pid)
        if not tracker:
            return False, ""
        if not tracker.deleted_files or not tracker.created_files:
            return False, ""

        deleted_stems = set()
        for e in tracker.deleted_files:
            stem, _ = os.path.splitext(os.path.basename(e.file_path))
            deleted_stems.add(stem)

        suspicious_creates = []
        for e in tracker.created_files:
            stem, ext = os.path.splitext(os.path.basename(e.file_path))
            if ext and ext.lower() in SUSPICIOUS_EXTENSIONS and stem in deleted_stems:
                suspicious_creates.append(e)

        if suspicious_creates:
            return True, (
                f"{len(suspicious_creates)} delete-then-create-encrypted patterns by pid {pid}"
            )
        return False, ""

    # ------------------------------------------------------------------
    # Public: evaluate all indicators for a process
    # ------------------------------------------------------------------

    def evaluate(self, pid: int | None) -> dict[str, tuple[bool, str]]:
        """Run all six indicator checks for a given process.

        Returns a dict mapping indicator name to (triggered, detail_string).
        """
        self._prune(pid)
        return {
            "mass_modification": self.check_mass_modification(pid),
            "entropy_spike": self.check_entropy_spike(pid),
            "extension_manipulation": self.check_extension_manipulation(pid),
            "directory_traversal": self.check_directory_traversal(pid),
            "suspicious_process": self.check_suspicious_process(pid),
            "deletion_pattern": self.check_deletion_pattern(pid),
        }

    def get_all_tracked_pids(self) -> list[int | None]:
        """Return all PIDs currently being tracked."""
        return list(self._trackers.keys())
