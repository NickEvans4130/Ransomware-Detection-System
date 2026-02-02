"""Process management for threat response.

Provides suspend, resume, terminate, and block operations on processes
identified by PID, using psutil.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ProcessAction:
    """Record of an action taken on a process."""
    timestamp: str
    pid: int
    process_name: str | None
    action: str  # "suspend", "resume", "terminate", "block"
    success: bool
    error: str | None = None


class ProcessController:
    """Manages process suspension, termination, and blocking."""

    def __init__(self):
        # Blocked executables: set of normalized executable paths
        self._blocked: set[str] = set()
        self._action_log: list[ProcessAction] = []

    def _log_action(self, pid: int, name: str | None, action: str,
                    success: bool, error: str | None = None) -> ProcessAction:
        record = ProcessAction(
            timestamp=datetime.now().isoformat(),
            pid=pid,
            process_name=name,
            action=action,
            success=success,
            error=error,
        )
        self._action_log.append(record)
        return record

    def suspend(self, pid: int) -> ProcessAction:
        """Suspend (pause) a process by PID."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.suspend()
            logger.warning("Suspended process pid=%d (%s)", pid, name)
            return self._log_action(pid, name, "suspend", True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            logger.error("Failed to suspend pid=%d: %s", pid, exc)
            return self._log_action(pid, None, "suspend", False, str(exc))

    def resume(self, pid: int) -> ProcessAction:
        """Resume a previously suspended process."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.resume()
            logger.info("Resumed process pid=%d (%s)", pid, name)
            return self._log_action(pid, name, "resume", True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            logger.error("Failed to resume pid=%d: %s", pid, exc)
            return self._log_action(pid, None, "resume", False, str(exc))

    def terminate(self, pid: int) -> ProcessAction:
        """Terminate (kill) a process by PID."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.terminate()
            logger.warning("Terminated process pid=%d (%s)", pid, name)
            return self._log_action(pid, name, "terminate", True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            logger.error("Failed to terminate pid=%d: %s", pid, exc)
            return self._log_action(pid, None, "terminate", False, str(exc))

    def block_executable(self, pid: int) -> ProcessAction:
        """Add the executable behind a PID to the blocked list."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = proc.exe()
            self._blocked.add(os.path.normpath(exe))
            logger.warning("Blocked executable: %s (pid=%d)", exe, pid)
            return self._log_action(pid, name, "block", True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            logger.error("Failed to block pid=%d: %s", pid, exc)
            return self._log_action(pid, None, "block", False, str(exc))

    def is_blocked(self, exe_path: str) -> bool:
        """Check if an executable path is on the blocked list."""
        return os.path.normpath(exe_path) in self._blocked

    def get_process_tree(self, pid: int) -> list[dict] | None:
        """Return the process tree (parent + children) for logging."""
        try:
            proc = psutil.Process(pid)
            tree = [{
                "pid": proc.pid,
                "name": proc.name(),
                "status": proc.status(),
                "exe": proc.exe() if proc.is_running() else None,
            }]
            for child in proc.children(recursive=True):
                try:
                    tree.append({
                        "pid": child.pid,
                        "name": child.name(),
                        "status": child.status(),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return tree
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @property
    def blocked_executables(self) -> set[str]:
        return set(self._blocked)

    @property
    def action_log(self) -> list[ProcessAction]:
        return list(self._action_log)
