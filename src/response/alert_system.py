"""User notification system.

Provides non-blocking alerts at varying severity levels. Uses
platform-appropriate notification mechanisms where available and
falls back to logging.

Alert levels map to escalation levels:
    INFO       -> Level 1 (non-intrusive notification)
    WARNING    -> Level 2 (prominent warning)
    CRITICAL   -> Level 3 (critical alert)
    EMERGENCY  -> Level 4 (emergency, auto-action taken)
"""

import logging
import subprocess
import platform
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

ALERT_INFO = "INFO"
ALERT_WARNING = "WARNING"
ALERT_CRITICAL = "CRITICAL"
ALERT_EMERGENCY = "EMERGENCY"


@dataclass
class Alert:
    """Record of an alert sent to the user."""
    timestamp: str
    level: str
    title: str
    message: str
    process_id: int | None
    process_name: str | None
    score: int
    delivered: bool


class AlertSystem:
    """Non-blocking user alert system.

    Alerts are always logged. Desktop notifications are attempted
    on supported platforms but failures are silently swallowed to
    keep the system non-blocking.
    """

    def __init__(self, enable_desktop: bool = True):
        self.enable_desktop = enable_desktop
        self._alert_log: list[Alert] = []
        self._system = platform.system()

    def send(
        self,
        level: str,
        title: str,
        message: str,
        process_id: int | None = None,
        process_name: str | None = None,
        score: int = 0,
    ) -> Alert:
        """Send a non-blocking alert."""
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            level=level,
            title=title,
            message=message,
            process_id=process_id,
            process_name=process_name,
            score=score,
            delivered=False,
        )

        # Always log
        log_fn = {
            ALERT_INFO: logger.info,
            ALERT_WARNING: logger.warning,
            ALERT_CRITICAL: logger.critical,
            ALERT_EMERGENCY: logger.critical,
        }.get(level, logger.info)

        log_fn("ALERT [%s] %s: %s (pid=%s, score=%d)",
               level, title, message, process_id, score)

        # Attempt desktop notification
        if self.enable_desktop:
            alert.delivered = self._desktop_notify(level, title, message)
        else:
            alert.delivered = True  # log-only counts as delivered

        self._alert_log.append(alert)
        return alert

    def _desktop_notify(self, level: str, title: str, message: str) -> bool:
        """Try platform-specific desktop notification. Returns success."""
        try:
            if self._system == "Linux":
                urgency = {
                    ALERT_INFO: "low",
                    ALERT_WARNING: "normal",
                    ALERT_CRITICAL: "critical",
                    ALERT_EMERGENCY: "critical",
                }.get(level, "normal")
                subprocess.Popen(
                    ["notify-send", "-u", urgency, title, message],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
            elif self._system == "Darwin":
                script = f'display notification "{message}" with title "{title}"'
                subprocess.Popen(
                    ["osascript", "-e", script],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
            # Windows or unknown: log only
            return True
        except (FileNotFoundError, OSError):
            return False

    @property
    def alert_log(self) -> list[Alert]:
        return list(self._alert_log)

    def get_alerts_by_level(self, level: str) -> list[Alert]:
        return [a for a in self._alert_log if a.level == level]
