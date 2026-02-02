"""Real-time file system monitor using watchdog and psutil."""

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

import psutil
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    DirCreatedEvent,
    DirModifiedEvent,
    DirDeletedEvent,
    DirMovedEvent,
)

from src.database.event_logger import EventLogger
from src.analysis.entropy_detector import EntropyDetector

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "config.json"


def get_process_info(pid: int = None) -> tuple[int | None, str | None]:
    """Get process ID and name for the most likely writer process.

    Attempts to identify which process triggered the file event by checking
    recent disk-writing processes. Falls back to None if unavailable.
    """
    try:
        if pid:
            proc = psutil.Process(pid)
            return proc.pid, proc.name()

        current_pid = os.getpid()
        candidates = []
        for proc in psutil.process_iter(["pid", "name", "io_counters"]):
            try:
                if proc.info["pid"] == current_pid:
                    continue
                io = proc.info.get("io_counters")
                if io and io.write_bytes > 0:
                    candidates.append((proc.info["pid"], proc.info["name"], io.write_bytes))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if candidates:
            candidates.sort(key=lambda x: x[2], reverse=True)
            return candidates[0][0], candidates[0][1]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return None, None


def get_file_size(path: str) -> int | None:
    """Return file size in bytes, or None if inaccessible."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


class RansomwareEventHandler(FileSystemEventHandler):
    """Watchdog event handler that logs all file operations with metadata."""

    def __init__(self, event_logger: EventLogger, exclude_dirs: list[str] = None,
                 extension_filter: list[str] = None,
                 entropy_detector: EntropyDetector = None):
        super().__init__()
        self.event_logger = event_logger
        self.entropy_detector = entropy_detector
        self.exclude_dirs = [os.path.normpath(d) for d in (exclude_dirs or [])]
        self.extension_filter = [
            ext if ext.startswith(".") else f".{ext}"
            for ext in (extension_filter or [])
        ]
        self._size_cache: dict[str, int] = {}

    def _is_excluded(self, path: str) -> bool:
        norm = os.path.normpath(path)
        for exc in self.exclude_dirs:
            if exc in norm:
                return True
        return False

    def _passes_extension_filter(self, path: str) -> bool:
        if not self.extension_filter:
            return True
        _, ext = os.path.splitext(path)
        return ext.lower() in self.extension_filter

    def _detect_extension_change(self, old_path: str, new_path: str) -> bool:
        _, old_ext = os.path.splitext(old_path)
        _, new_ext = os.path.splitext(new_path)
        return old_ext.lower() != new_ext.lower()

    def on_created(self, event):
        try:
            self._handle_created(event)
        except Exception:
            logger.exception("Error handling created event for %s", event.src_path)

    def _handle_created(self, event):
        if self._is_excluded(event.src_path):
            return
        if not event.is_directory and not self._passes_extension_filter(event.src_path):
            return

        size = get_file_size(event.src_path)
        if size is not None:
            self._size_cache[event.src_path] = size

        pid, pname = get_process_info()
        _, ext = os.path.splitext(event.src_path)

        self.event_logger.log_event(
            event_type="created",
            file_path=event.src_path,
            file_extension=ext or None,
            file_size_after=size,
            process_id=pid,
            process_name=pname,
            is_directory=event.is_directory,
        )
        logger.info("CREATED: %s (pid=%s, %s)", event.src_path, pid, pname)

        if not event.is_directory and self.entropy_detector:
            result = self.entropy_detector.on_file_created(event.src_path)
            if result and result["suspicious"]:
                logger.warning("ENTROPY ALERT on create: %s (%.2f)",
                               event.src_path, result["entropy_after"])

    def on_modified(self, event):
        try:
            self._handle_modified(event)
        except Exception:
            logger.exception("Error handling modified event for %s", event.src_path)

    def _handle_modified(self, event):
        if event.is_directory:
            return
        if self._is_excluded(event.src_path):
            return
        if not self._passes_extension_filter(event.src_path):
            return

        size_before = self._size_cache.get(event.src_path)
        size_after = get_file_size(event.src_path)
        if size_after is not None:
            self._size_cache[event.src_path] = size_after

        pid, pname = get_process_info()
        _, ext = os.path.splitext(event.src_path)

        self.event_logger.log_event(
            event_type="modified",
            file_path=event.src_path,
            file_extension=ext or None,
            file_size_before=size_before,
            file_size_after=size_after,
            process_id=pid,
            process_name=pname,
            is_directory=False,
        )
        logger.info("MODIFIED: %s (pid=%s, %s)", event.src_path, pid, pname)

        if self.entropy_detector:
            result = self.entropy_detector.analyze_file(event.src_path)
            if result and result["suspicious"]:
                logger.warning(
                    "ENTROPY ALERT on modify: %s (%.2f -> %.2f, delta=%.2f)",
                    event.src_path, result["entropy_before"] or 0.0,
                    result["entropy_after"], result["delta"],
                )

    def on_deleted(self, event):
        try:
            self._handle_deleted(event)
        except Exception:
            logger.exception("Error handling deleted event for %s", event.src_path)

    def _handle_deleted(self, event):
        if self._is_excluded(event.src_path):
            return
        if not event.is_directory and not self._passes_extension_filter(event.src_path):
            return

        size_before = self._size_cache.pop(event.src_path, None)
        pid, pname = get_process_info()
        _, ext = os.path.splitext(event.src_path)

        self.event_logger.log_event(
            event_type="deleted",
            file_path=event.src_path,
            file_extension=ext or None,
            file_size_before=size_before,
            process_id=pid,
            process_name=pname,
            is_directory=event.is_directory,
        )
        logger.info("DELETED: %s (pid=%s, %s)", event.src_path, pid, pname)

        if not event.is_directory and self.entropy_detector:
            self.entropy_detector.on_file_deleted(event.src_path)

    def on_moved(self, event):
        try:
            self._handle_moved(event)
        except Exception:
            logger.exception("Error handling moved event for %s", event.src_path)

    def _handle_moved(self, event):
        if self._is_excluded(event.src_path) and self._is_excluded(event.dest_path):
            return

        size = self._size_cache.pop(event.src_path, None)
        if size is None:
            size = get_file_size(event.dest_path)
        if size is not None:
            self._size_cache[event.dest_path] = size

        pid, pname = get_process_info()
        _, old_ext = os.path.splitext(event.src_path)
        _, new_ext = os.path.splitext(event.dest_path)

        event_type = "moved"
        if not event.is_directory and self._detect_extension_change(
            event.src_path, event.dest_path
        ):
            event_type = "extension_changed"

        self.event_logger.log_event(
            event_type=event_type,
            file_path=event.dest_path,
            file_extension=new_ext or None,
            old_path=event.src_path,
            file_size_before=size,
            file_size_after=size,
            process_id=pid,
            process_name=pname,
            is_directory=event.is_directory,
        )
        logger.info(
            "%s: %s -> %s (pid=%s, %s)",
            event_type.upper(), event.src_path, event.dest_path, pid, pname,
        )


class FileMonitor:
    """Manages watchdog observers for configured directories."""

    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path or str(DEFAULT_CONFIG))
        self.event_logger = EventLogger(self.config["database"]["path"])

        entropy_cfg = self.config.get("entropy", {})
        baseline_db = entropy_cfg.get("baseline_db_path", "data/entropy_baselines.db")
        delta_threshold = entropy_cfg.get("delta_threshold", 2.0)
        self.entropy_detector = EntropyDetector(
            baseline_db_path=baseline_db,
            delta_threshold=delta_threshold,
        )

        self.observer = Observer()
        self._running = False

    @staticmethod
    def _load_config(config_path: str) -> dict:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with open(path) as f:
            return json.load(f)

    def _resolve_path(self, path_str: str) -> Path:
        return Path(os.path.expanduser(os.path.expandvars(path_str))).resolve()

    def start(self):
        """Start monitoring all configured directories."""
        monitor_cfg = self.config["monitor"]
        handler = RansomwareEventHandler(
            event_logger=self.event_logger,
            exclude_dirs=monitor_cfg.get("exclude_directories", []),
            extension_filter=monitor_cfg.get("file_extension_filter", []),
            entropy_detector=self.entropy_detector,
        )

        watch_dirs = monitor_cfg.get("watch_directories", [])
        recursive = monitor_cfg.get("recursive", True)

        scheduled = 0
        for dir_str in watch_dirs:
            watch_path = self._resolve_path(dir_str)
            if not watch_path.exists():
                logger.warning("Watch directory does not exist, skipping: %s", watch_path)
                continue
            if not watch_path.is_dir():
                logger.warning("Path is not a directory, skipping: %s", watch_path)
                continue

            self.observer.schedule(handler, str(watch_path), recursive=recursive)
            logger.info("Watching: %s (recursive=%s)", watch_path, recursive)
            scheduled += 1

        if scheduled == 0:
            logger.error("No valid directories to watch. Check config.")
            sys.exit(1)

        self.observer.start()
        self._running = True
        logger.info("File monitor started. Watching %d directories.", scheduled)

    def stop(self):
        """Stop monitoring and clean up."""
        if self._running:
            self.observer.stop()
            self.observer.join()
            self.entropy_detector.close()
            self.event_logger.close()
            self._running = False
            logger.info("File monitor stopped.")

    def run(self):
        """Start monitoring and block until interrupted."""
        self.start()
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


def main():
    parser = argparse.ArgumentParser(description="Ransomware Detection - File System Monitor")
    parser.add_argument(
        "-c", "--config",
        default=str(DEFAULT_CONFIG),
        help="Path to config.json",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    monitor = FileMonitor(config_path=args.config)

    def handle_signal(signum, frame):
        logger.info("Received signal %s, shutting down...", signum)
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    monitor.run()


if __name__ == "__main__":
    main()
