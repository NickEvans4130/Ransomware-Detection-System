"""Unified launcher for the Ransomware Detection System.

Starts both the file monitor and web dashboard in a single process.
The monitor runs in a background thread while the Flask dashboard
runs on the main thread.

Usage:
    python run.py
    python run.py --config config/config.json --port 5000
    python run.py --monitor-only
    python run.py --dashboard-only
"""

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = str(PROJECT_ROOT / "config" / "config.json")

logger = logging.getLogger("ransomware_detection")


def run_monitor(config_path, stop_event):
    """Run the file monitor in a thread until stop_event is set."""
    from src.monitor.file_monitor import FileMonitor

    monitor = FileMonitor(config_path=config_path)
    monitor.start()
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    finally:
        monitor.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Detection System",
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG,
        help="Path to config.json (default: config/config.json)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Dashboard host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        default=5000,
        type=int,
        help="Dashboard port (default: 5000)",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )
    parser.add_argument(
        "--monitor-only",
        action="store_true",
        help="Run only the file monitor (no dashboard)",
    )
    parser.add_argument(
        "--dashboard-only",
        action="store_true",
        help="Run only the web dashboard (no monitor)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.monitor_only and args.dashboard_only:
        parser.error("Cannot use --monitor-only and --dashboard-only together")

    stop_event = threading.Event()

    def handle_signal(signum, frame):
        logger.info("Received signal %s, shutting down...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Monitor only
    if args.monitor_only:
        from src.monitor.file_monitor import FileMonitor
        logger.info("Starting file monitor (no dashboard)...")
        monitor = FileMonitor(config_path=args.config)
        monitor.start()
        try:
            while not stop_event.is_set():
                stop_event.wait(timeout=1.0)
        finally:
            monitor.stop()
        return

    # Dashboard only
    if args.dashboard_only:
        from src.dashboard.app import create_app
        logger.info("Starting dashboard (no monitor)...")
        app = create_app(config_path=args.config)
        app.run(host=args.host, port=args.port, debug=False)
        return

    # Both: monitor in background thread, dashboard on main thread
    logger.info("Starting Ransomware Detection System...")
    logger.info("  Monitor: watching configured directories")
    logger.info("  Dashboard: http://%s:%d", args.host, args.port)

    monitor_thread = threading.Thread(
        target=run_monitor,
        args=(args.config, stop_event),
        daemon=True,
        name="file-monitor",
    )
    monitor_thread.start()

    from src.dashboard.app import create_app
    app = create_app(config_path=args.config)

    try:
        app.run(host=args.host, port=args.port, debug=False)
    finally:
        stop_event.set()
        monitor_thread.join(timeout=5)
        logger.info("System stopped.")


if __name__ == "__main__":
    main()
