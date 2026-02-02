# Ransomware Detection System

A behavioral ransomware detection system that monitors file system activity in real time, detects encryption patterns through Shannon entropy analysis, and provides automated response with backup and rollback capabilities. Built as an MSci Computer Science with Cyber Security project.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Web Dashboard](#web-dashboard)
- [API Reference](#api-reference)
- [Detection Logic](#detection-logic)
- [Response System](#response-system)
- [Testing](#testing)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)

## Features

- **Real-Time File Monitoring** -- Watches configured directories for file creation, modification, deletion, and renaming using the watchdog library. Tracks the responsible process via psutil.
- **Shannon Entropy Analysis** -- Measures file content randomness to detect encryption. Normal text files have entropy around 4-5 bits/byte; encrypted files approach 7.9-8.0 bits/byte.
- **Behavioral Pattern Detection** -- Identifies six ransomware indicators: mass file modification, entropy spikes, extension manipulation, directory traversal, suspicious processes, and delete-create patterns.
- **Weighted Threat Scoring** -- Combines indicator weights into a 0-100 score with four confidence levels (Normal, Suspicious, Likely, Critical) to minimize false positives.
- **Automated Response Engine** -- Four escalation levels from passive monitoring to process termination, with a safe mode requiring user confirmation before destructive actions.
- **Copy-on-Write Backup System** -- Automatic file snapshots with SHA-256 integrity verification, 48-hour retention, and one-click recovery.
- **Web Dashboard** -- Real-time monitoring interface with live event feed, threat history, file recovery, configuration management, and statistics via Chart.js visualizations.
- **WebSocket Live Updates** -- Push-based notifications for events, threats, and restore operations via the `/ws/live` endpoint.

## Architecture

The system follows a modular, event-driven architecture with four layers. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full details.

```
File System Events
       |
       v
+------------------+     +---------------+     +------------------+
|  File Monitor    | --> | Event Logger  | --> | SQLite Database  |
|  (watchdog)      |     | (thread-safe) |     | (WAL mode)       |
+------------------+     +---------------+     +------------------+
       |                                              |
       v                                              v
+------------------+     +---------------+     +------------------+
| Process Tracker  |     |   Entropy     |     |    Behavior     |
| (psutil)         |     |   Analyzer    |     |    Analyzer     |
+------------------+     +---------------+     +------------------+
                                |                     |
                                v                     v
                         +----------------------------------+
                         |        Threat Scorer             |
                         |  (weighted indicator scoring)    |
                         +----------------------------------+
                                      |
                                      v
                         +----------------------------------+
                         |       Response Engine            |
                         | Level 1: Monitor & Log           |
                         | Level 2: Warn & Backup           |
                         | Level 3: Quarantine (suspend)    |
                         | Level 4: Terminate & Rollback    |
                         +----------------------------------+
                           |            |            |
                           v            v            v
                      Alert        Backup       Process
                      System       Manager      Controller
                                      |
                                      v
                              Recovery Manager
                                      |
                                      v
                              Web Dashboard
                         (Flask + WebSocket)
```

### Data Flow

1. A file operation occurs in a monitored directory
2. The watchdog observer captures the event with process metadata
3. The event is logged to the SQLite database
4. The entropy analyzer computes Shannon entropy for modified files
5. The behavior analyzer aggregates patterns within a sliding time window
6. The threat scorer calculates a weighted score from triggered indicators
7. If the score exceeds the action threshold (71+), the response engine acts
8. The dashboard receives updates via WebSocket and REST polling

## Project Structure

```
.
|-- config/
|   +-- config.json              # Main configuration file
|-- data/                        # Runtime databases (auto-created)
|-- docs/                        # Phase documentation
|-- src/
|   |-- monitor/
|   |   +-- file_monitor.py      # Watchdog observer and event handler
|   |-- analysis/
|   |   |-- entropy_analyzer.py  # Shannon entropy calculation
|   |   |-- entropy_detector.py  # Baseline tracking and spike detection
|   |   |-- pattern_detector.py  # Six behavioral indicator detectors
|   |   |-- threat_scoring.py    # Weighted scoring algorithm
|   |   +-- behavior_analyzer.py # Entry point for analysis pipeline
|   |-- database/
|   |   +-- event_logger.py      # Thread-safe SQLite event storage
|   |-- response/
|   |   |-- response_engine.py   # Four-level escalation logic
|   |   |-- process_controller.py# Process suspend/terminate/block
|   |   |-- alert_system.py      # Notification alerts
|   |   |-- backup_manager.py    # Backup orchestration
|   |   |-- backup_config.py     # Retention and vault settings
|   |   |-- snapshot_service.py  # File versioning with SHA-256
|   |   |-- recovery_manager.py  # File restore with integrity checks
|   |   +-- recovery_workflow.py # Incident reports and batch restore
|   +-- dashboard/
|       |-- app.py               # Flask application factory
|       |-- websocket_handler.py # WebSocket broadcast handler
|       |-- api/
|       |   +-- routes.py        # REST API endpoints
|       |-- templates/
|       |   +-- index.html       # Single-page dashboard UI
|       +-- static/
|           |-- css/dashboard.css
|           +-- js/dashboard.js
|-- tests/                       # 412 tests across 13 test files
+-- requirements.txt
```

## Installation

### Prerequisites

- Python 3.10 or later
- pip package manager

### Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/NickEvans4130/Ransomware-Detection-System.git
    cd Ransomware-Detection-System
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    venv\Scripts\activate     # Windows
    ```

3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Dependencies

| Package     | Version  | Purpose                           |
|-------------|----------|-----------------------------------|
| watchdog    | >= 3.0.0 | File system event monitoring      |
| psutil      | >= 5.9.0 | Process tracking and management   |
| numpy       | >= 1.24.0| Shannon entropy calculation       |
| Flask       | >= 3.0.0 | Web dashboard backend             |
| flask-sock  | >= 0.7.0 | WebSocket support                 |

For testing, also install:
```bash
pip install pytest cryptography
```

## Configuration

The system is configured through `config/config.json`. All paths support environment variables and `~` expansion.

```json
{
    "monitor": {
        "watch_directories": [
            "~/Documents",
            "~/Desktop",
            "~/Downloads"
        ],
        "exclude_directories": [
            "/proc", "/sys", "/dev", "/run",
            "__pycache__", ".git", "node_modules"
        ],
        "file_extension_filter": [],
        "recursive": true
    },
    "entropy": {
        "baseline_db_path": "data/entropy_baselines.db",
        "delta_threshold": 2.0
    },
    "database": {
        "path": "data/events.db"
    },
    "logging": {
        "level": "INFO"
    }
}
```

### Configuration Options

**monitor**
- `watch_directories` -- List of directories to monitor. Supports `~` and environment variables.
- `exclude_directories` -- Paths to ignore. Any path containing these strings is skipped.
- `file_extension_filter` -- If non-empty, only files with these extensions are tracked. Empty means all files.
- `recursive` -- Whether to monitor subdirectories.

**entropy**
- `baseline_db_path` -- SQLite database storing per-file entropy baselines.
- `delta_threshold` -- Minimum entropy change (bits/byte) to flag as suspicious. Default 2.0 covers the typical gap between text (~4.5) and encrypted data (~7.9).

**database**
- `path` -- Path to the event log SQLite database.

**logging**
- `level` -- Python logging level: `DEBUG`, `INFO`, `WARNING`, or `ERROR`.

## Usage

### Quick Start (Recommended)

Run the unified launcher to start both the monitor and dashboard together:

```bash
python run.py
```

Open **http://localhost:5000** in your browser. The monitor watches directories in the background while the dashboard serves on the main thread.

```bash
# Custom port and config
python run.py --port 8080 --config /path/to/config.json

# Monitor only (no dashboard)
python run.py --monitor-only

# Dashboard only (no file monitoring)
python run.py --dashboard-only
```

### Running Components Separately

```bash
# Terminal 1: File monitor
python -m src.monitor

# Terminal 2: Web dashboard
python -m src.dashboard
```

The monitor and dashboard communicate through the shared SQLite database.

### Demo Mode

The system includes a built-in demo that simulates a ransomware attack through the full detection pipeline. No real malware is involved -- the demo creates temporary files in `/tmp/ransomware_demo/` and feeds synthetic events through the analysis engine.

**From the dashboard:** Click the **Run Demo** button in the navbar. The demo runs four phases (normal activity, suspicious activity, ransomware attack, recovery) and you can watch events appear in the live feed, threat scores rise, and the response engine fire.

**From the command line:**

```bash
# Start a demo (polls until complete)
python -m src.demo.simulate

# Run at 2x speed
python -m src.demo.simulate --speed 2.0

# Stop a running demo
python -m src.demo.simulate --stop
```

**Demo API endpoints:**

| Method | Endpoint            | Description                     |
|--------|---------------------|---------------------------------|
| POST   | `/api/demo/start`   | Start demo (optional `{"speed": 1.0}`) |
| POST   | `/api/demo/stop`    | Stop a running demo             |
| GET    | `/api/demo/status`  | Current demo status and progress |

### CLI Flags

| Flag              | Applies To       | Default       | Description                    |
|-------------------|------------------|---------------|--------------------------------|
| `-c` / `--config` | All              | `config/config.json` | Path to configuration file |
| `--host`          | Dashboard / run.py | `127.0.0.1` | Network interface to bind to   |
| `--port`          | Dashboard / run.py | `5000`      | Port for the web dashboard     |
| `--log-level`     | All              | `INFO`        | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--monitor-only`  | run.py           | off           | Run only the file monitor      |
| `--dashboard-only`| run.py           | off           | Run only the web dashboard     |

## Web Dashboard

The dashboard provides five main views accessible via tabs:

### Monitor Tab
- Live scrolling feed of file system events (create, modify, delete, move)
- Current system threat level indicator (Normal / Elevated / Critical)
- List of actively monitored processes with their threat scores

### Threats Tab
- Table of detected threats with severity, process name, score, and timestamp
- Click any threat for full details including triggered indicators and actions taken
- Filter by severity level and date range

### Recovery Tab
- Browse all available file backups sorted by date
- Search for specific files by path
- Restore individual files or batch restore by process name
- Verify file integrity via SHA-256 checksums

### Config Tab
- Add or remove monitored directories
- Adjust detection thresholds (entropy delta, mass modification count)
- Manage the process whitelist
- Changes are saved to `config.json` and applied on next restart

### Statistics Tab
- Four Chart.js visualizations:
  - Events by type (bar chart)
  - Threat level distribution (doughnut chart)
  - Activity timeline (line chart)
  - Top processes by event count (horizontal bar)

## API Reference

All endpoints are prefixed with `/api`.

| Method | Endpoint          | Description                          |
|--------|-------------------|--------------------------------------|
| GET    | `/api/status`     | System status, threat level, active processes |
| GET    | `/api/events`     | Recent file events (paginated via `limit` and `offset` params) |
| GET    | `/api/threats`    | Threat history (filter by `severity`, `since`) |
| POST   | `/api/quarantine` | Suspend a process by PID (`{"pid": 1234}`) |
| GET    | `/api/backups`    | List backups (filter by `path`, `process`, `since`) |
| POST   | `/api/restore`    | Restore files (`{"backup_id": 1}`, `{"backup_ids": [1,2]}`, or `{"process_name": "..."}`) |
| GET    | `/api/config`     | Current configuration                |
| PUT    | `/api/config`     | Update configuration (merge)         |
| POST   | `/api/demo/start` | Start demo simulation (optional `{"speed": 1.0}`) |
| POST   | `/api/demo/stop`  | Stop a running demo                  |
| GET    | `/api/demo/status` | Demo status (`running`, `phase`, `progress`) |
| WS     | `/ws/live`        | WebSocket for real-time event streaming |

### WebSocket Messages

The `/ws/live` endpoint pushes JSON messages with a `type` field:

- `event` -- New file system event
- `threat` -- Threat score update
- `quarantine` -- Process quarantine result
- `restore` -- File restore result
- `config_updated` -- Configuration change

## Detection Logic

### Shannon Entropy

The system calculates Shannon entropy using the formula:

```
H(X) = -sum(p(x) * log2(p(x)))
```

where `p(x)` is the frequency of each byte value in the file. Results range from 0 (uniform) to 8.0 (maximum randomness). Only the first 1KB of each file is sampled for performance.

- Plain text: typically 3.5-5.0 bits/byte
- Compressed files (zip, jpg): typically 7.0-7.8 bits/byte
- Encrypted files: typically 7.9-8.0 bits/byte

The entropy detector maintains baselines per file and flags changes exceeding the `delta_threshold` (default 2.0 bits/byte).

### Behavioral Indicators

Six indicators are evaluated within a sliding time window (default 60 seconds):

| Indicator               | Weight | Trigger Condition                          |
|-------------------------|--------|--------------------------------------------|
| Mass Modification       | 25     | Many files modified rapidly by one process |
| Entropy Spike           | 30     | Multiple files show large entropy increases|
| Extension Manipulation  | 25     | File extensions changed (e.g., .docx to .encrypted) |
| Directory Traversal     | 10     | Process modifies files across many directories |
| Suspicious Process      | 10     | Process name/behavior matches known patterns |
| Deletion Pattern        | 20     | Files deleted and replaced with new files  |

### Threat Levels

| Score  | Level      | Description                         |
|--------|------------|-------------------------------------|
| 0-30   | NORMAL     | Normal activity, no action          |
| 31-50  | SUSPICIOUS | Monitor closely, increase logging   |
| 51-70  | LIKELY     | Likely threat, prepare response     |
| 71-100 | CRITICAL   | Immediate action required           |

Indicator weights sum to 120 (intentionally above 100) so that a combination of several strong indicators crosses the action threshold. The final score is clamped to 100.

## Response System

When a threat score reaches 71 or higher, the response engine escalates through four levels. See [docs/PHASE5_RESPONSE_SYSTEM.md](docs/PHASE5_RESPONSE_SYSTEM.md) for full details.

| Level | Score Range | Actions                                             |
|-------|-------------|-----------------------------------------------------|
| 1     | 31-50       | Detailed logging, increased monitoring frequency    |
| 2     | 51-70       | Warning alerts, emergency backup snapshots          |
| 3     | 71-85       | Process suspended, write access blocked, critical alert |
| 4     | 86-100      | Process terminated, executable blocked, automatic rollback, incident report |

### Safe Mode

When enabled, Levels 3 and 4 require explicit user confirmation before process suspension or termination. Pending actions can be confirmed or denied through the dashboard or API.

### Backup System

- **Vault location**: `~/.ransomware_detection/backup_vault/` (owner-only permissions 0700)
- **Retention**: 48 hours (configurable)
- **Integrity**: SHA-256 checksums on all backup copies
- **Recovery**: Restore individual files, batch by backup ID list, or all files associated with a process
- **Disk space**: Backups are skipped if free space drops below 100 MB

## Testing

The project includes 412 tests across 13 test files.

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_phase7_unit.py -v          # Unit tests (108 tests)
python -m pytest tests/test_phase7_integration.py -v   # Integration tests (18 tests)
python -m pytest tests/test_ransomware_simulation.py -v # Ransomware simulation (11 tests)
python -m pytest tests/test_phase7_performance.py -v   # Performance benchmarks (16 tests)
python -m pytest tests/test_phase7_false_positives.py -v # False positive tests (26 tests)
```

### Test Categories

**Unit Tests** -- Cover every public class and function across all modules: entropy calculation, pattern detection, threat scoring, event logging, backup/restore, process control, alerts, response engine, and WebSocket handling.

**Integration Tests** -- End-to-end pipelines: detection through response through recovery, multi-process tracking, concurrent database access, edge cases (missing directories, corrupted backups, special characters), and dashboard API state verification.

**Simulated Ransomware Tests** -- Use Fernet symmetric encryption to simulate ransomware in an isolated temp directory. Verify that encryption is detected, the behavior analyzer reaches CRITICAL, the response engine triggers quarantine, and files are fully recoverable from backup.

**Performance Tests** -- Verify the system meets documented targets:
- Detection latency: < 2 seconds for 100 events
- Backup overhead: < 100ms per file
- Database inserts: < 10ms per event
- API response times: < 50ms per request

**False Positive Tests** -- Simulate legitimate software behavior (document editing, archive extraction, backup tools, antivirus scanning, system updates, photo editing) and verify none trigger action-required threat scores.

### Performance Targets

| Metric                  | Target      | Verified |
|-------------------------|-------------|----------|
| Detection latency       | < 2 seconds | Yes      |
| False positive rate     | < 5%        | Yes (0%) |
| Backup per file         | < 100ms     | Yes      |
| Recovery success rate   | 100%        | Yes      |
| API response time       | < 50ms      | Yes      |

## Deployment

This system monitors local file system events and local processes, so it must run on the machine it protects. A cloud deployment is not applicable -- this is the same architecture used by commercial endpoint security tools (CrowdStrike, Windows Defender, etc.).

### Linux (systemd)

Run as a persistent background service that starts on login:

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/ransomware-detection.service << 'EOF'
[Unit]
Description=Ransomware Detection System
After=network.target

[Service]
Type=simple
WorkingDirectory=%h/Desktop/test
ExecStart=%h/Desktop/test/venv/bin/python run.py --host 127.0.0.1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable ransomware-detection
systemctl --user start ransomware-detection
```

Keep it running after logout: `loginctl enable-linger $USER`

View logs: `journalctl --user -u ransomware-detection -f`

### Windows (Task Scheduler)

Create a `start_monitor.bat` in the project folder, then add it to Task Scheduler with trigger "When I log on":

```bat
@echo off
cd /d "%~dp0"
call venv\Scripts\activate.bat
python run.py --host 127.0.0.1
```

### Remote Dashboard Access

To access the dashboard from other devices on the same network, bind to all interfaces:

```bash
python run.py --host 0.0.0.0
```

Then open `http://<machine-ip>:5000` from any device on the network. Only use this on trusted networks -- the dashboard has no authentication.

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md#12-deployment) for full deployment instructions including macOS launchd and split service configurations.

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for solutions to common issues including:

- **Permission denied errors** -- Run with appropriate file system permissions or adjust `watch_directories`.
- **High CPU usage** -- Add noisy directories to `exclude_directories`. Reduce the number of watched paths.
- **Database locked errors** -- The system uses WAL journal mode and thread-local connections. Ensure no external processes hold the database open.
- **Disk space warnings** -- Backups are skipped automatically below 100 MB free. Reduce `RETENTION_HOURS` or run manual cleanup.
- **False positives** -- Increase `delta_threshold` in the entropy config, or add trusted process names to the whitelist.

## Documentation

Detailed phase-by-phase documentation is in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md) | Project goals, tech stack, success criteria |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and data flow |
| [PHASE1_FILE_MONITOR.md](docs/PHASE1_FILE_MONITOR.md) | File system monitoring with watchdog |
| [PHASE2_ENTROPY_ANALYSIS.md](docs/PHASE2_ENTROPY_ANALYSIS.md) | Shannon entropy engine |
| [PHASE3_BEHAVIORAL_DETECTION.md](docs/PHASE3_BEHAVIORAL_DETECTION.md) | Pattern detection and threat scoring |
| [PHASE4_BACKUP_SYSTEM.md](docs/PHASE4_BACKUP_SYSTEM.md) | Copy-on-write backup and recovery |
| [PHASE5_RESPONSE_SYSTEM.md](docs/PHASE5_RESPONSE_SYSTEM.md) | Automated four-level response |
| [PHASE6_WEB_DASHBOARD.md](docs/PHASE6_WEB_DASHBOARD.md) | Web dashboard and API |
| [PHASE7_TESTING.md](docs/PHASE7_TESTING.md) | Testing strategy and refinement checklist |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Full user guide with deployment instructions |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
