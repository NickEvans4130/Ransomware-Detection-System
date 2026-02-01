# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Git Workflow

- After completing each change, create or use an appropriate feature branch (`feat/...`, `fix/...`, `refactor/...`). Never commit directly to main/master.
- Run `git fetch origin` and ensure the branch is up to date before committing.
- Commit with a concise, relevant message. No emojis, no Claude attribution (no "Co-Authored-By" lines).
- Push the branch to origin after committing.
- No emojis anywhere: not in commits, not in code, not in documentation.

## Project

Behavioral ransomware detection system (MSci Computer Science with Cyber Security). Monitors file system activity, detects encryption patterns via entropy analysis, and provides automated backup/rollback. This is a **defensive security tool**, not malware.

## Tech Stack

Python 3.10+, watchdog (FS monitoring), psutil (process tracking), numpy (entropy), Flask (dashboard), SQLite (event logging). Virtual environment in `venv/`.

## Commands

```bash
# Activate venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Run a single test
python -m pytest tests/test_file_monitor.py -v

# Start the monitor (CLI)
python -m src.monitor.file_monitor

# Start the web dashboard
python -m src.dashboard

# Enable debug logging
LOG_LEVEL=DEBUG python -m src.monitor.file_monitor
```

## Architecture

Event-driven pipeline with four layers:

1. **Monitoring** (`src/monitor/`) - watchdog file event capture + psutil process attribution
2. **Analysis** (`src/analysis/`) - entropy calculation (first 1KB sampling) and behavioral pattern detection with threat scoring
3. **Response** (`src/response/`) - process killing, alerting, backup/recovery management
4. **Dashboard** (`src/dashboard/`) - Flask web UI on port 5000

All events flow through `src/database/` (SQLite). Events are processed asynchronously with time-windowed aggregation.

## Key Design Decisions

- Entropy is calculated on first 1KB only (performance)
- Backup vault must be on a separate volume from monitored files
- Monitored directories and thresholds configured via `config/` JSON files
- Whitelisting legitimate processes to reduce false positives
- Target: detection within 2 seconds, false positive rate < 5%

## Project Phases (in docs/)

Detailed specs for each phase live in `docs/PHASE1_FILE_MONITOR.md` through `docs/PHASE7_TESTING.md`. Always read the relevant phase doc before implementing.
