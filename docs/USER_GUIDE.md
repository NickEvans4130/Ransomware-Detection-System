# User Guide

This guide walks you through setting up, configuring, and using the Ransomware Detection System. It is written for users who may not have deep experience with Python or security tooling -- every step is explained from scratch.

## Table of Contents

1. [What This System Does](#1-what-this-system-does)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Starting the System](#5-starting-the-system)
6. [Using the Dashboard](#6-using-the-dashboard)
7. [Understanding Threat Alerts](#7-understanding-threat-alerts)
8. [Responding to Threats](#8-responding-to-threats)
9. [Recovering Files](#9-recovering-files)
10. [Tuning Detection Settings](#10-tuning-detection-settings)
11. [Running Tests](#11-running-tests)
12. [Troubleshooting](#12-troubleshooting)
13. [Glossary](#13-glossary)

---

## 1. What This System Does

The Ransomware Detection System monitors folders on your computer for suspicious activity that looks like ransomware. It works in four stages:

1. **Watch** -- A background process watches your Documents, Desktop, and Downloads folders (or any folders you choose) for file changes.
2. **Analyse** -- When files are created, modified, deleted, or renamed, the system measures how "random" the file contents are (entropy) and looks for patterns that ransomware typically exhibits.
3. **Score** -- Each process gets a threat score from 0 to 100. A score of 71 or above means the system is confident enough to take action.
4. **Respond** -- Depending on severity, the system can log the activity, create emergency backups, suspend the suspicious process, or terminate it and roll back your files.

All of this happens in real time. You can watch it unfold in a web dashboard that runs in your browser.

---

## 2. Prerequisites

Before you begin, make sure you have the following installed on your machine.

### Required Software

| Software   | Minimum Version | How to Check          | Installation                     |
|------------|----------------|-----------------------|----------------------------------|
| Python     | 3.10           | `python --version`    | https://www.python.org/downloads |
| pip        | (bundled)      | `pip --version`       | Comes with Python                |
| Git        | any            | `git --version`       | https://git-scm.com              |

### Supported Operating Systems

- **Linux** -- Fully supported. Tested on Fedora and Ubuntu.
- **Windows** -- Fully supported. Use PowerShell or Command Prompt for terminal commands. Where this guide shows `source venv/bin/activate`, use `venv\Scripts\activate` instead.
- **macOS** -- Should work, but not formally tested.

---

## 3. Installation

Follow these steps exactly. Each command is shown with what it does.

### Step 1: Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/NickEvans4130/Ransomware-Detection-System.git
cd Ransomware-Detection-System
```

This downloads the project to your machine and moves you into the project folder.

### Step 2: Create a Virtual Environment

A virtual environment keeps this project's packages separate from your system Python. This avoids version conflicts with other projects.

```bash
python -m venv venv
```

This creates a `venv/` folder inside the project directory.

### Step 3: Activate the Virtual Environment

**Linux / macOS:**
```bash
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat
```

You will see `(venv)` at the start of your terminal prompt. This means the virtual environment is active. You need to activate it every time you open a new terminal to work on this project.

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs five packages:

| Package     | What It Does                                           |
|-------------|--------------------------------------------------------|
| watchdog    | Monitors folders for file changes                      |
| psutil      | Identifies which process made each file change         |
| numpy       | Used for Shannon entropy calculation                   |
| Flask       | Runs the web dashboard server                          |
| flask-sock  | Adds WebSocket support so the dashboard updates live   |

### Step 5: Install Test Dependencies (Optional)

If you plan to run the test suite:

```bash
pip install pytest cryptography
```

`pytest` is the test runner. `cryptography` provides the Fernet encryption used in the simulated ransomware tests.

### Step 6: Verify the Installation

Run a quick check:

```bash
python -c "import watchdog, psutil, numpy, flask, flask_sock; print('All dependencies installed.')"
```

If you see `All dependencies installed.` then everything is working.

---

## 4. Configuration

The system reads its settings from `config/config.json`. Open this file in any text editor to customise it.

### Default Configuration

```json
{
    "monitor": {
        "watch_directories": [
            "~/Documents",
            "~/Desktop",
            "~/Downloads"
        ],
        "exclude_directories": [
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "__pycache__",
            ".git",
            "node_modules"
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

### What Each Setting Means

**watch_directories** -- The folders the system monitors. Use `~` as a shortcut for your home directory. Add or remove folders to match what you want to protect.

Example: to also watch a `Projects` folder:
```json
"watch_directories": [
    "~/Documents",
    "~/Desktop",
    "~/Downloads",
    "~/Projects"
]
```

**exclude_directories** -- Folders to ignore. This is important for avoiding noise from system folders, build caches, and version control metadata. If you use a tool that creates a lot of temporary files (like a build system), add its output directory here.

**file_extension_filter** -- When empty (the default), all files are monitored. To only monitor certain types, list their extensions:
```json
"file_extension_filter": [".docx", ".xlsx", ".pdf", ".jpg", ".png"]
```

**recursive** -- When `true`, subdirectories within your watched folders are also monitored. Leave this as `true` unless you have a specific reason not to.

**delta_threshold** -- The minimum entropy change (in bits per byte) needed to flag a file as suspicious. The default of 2.0 works well for most cases:
- A normal text file has entropy around 4.5 bits/byte
- An encrypted file has entropy around 7.9 bits/byte
- The difference is about 3.4, which is above the 2.0 threshold

Only increase this if you get false positives from compressed files. Only decrease it if you want more sensitive detection.

**database.path** -- Where the event database is stored. The default `data/events.db` is fine. The `data/` directory is created automatically.

**logging.level** -- Controls how much detail appears in the terminal:
- `DEBUG` -- Everything, including individual event processing. Useful for development.
- `INFO` -- Normal operation messages. Recommended for everyday use.
- `WARNING` -- Only potential problems.
- `ERROR` -- Only actual errors.

---

## 5. Starting the System

The system has two components that run in separate terminal windows: the **file monitor** and the **web dashboard**. The monitor detects threats; the dashboard lets you see what is happening and take action.

### Starting the File Monitor

Open a terminal, activate the virtual environment, then run:

```bash
python -m src.monitor.file_monitor
```

You will see output like:
```
2025-02-01 14:30:00 [INFO] src.monitor.file_monitor: Watching: /home/you/Documents (recursive=True)
2025-02-01 14:30:00 [INFO] src.monitor.file_monitor: Watching: /home/you/Desktop (recursive=True)
2025-02-01 14:30:00 [INFO] src.monitor.file_monitor: Watching: /home/you/Downloads (recursive=True)
2025-02-01 14:30:00 [INFO] src.monitor.file_monitor: File monitor started. Watching 3 directories.
```

The monitor is now running. Leave this terminal open. To stop it, press `Ctrl+C`.

**Useful flags:**

| Flag              | Example                           | What It Does                          |
|-------------------|-----------------------------------|---------------------------------------|
| `-c` / `--config` | `--config /path/to/config.json`   | Use a different configuration file    |
| `--log-level`     | `--log-level DEBUG`               | Override the logging level            |

### Starting the Web Dashboard

Open a **second** terminal, activate the virtual environment, then run:

```bash
python -m src.dashboard.app
```

You will see:
```
 * Running on http://127.0.0.1:5000
```

Open your web browser and go to **http://localhost:5000**. The dashboard will appear.

### Quick Start Summary

1. Terminal 1: `python -m src.monitor.file_monitor`
2. Terminal 2: `python -m src.dashboard.app`
3. Browser: `http://localhost:5000`

---

## 6. Using the Dashboard

The dashboard is a single web page with five tabs across the top. Here is what each tab does and how to use it.

### Monitor Tab

This is the default view when you open the dashboard.

**Live Activity Feed** -- A scrolling log of every file event the system detects. Each line shows:
- Timestamp
- Event type (CREATED, MODIFIED, DELETED, MOVED, EXTENSION_CHANGED)
- File path
- Process name and PID responsible

The feed updates automatically via WebSocket. You do not need to refresh the page.

**System Status** -- At the top of the page you will see:
- **Protected** / **Elevated** / **Critical** -- The current overall threat level
- Count of threats detected today

**Monitored Processes** -- A list of processes the system is tracking, each with their current threat score and level (Normal, Suspicious, Likely, Critical). Processes scoring 0-30 show as Normal.

### Threats Tab

Shows a table of all threats the system has detected, sorted newest first.

Each row includes:
- **Timestamp** -- When the threat was detected
- **Process** -- The name and PID of the suspicious process
- **Score** -- The threat score (0-100)
- **Level** -- The confidence level (Suspicious, Likely, Critical)
- **Escalation** -- Which response level was triggered (1-4)
- **Actions** -- What the system did about it

Click any row to see full details, including:
- Which behavioral indicators were triggered (e.g., mass_modification, entropy_spike)
- Every action the response engine took
- The incident report (for Level 4 responses)

You can filter threats by severity level or date range using the controls at the top of the table.

### Recovery Tab

This is where you restore files from backup.

**Browsing Backups** -- The tab shows a list of all backed-up files, sorted by date with the newest first. Each entry shows:
- Original file path
- Backup timestamp
- SHA-256 hash (for verifying integrity)
- Process that triggered the backup

**Restoring a Single File:**
1. Find the file in the list
2. Click the **Restore** button next to it
3. The system copies the backup over the current file and verifies the SHA-256 hash matches
4. A success or failure message appears

**Batch Restore by Process:**
1. Enter a process name in the "Restore by Process" field
2. Click **Restore All**
3. Every file backed up because of that process is restored

**Searching:** Use the search box to filter backups by file path.

### Config Tab

Lets you change system settings without editing the JSON file by hand.

**Monitored Directories** -- Shows the current list. Click the X next to a directory to remove it. Type a path and click Add to add a new one.

**Detection Thresholds** -- Sliders and inputs for:
- Entropy delta threshold (default 2.0)
- Mass modification threshold (how many files trigger the indicator)

**Process Whitelist** -- Add process names that should never trigger a threat. Useful for backup software, antivirus, or build tools that legitimately modify many files.

After making changes, click **Save Configuration**. Changes are written to `config/config.json`. The monitor picks up directory changes when restarted.

### Statistics Tab

Four charts showing system activity at a glance:

- **Events by Type** -- Bar chart showing how many create, modify, delete, and move events have occurred
- **Threat Levels** -- Doughnut chart showing the distribution of threat scores across all tracked processes
- **Activity Timeline** -- Line chart showing event volume over time
- **Top Processes** -- Horizontal bar chart showing which processes generate the most file events

Charts update when you switch to the tab. They provide a useful overview for understanding normal activity patterns on your system.

---

## 7. Understanding Threat Alerts

When the system detects suspicious behaviour, it assigns a threat score based on six indicators. Understanding these helps you decide whether an alert is real or a false positive.

### The Six Indicators

**Mass Modification (weight: 25)** -- A single process modifies many files in a short time. Ransomware encrypts files as fast as possible, so this is a strong signal. Legitimate triggers: backup software, batch file operations.

**Entropy Spike (weight: 30)** -- Multiple files suddenly become much more random (higher entropy). This is the strongest single indicator because encryption turns structured data into near-random bytes. Legitimate triggers: compressing files, converting images to different formats.

**Extension Manipulation (weight: 25)** -- Files are renamed with new extensions like `.encrypted`, `.locked`, or `.crypto`. Ransomware does this to mark which files it has encrypted. Legitimate triggers: batch file renaming, file format conversion tools.

**Directory Traversal (weight: 10)** -- A process modifies files across many different directories. Ransomware typically walks the entire file system. Legitimate triggers: system updates, antivirus scans, search indexers.

**Suspicious Process (weight: 10)** -- The process name or location matches known suspicious patterns (e.g., running from a temp folder). This is a supporting indicator, not strong on its own.

**Deletion Pattern (weight: 20)** -- Files are deleted and immediately replaced with new files. Ransomware often deletes the original after writing the encrypted copy. Legitimate triggers: some save operations that delete-then-write.

### How Scores Work

Each triggered indicator adds its weight to the total. The maximum possible is 120, but the score is capped at 100. This means a combination of several indicators quickly reaches the action threshold:

- **entropy_spike (30) + mass_modification (25) + extension_manipulation (25) = 80** -- This triggers Level 3 (Quarantine).
- **directory_traversal (10) alone = 10** -- This is well within Normal range.
- **mass_modification (25) + directory_traversal (10) = 35** -- Suspicious, but only Level 1 monitoring.

### Threat Levels

| Score  | Level      | What It Means                                    |
|--------|------------|--------------------------------------------------|
| 0-30   | NORMAL     | Routine activity. No action taken.               |
| 31-50  | SUSPICIOUS | Something unusual. System logs extra detail.     |
| 51-70  | LIKELY     | Probably a threat. Emergency backups are created. |
| 71-100 | CRITICAL   | High confidence threat. Process is quarantined.  |

---

## 8. Responding to Threats

When the system detects a threat, it automatically takes actions based on the severity. Here is what happens at each level and what you should do.

### Level 1: Monitor (Score 31-50)

**What the system does:**
- Logs detailed activity for the suspicious process
- Increases monitoring frequency
- Sends a low-priority informational alert

**What you should do:**
1. Check the Threats tab in the dashboard
2. Look at which indicators were triggered
3. If you recognise the process as legitimate (e.g., a backup tool), you can add it to the whitelist in the Config tab
4. If you do not recognise the process, keep an eye on it -- the score may rise

### Level 2: Warn (Score 51-70)

**What the system does:**
- Creates immediate backup snapshots of affected files
- Sends a prominent warning alert
- Logs the full process tree (parent and child processes)
- Prepares for process suspension

**What you should do:**
1. Check the dashboard immediately when you see a warning
2. Look at the affected files and the process name
3. If this is a false positive, add the process to the whitelist
4. If this looks real, you do not need to do anything -- the system will escalate if behaviour continues
5. Your files have been backed up, so even if the threat worsens, recovery is possible

### Level 3: Quarantine (Score 71-85)

**What the system does:**
- Suspends the suspicious process (it is paused, not killed)
- Blocks file system writes from that process
- Creates emergency backups
- Sends a critical alert

**What you should do:**
1. Open the Threats tab and review the incident
2. Check which indicators triggered: if you see entropy_spike + mass_modification + extension_manipulation, this is almost certainly ransomware
3. Check the Recovery tab to see what files were backed up
4. If this is a false positive: the process is only suspended (paused), not terminated. You can resume it through your operating system's process manager
5. If this is real: the process is already contained. Proceed to file recovery (Section 9)

**If safe mode is enabled:** The system will not suspend the process automatically. Instead, it sends a confirmation request. You must click Confirm in the dashboard to proceed, or Deny to cancel the action.

### Level 4: Terminate (Score 86-100)

**What the system does:**
- Terminates (kills) the process immediately
- Blocks the executable from running again
- Initiates automatic rollback of all files affected by that process
- Generates a full incident report

**What you should do:**
1. The most urgent action is already done -- the process is stopped
2. Check the incident report in the Threats tab for a complete summary
3. Verify that the automatic rollback restored your files correctly in the Recovery tab
4. If some files were not restored automatically, use the Recovery tab to restore them manually (see Section 9)
5. Consider reporting the executable to your IT department or antivirus vendor

**If safe mode is enabled:** Termination requires your confirmation. The system sends a prompt -- click Confirm to proceed or Deny to cancel.

### A Note on Safe Mode

Safe mode is useful when you are first setting up the system or if you want to verify every action before it happens. To enable it, add to your `config/config.json`:

```json
{
    "response": {
        "safe_mode": true
    }
}
```

In safe mode, Level 1 and Level 2 actions still happen automatically (they are non-destructive). Levels 3 and 4 require your explicit confirmation.

---

## 9. Recovering Files

If ransomware encrypts your files, the backup system lets you restore them to their original state. There are several ways to do this.

### Method 1: Restore a Single File (Dashboard)

1. Open the dashboard at **http://localhost:5000**
2. Click the **Recovery** tab
3. Browse or search for the file you want to restore
4. Click the **Restore** button next to the file
5. The system restores the file and verifies its SHA-256 checksum
6. A green success message confirms the restore, or a red message explains what went wrong

### Method 2: Restore All Files Affected by a Process (Dashboard)

This is the fastest way to undo damage from a specific threat.

1. Go to the **Recovery** tab
2. Enter the process name in the "Restore by Process" field (e.g., `ransomware.exe` or `attacker`)
3. Click **Restore All**
4. The system finds every file that was backed up because of that process and restores them all
5. A summary shows how many files were restored successfully

### Method 3: Restore via the API

If the dashboard is not available, you can use the REST API directly with curl:

**Restore a single file by backup ID:**
```bash
curl -X POST http://localhost:5000/api/restore \
  -H "Content-Type: application/json" \
  -d '{"backup_id": 42}'
```

**Restore multiple files by backup ID:**
```bash
curl -X POST http://localhost:5000/api/restore \
  -H "Content-Type: application/json" \
  -d '{"backup_ids": [42, 43, 44, 45]}'
```

**Restore all files for a process:**
```bash
curl -X POST http://localhost:5000/api/restore \
  -H "Content-Type: application/json" \
  -d '{"process_name": "suspicious_process"}'
```

**List available backups:**
```bash
curl http://localhost:5000/api/backups
```

**Filter backups by original path:**
```bash
curl "http://localhost:5000/api/backups?path=/home/you/Documents/report.docx"
```

### How Backup Integrity Works

Every time the system backs up a file, it calculates a SHA-256 hash of the backup copy. When you restore:

1. The backup copy is written to the original location
2. The system calculates the SHA-256 hash of the restored file
3. It compares this hash with the hash stored at backup time
4. If they match, the restore is marked as successful with `integrity_ok: true`
5. If they do not match, the file is still restored but the integrity check is flagged as failed -- this can indicate disk corruption

### Where Backups Are Stored

Backups live in a hidden folder in your home directory:

```
~/.ransomware_detection/backup_vault/
```

The structure inside looks like:

```
backup_vault/
|-- 2025-02-01_14-30-00/
|   |-- home_you_Documents_report.docx
|   |-- home_you_Desktop_photo.jpg
|   +-- metadata.json
|-- 2025-02-01_14-31-15/
|   +-- ...
+-- index.db
```

Each timestamped folder contains copies of files backed up at that time. The `metadata.json` file records what each backup contains. The `index.db` SQLite database tracks all backups for fast querying.

### Backup Retention

Backups older than 48 hours are automatically eligible for cleanup. This prevents the backup vault from consuming too much disk space. If you need to keep backups longer, you can copy the vault folder to an external drive.

### What If Backups Were Not Created?

Backups are created at two points:
- **Level 2 (score 51-70):** When a process looks suspicious, the system pre-emptively backs up files it has been touching
- **Level 3-4 (score 71+):** Emergency backups of all affected files

If a threat jumps straight to Level 3 or 4 without passing through Level 2 first, the emergency backup still captures everything. However, if a file was encrypted before the system detected the threat, the backup will contain the encrypted version.

The best protection is to run the monitor continuously so the system can detect suspicious patterns early (at Level 2) and back up files before they are encrypted.

---

## 10. Tuning Detection Settings

If you experience false positives (legitimate software flagged as ransomware) or false negatives (actual threats not detected), you can adjust the detection sensitivity.

### Reducing False Positives

**Add processes to the whitelist:**

Open the Config tab in the dashboard or edit `config/config.json`:
```json
{
    "response": {
        "process_whitelist": ["7z.exe", "backup_agent", "rsync"]
    }
}
```

**Increase the entropy threshold:**

If compressed file operations trigger false alerts, raise the entropy delta threshold from 2.0 to 2.5 or 3.0:
```json
{
    "entropy": {
        "delta_threshold": 2.5
    }
}
```

This means a file must show a larger entropy change before it is flagged.

**Exclude noisy directories:**

If a specific folder generates many events (e.g., a build output folder), add it to the exclude list:
```json
{
    "monitor": {
        "exclude_directories": [
            "__pycache__", ".git", "node_modules",
            "build", "dist", ".cache"
        ]
    }
}
```

### Increasing Sensitivity

**Lower the entropy threshold:**

Set `delta_threshold` to 1.5 for more sensitive detection. This will catch smaller entropy changes but may increase false positives.

**Monitor more directories:**

Add additional folders to `watch_directories`.

### Recommended Settings for Common Scenarios

**Development machine** (lots of build tools, compilers, etc.):
```json
{
    "entropy": { "delta_threshold": 2.5 },
    "monitor": {
        "exclude_directories": [
            "__pycache__", ".git", "node_modules",
            "target", "build", "dist", ".cache", ".tox"
        ]
    }
}
```

**Office workstation** (mostly documents and email):
```json
{
    "entropy": { "delta_threshold": 2.0 },
    "monitor": {
        "watch_directories": ["~/Documents", "~/Desktop", "~/Downloads"],
        "file_extension_filter": [
            ".docx", ".xlsx", ".pptx", ".pdf",
            ".jpg", ".png", ".txt", ".csv"
        ]
    }
}
```

**Maximum sensitivity** (security testing or honeypot):
```json
{
    "entropy": { "delta_threshold": 1.5 },
    "monitor": {
        "watch_directories": ["/home"],
        "recursive": true,
        "file_extension_filter": []
    }
}
```

---

## 11. Running Tests

The project includes 412 automated tests. Running them is a good way to verify everything is installed correctly.

### Running All Tests

```bash
python -m pytest tests/ -v
```

This runs every test and shows each one as it passes or fails. Expect all 412 to pass. The full suite runs in about 30-35 seconds.

### Running Specific Test Categories

If you only want to run certain types of tests:

**Unit tests** (108 tests -- test individual functions and classes):
```bash
python -m pytest tests/test_phase7_unit.py -v
```

**Integration tests** (18 tests -- test components working together):
```bash
python -m pytest tests/test_phase7_integration.py -v
```

**Simulated ransomware tests** (11 tests -- verify detection of Fernet encryption):
```bash
python -m pytest tests/test_ransomware_simulation.py -v
```

**Performance tests** (16 tests -- verify speed targets are met):
```bash
python -m pytest tests/test_phase7_performance.py -v
```

**False positive tests** (26 tests -- verify legitimate software is not flagged):
```bash
python -m pytest tests/test_phase7_false_positives.py -v
```

### What the Tests Verify

| Category              | What It Checks                                             | Pass Criteria          |
|-----------------------|------------------------------------------------------------|------------------------|
| Unit tests            | Every function produces correct output for known inputs    | All assertions pass    |
| Integration tests     | Full detect-respond-recover pipeline works end to end      | All assertions pass    |
| Ransomware simulation | Fernet-encrypted files are detected and recoverable        | Detection within 2s    |
| Performance           | System meets speed targets under load                      | All timings under limits|
| False positives       | Simulated Word, 7-Zip, backup, antivirus, etc. are not flagged | No action_required  |

### If a Test Fails

1. Read the failure message -- it will tell you which assertion failed and why
2. Check that all dependencies are installed (`pip install -r requirements.txt`)
3. Check that no other process is locking the test database files in `/tmp`
4. Try running the specific failing test in isolation: `python -m pytest tests/test_file.py::TestClass::test_name -v`

---

## 12. Troubleshooting

### The Monitor Starts but Detects No Events

**Check your directories.** Open `config/config.json` and verify that the paths in `watch_directories` exist on your machine. Paths use `~` for your home directory, which should work on both Linux and Windows.

```bash
# Check if the directories exist
ls ~/Documents
ls ~/Desktop
ls ~/Downloads
```

**Check permissions.** The monitor needs read access to the directories it watches. On Linux, check with:
```bash
ls -la ~/Documents
```

**Check the logs.** Start the monitor with debug logging to see exactly what it is doing:
```bash
python -m src.monitor.file_monitor --log-level DEBUG
```

**Verify watchdog is installed:**
```bash
pip show watchdog
```

### High CPU Usage

The monitor uses CPU when processing events. If it is using too much:

1. **Add noisy directories to the exclude list.** Folders with frequent automated changes (build outputs, caches, temporary files) generate many events:
   ```json
   "exclude_directories": ["__pycache__", ".git", "node_modules", ".cache", "build"]
   ```

2. **Reduce the number of watched directories.** Only monitor folders that contain files you care about.

3. **Use the file extension filter.** If you only need to protect documents:
   ```json
   "file_extension_filter": [".docx", ".xlsx", ".pdf", ".jpg"]
   ```

### Too Many False Positives

If legitimate software keeps triggering alerts:

1. **Check which process is causing it.** Look at the Threats tab for the process name.
2. **Add it to the whitelist** via the Config tab or in `config.json`.
3. **Raise the entropy threshold** if compressed file operations are the cause (see Section 10).
4. See [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more detail.

### Database Locked Errors

The system uses SQLite in WAL (Write-Ahead Logging) mode with thread-local connections. If you see "database is locked" errors:

1. Make sure you are not opening the database file with another tool (like a SQLite browser) while the monitor is running
2. Check that only one instance of the monitor is running
3. If the problem persists, stop the monitor and dashboard, then restart both

### Dashboard Not Loading

**Check the server is running.** You should see `Running on http://127.0.0.1:5000` in the terminal.

**Check the port.** Make sure port 5000 is not used by another application. On Linux:
```bash
ss -tlnp | grep 5000
```

On macOS, port 5000 is sometimes used by AirPlay Receiver. You may need to disable it in System Preferences or change the Flask port.

**Check browser console.** Open your browser's developer tools (usually F12) and look at the Console tab for JavaScript errors.

**Check database access.** The dashboard needs to read the same database the monitor writes to. If you changed `database.path` in the config, make sure both components use the same config file.

### Cannot Restore Files

**Verify backups exist.** Go to the Recovery tab or call the API:
```bash
curl http://localhost:5000/api/backups
```

**Check the backup vault.** The vault is at `~/.ransomware_detection/backup_vault/`. Check it exists and contains timestamped folders:
```bash
ls -la ~/.ransomware_detection/backup_vault/
```

**Check permissions.** The system needs write access to the original file location to restore a file.

**Check disk space.** If the disk is full, restores will fail. Free up space and try again.

### Disk Space Running Low

Backups can consume disk space over time. The system automatically skips new backups when free space drops below 100 MB.

To free space manually:
1. Old backups (older than 48 hours) can be safely deleted from the vault
2. You can also run SQLite VACUUM on the databases to reclaim unused space:
   ```bash
   python -c "
   from src.database.event_logger import EventLogger
   el = EventLogger('data/events.db')
   el.vacuum()
   el.close()
   print('Done.')
   "
   ```

### Enabling Debug Mode

For maximum diagnostic information:

```bash
python -m src.monitor.file_monitor --log-level DEBUG
```

Or set it in the config:
```json
{
    "logging": {
        "level": "DEBUG"
    }
}
```

Debug mode logs every individual event, every entropy calculation, and every scoring decision. This is very verbose -- only use it when investigating a problem.

---

## 13. Glossary

| Term                   | Definition                                                                                  |
|------------------------|---------------------------------------------------------------------------------------------|
| **Entropy**            | A measure of randomness in data, measured in bits per byte (0-8). Higher entropy means more random. Encrypted files have very high entropy. |
| **Shannon Entropy**    | The specific formula used: H(X) = -sum(p(x) * log2(p(x))). Named after Claude Shannon, the father of information theory. |
| **Baseline**           | The "normal" entropy of a file, measured when it is first seen. Changes are measured against this baseline. |
| **Delta**              | The difference between the current entropy and the baseline. A large delta suggests the file has been encrypted. |
| **Indicator**          | One of six specific patterns that suggest ransomware behaviour (see Section 7). |
| **Threat Score**       | A number from 0 to 100 calculated by adding the weights of all triggered indicators for a process. |
| **Escalation Level**   | One of four response tiers (1-4) determined by the threat score. Higher levels take more aggressive action. |
| **Quarantine**         | Suspending a process so it cannot continue running but is not permanently killed. The process can be resumed if the alert is a false positive. |
| **Safe Mode**          | A setting where Level 3 and 4 actions require user confirmation before executing. |
| **Vault**              | The hidden folder (`~/.ransomware_detection/backup_vault/`) where backup copies of files are stored. |
| **WAL Mode**           | Write-Ahead Logging -- a SQLite journal mode that allows concurrent readers and writers without locking. |
| **Watchdog**           | A Python library that receives notifications from the operating system when files change. |
| **psutil**             | A Python library for retrieving information about running processes (name, PID, resource usage). |
| **Fernet**             | A symmetric encryption scheme from the `cryptography` library, used in the test suite to simulate ransomware. Not used in the production system. |
| **WebSocket**          | A protocol that allows the server to push updates to the browser in real time, without the browser having to poll. |
