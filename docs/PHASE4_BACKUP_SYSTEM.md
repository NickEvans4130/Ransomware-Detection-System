# Phase 4: Backup/Snapshot System

## Objective
Implement copy-on-write backup system that preserves original file versions 
before modifications, enabling rollback.

## Approach Options

### Option A: Simple File Versioning (Recommended for Phase 1)
- Intercept file modifications
- Copy original file to secure backup location before allowing change
- Organize by timestamp and original path
- Retention: 48 hours rolling window

### Option B: OS Snapshot Integration (Advanced)
- Windows: Volume Shadow Copy Service (VSS)
- Linux: LVM snapshots
- Requires elevated privileges

## Requirements

### Core Functionality
1. Pre-modification backup:
   - Detect when file is about to be modified
   - Create backup copy in secure location
   - Maintain directory structure mapping

2. Secure storage:
   - Backup location hidden from user processes
   - Different permissions (system-only access)
   - Encrypted backup directory (optional)

3. Metadata tracking:
   - Original file path
   - Backup timestamp
   - File hash (SHA-256) for integrity
   - Backup reason (suspicious activity, routine, etc.)

### Recovery System
1. File restoration:
   - Browse available backups by time
   - Preview file metadata
   - Restore individual files or entire directories
   - Verify restoration integrity

2. Rollback capabilities:
   - Point-in-time recovery
   - Restore all files modified by specific process
   - Batch restoration

## Technical Implementation

### Backup Structure
backup_vault/
├── 2025-02-01_14-30-00/
│   ├── C_Users_student_Documents_report.docx
│   ├── C_Users_student_Desktop_photo.jpg
│   └── metadata.json
├── 2025-02-01_14-31-15/
│   └── ...
└── index.db (SQLite tracking database)

### Database Schema
```sqlCREATE TABLE backups (
id INTEGER PRIMARY KEY,
original_path TEXT,
backup_path TEXT,
timestamp DATETIME,
file_hash TEXT,
reason TEXT,
process_name TEXT
);

## Deliverables
- `backup_manager.py` - Backup orchestration
- `snapshot_service.py` - File versioning logic
- `recovery_manager.py` - Restoration utilities
- `backup_config.py` - Retention policies

## Testing
- Modify files and verify backups created
- Test restoration accuracy
- Verify backup isolation (can't be accessed by test "ransomware")
- Test storage cleanup (old backups deleted)
- Performance impact measurement