# Phase 1: File System Monitor

## Objective
Create a real-time file system monitoring service that tracks all file operations 
on specified directories.

## Requirements
1. Monitor these file operations:
   - File creation
   - File modification (content changes)
   - File deletion
   - File rename/move
   - Extension changes

2. Capture metadata:
   - Timestamp
   - File path
   - Operation type
   - File size (before/after)
   - Process ID that made the change
   - Process name

3. Configurable monitoring:
   - Watch specific directories (Documents, Desktop, etc.)
   - Exclude system directories
   - Filter by file extensions if needed

## Technical Approach
- Use `watchdog` library for cross-platform file monitoring
- Implement event handler class that logs all operations
- Store events in SQLite database for analysis
- Track process information using `psutil`

## Deliverables
- `file_monitor.py` - Main monitoring class
- `event_logger.py` - Database logging utilities
- `config.json` - Configuration for monitored paths
- Basic CLI to start/stop monitoring

## Testing
- Create test directory structure
- Perform various file operations manually
- Verify all events are captured correctly
- Check process attribution is accurate