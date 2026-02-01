# Ransomware Detection System - Project Guide

## Project Goal
Build a behavioral ransomware detection system that monitors file system activity, 
detects encryption patterns through entropy analysis, and provides automated 
backup/rollback capabilities.

## Technology Stack
- **Language**: Python 3.10+
- **OS Support**: Windows (primary), Linux (secondary)
- **Key Libraries**: 
  - watchdog (file system monitoring)
  - psutil (process management)
  - numpy (entropy calculations)
  - Flask (web dashboard)
  - SQLite (event logging)

## Project Phases
1. File System Monitor (Week 1-2)
2. Entropy Analysis Engine (Week 3)
3. Behavioral Detection Logic (Week 4)
4. Backup/Snapshot System (Week 5-6)
5. Automated Response System (Week 7)
6. Web Dashboard (Week 8)
7. Testing & Refinement (Week 9-10)

## Success Criteria
- Detect simulated ransomware within 2 seconds
- False positive rate < 5% with normal applications
- Successfully restore files to pre-encryption state
- Clean, documented codebase suitable for portfolio