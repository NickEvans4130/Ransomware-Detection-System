# Phase 3: Behavioral Detection Logic

## Objective
Combine file monitoring and entropy analysis to detect ransomware-like behavior 
patterns in real-time.

## Ransomware Behavioral Signatures

### Primary Indicators
1. **Mass File Modification**
   - Threshold: >20 files modified in <10 seconds by single process
   - Weight: HIGH

2. **Entropy Spike Pattern**
   - Multiple files with entropy increase >2.0 bits/byte
   - Weight: CRITICAL

3. **Extension Manipulation**
   - Mass renaming with suspicious extensions (.locked, .encrypted, etc.)
   - Original extension replaced
   - Weight: HIGH

4. **Directory Traversal**
   - Recursive scanning across multiple folders
   - Weight: MEDIUM

### Secondary Indicators
5. **Suspicious Process Characteristics**
   - Executed from temp/download folders
   - Unknown/unsigned executable
   - Recently created process
   - Weight: MEDIUM

6. **File Deletion Patterns**
   - Original file deleted after encrypted copy created
   - Shadow copy deletion attempts
   - Weight: HIGH

## Scoring System
- Each indicator contributes to threat score (0-100)
- Threshold for action: 70+
- Confidence levels:
  - 0-30: Normal activity
  - 31-50: Suspicious, monitor closely
  - 51-70: Likely threat, prepare response
  - 71-100: Critical threat, immediate action

## Requirements
1. Real-time behavior analysis
2. Per-process threat tracking
3. Time-windowed pattern detection
4. Configurable thresholds

## Deliverables
- `behavior_analyzer.py` - Main detection engine
- `threat_scoring.py` - Scoring algorithm
- `pattern_detector.py` - Pattern matching logic
- Configuration file for tuning thresholds

## Testing
- Create test scenarios for each indicator
- Combine indicators to test scoring
- Test false positive scenarios (backup software, batch operations)
- Measure detection latency