# Claude Code Prompts - WITH Documentation References

## Initial Setup Prompt
```
I'm building a ransomware detection system for my MSci Computer Science with Cyber Security degree. I have comprehensive documentation in the docs/ folder that outlines the entire project architecture and implementation plan.

Before we start coding, please:
1. Read docs/PROJECT_OVERVIEW.md to understand the project scope
2. Read docs/ARCHITECTURE.md to understand the system design
3. Confirm you understand the overall approach

Then let's begin with Phase 1.
```

## Phase 1: File System Monitor

### Prompt 1.1: Setup with Documentation
```
Read docs/PHASE1_FILE_MONITOR.md for the complete requirements.

Based on that documentation, create the initial project structure:
- Virtual environment setup
- Install all dependencies listed in the docs
- Create the directory structure as specified
- Set up requirements.txt
- Create initial README.md

Follow the technical approach outlined in the documentation exactly.
```

### Prompt 1.2: Implement Monitor
```
Read docs/PHASE1_FILE_MONITOR.md again, specifically the "Requirements" and "Technical Approach" sections.

Now implement the file system monitor with all the features specified:
1. Create file_monitor.py following the requirements
2. Implement event_logger.py as documented
3. Create the database schema exactly as shown
4. Add process tracking using psutil as specified

Ensure all metadata capture requirements from the docs are met.
```

### Prompt 1.3: Monitor Testing
```
Reference the "Testing" section in docs/PHASE1_FILE_MONITOR.md.

Create the test suite as specified:
- All test cases mentioned in the docs
- CLI interface as described
- Test data directory structure

Run the tests and verify all requirements from the documentation are satisfied.
```

## Phase 2: Entropy Analysis

### Prompt 2.1: Entropy Implementation
```
Read docs/PHASE2_ENTROPY_ANALYSIS.md completely, paying special attention to:
- The background section on entropy values
- The Shannon entropy formula
- The performance optimization requirements

Implement the entropy analyzer exactly as specified in the "Technical Approach" section. Make sure to handle all the file types mentioned in the testing section.
```

### Prompt 2.2: Entropy Detection
```
Reference the "Requirements" section in docs/PHASE2_ENTROPY_ANALYSIS.md, specifically the "Track entropy changes" part.

Integrate entropy analysis with the file monitor we built in Phase 1. Implement:
- Baseline entropy tracking as documented
- Change detection with the thresholds specified
- All caching mechanisms mentioned

Then run the tests specified in the docs with the exact file types listed.
```

## Phase 3: Behavioral Detection

### Prompt 3.1: Core Behavior Analysis
```
Read docs/PHASE3_BEHAVIORAL_DETECTION.md thoroughly. This is a critical phase.

Pay special attention to:
- The "Ransomware Behavioral Signatures" section with all primary and secondary indicators
- The "Scoring System" with specific thresholds and weights
- The requirements for real-time analysis

Implement behavior_analyzer.py following the exact scoring weights and thresholds documented. Create the threat scoring system as specified.
```

### Prompt 3.2: Pattern Detection
```
Reference the "Ransomware Behavioral Signatures" section in docs/PHASE3_BEHAVIORAL_DETECTION.md.

Implement pattern detection for each indicator type listed:
- Mass file modification (with the >20 files in <10 seconds threshold)
- Entropy spike patterns
- Extension manipulation (check the specific extensions mentioned)
- Directory traversal
- Suspicious process characteristics

Create test scenarios for each indicator as specified in the testing section.
```

## Phase 4: Backup System

### Prompt 4.1: Backup Implementation
```
Read docs/PHASE4_BACKUP_SYSTEM.md, focusing on Option A (Simple File Versioning) which is recommended.

Implement the backup system following:
- The exact backup structure diagram shown in the docs
- The database schema provided
- All metadata tracking requirements
- The 48-hour retention policy specified

Create the secure storage mechanism as described in the "Requirements" section.
```

### Prompt 4.2: Recovery System
```
Reference the "Recovery System" section in docs/PHASE4_BACKUP_SYSTEM.md.

Implement the recovery manager with all the capabilities listed:
1. File restoration as specified
2. Rollback capabilities exactly as documented
3. Point-in-time recovery

Run all the tests mentioned in the testing section and verify backup isolation works as required.
```

## Phase 5: Response System

### Prompt 5.1: Response Engine
```
Read docs/PHASE5_RESPONSE_SYSTEM.md carefully, especially the "Response Escalation Levels" section.

Implement the response engine with EXACTLY the four escalation levels specified:
- Level 1 (Score 31-50): Actions listed
- Level 2 (Score 51-70): Actions listed
- Level 3 (Score 71-85): Actions listed
- Level 4 (Score 86-100): Actions listed

Follow the technical implementation approaches shown in the pseudocode sections. Include the "safe mode" feature mentioned in the requirements.
```

### Prompt 5.2: Alert and Recovery Workflow
```
Reference the "User Alerts" and "Recovery Workflow" sections in docs/PHASE5_RESPONSE_SYSTEM.md.

Implement:
1. The alert system with all notification types specified
2. The recovery workflow following the exact 4-step process documented
3. All logging requirements

Test each escalation level as specified in the testing section.
```

## Phase 6: Web Dashboard

### Prompt 6.1: Backend API
```
Read docs/PHASE6_WEB_DASHBOARD.md, focusing on the "API Endpoints" section.

Implement the Flask backend with EXACTLY the endpoints listed in the documentation:
- All GET endpoints with the exact paths shown
- All POST/PUT endpoints as specified
- WebSocket endpoint for real-time updates

Use the tech stack specified in the "Technical Stack" section.
```

### Prompt 6.2: Frontend Interface
```
Reference the "Dashboard Components" and "UI Mockup Structure" sections in docs/PHASE6_WEB_DASHBOARD.md.

Create the frontend with all 5 components listed:
1. Real-Time Monitoring View
2. Threat History
3. File Recovery Interface
4. Configuration Panel
5. Statistics Dashboard

Follow the UI mockup structure diagram exactly. Use the technologies specified in the tech stack section.
```

## Phase 7: Testing & Refinement

### Prompt 7.1: Comprehensive Testing
```
Read docs/PHASE7_TESTING.md completely. This covers all testing strategies.

Implement:
1. Unit tests for all modules as listed in "Unit Testing" section
2. Integration tests following the "Integration Testing" section
3. The safe test ransomware from "Simulated Ransomware Testing" section (following the example code)
4. Performance tests meeting the targets specified

Run the "False Positive Testing" with all the legitimate software listed in the docs.
```

### Prompt 7.2: Final Refinement
```
Reference the "Refinement Checklist" in docs/PHASE7_TESTING.md.

Go through each item on the checklist and ensure it's met:
- Detection accuracy >95%
- False positive rate <5%
- Performance targets met
- etc.

Also read docs/TROUBLESHOOTING.md and add any additional error handling needed for the common issues listed there.
```

## Phase 8: Documentation

### Prompt 8.1: Code Documentation
```
Our code is complete. Now let's document it properly.

Read docs/PROJECT_OVERVIEW.md and docs/ARCHITECTURE.md to understand what should be in the final documentation.

Update the README.md with:
- All sections mentioned in the documentation prompts
- Installation instructions
- Configuration guide
- Usage examples
- Architecture overview referencing the docs

Add docstrings to all functions/classes following Google style or NumPy style.
```

### Prompt 8.2: User Guide
```
Create a comprehensive USER_GUIDE.md that covers:
- Everything mentioned in the "Final Documentation" sections of the phase documents
- Step-by-step setup walkthrough
- How to use the dashboard (reference PHASE6 docs)
- How to respond to threats (reference PHASE5 docs)
- Recovery procedures (reference PHASE4 docs)
- Troubleshooting (reference TROUBLESHOOTING.md)

Make it clear and beginner-friendly since this is for a first-year MSci project.
```

## Advanced Extension Prompts (Optional)

### Machine Learning Extension
```
Read docs/PROMPTS_FOR_CLAUDE_CODE.md, specifically the "ML Integration" section under Advanced Prompts.

Research and implement the ML-based detection following those specifications. Before coding:
1. Find appropriate datasets (suggest sources)
2. Design feature extraction based on our behavioral indicators
3. Choose appropriate ML algorithm (Random Forest as suggested or better alternative)

Then implement following the documentation structure we've established.
```

### Kernel-Level Research
```
Read the "Kernel-Level Monitor" section in docs/PROMPTS_FOR_CLAUDE_CODE.md.

Don't implement this yet, but:
1. Research minifilter drivers for Windows
2. Research eBPF for Linux
3. Create a detailed comparison document: kernel vs user-space approach
4. Document pros/cons, complexity, and performance implications
5. Create a roadmap for potential Phase 9 implementation

This will be valuable for your project report.
```

## Debugging Prompts

### When Things Break
```
Something isn't working as expected. Let me provide context:

[Describe the issue]

Please:
1. Check docs/TROUBLESHOOTING.md for this issue
2. Review the relevant phase documentation (docs/PHASE[X]_*.md)
3. Verify we implemented the requirements exactly as specified
4. Debug and fix while maintaining compliance with the documentation

Show me what was wrong and how you fixed it.
```

### Performance Issues
```
The system is running slower than the performance targets specified in docs/PHASE7_TESTING.md.

Please:
1. Review the performance targets in the documentation
2. Profile the code to find bottlenecks
3. Check if we implemented all the performance optimizations mentioned in docs/ARCHITECTURE.md
4. Suggest and implement improvements

Current metrics vs targets: [provide measurements]
```

### Code Review Request
```
Before I submit this project, let's do a thorough review.

Please:
1. Check that every requirement in docs/PROJECT_OVERVIEW.md is met
2. Verify each phase's deliverables from the phase documents are complete
3. Ensure the architecture matches docs/ARCHITECTURE.md
4. Review code quality (comments, docstrings, structure)
5. Check test coverage against docs/PHASE7_TESTING.md requirements
6. Verify documentation is comprehensive

Provide a checklist of what's done and what needs attention.
```

