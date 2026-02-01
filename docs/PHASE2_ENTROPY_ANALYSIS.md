# Phase 2: Entropy Analysis Engine

## Objective
Implement Shannon entropy calculation to detect when files become encrypted 
(high entropy = high randomness = likely encrypted).

## Background
- Normal files (text, docs, images): entropy ~4-6 bits/byte
- Compressed files: entropy ~6-7 bits/byte
- Encrypted files: entropy ~7.5-8 bits/byte (near-perfect randomness)

Shannon entropy formula: H(X) = -Σ(p(x) * log2(p(x)))

## Requirements
1. Calculate entropy of file samples:
   - Read first N bytes (e.g., 1024 bytes) for speed
   - Calculate byte frequency distribution
   - Compute Shannon entropy

2. Track entropy changes:
   - Store baseline entropy before modification
   - Calculate entropy after modification
   - Detect significant entropy increases (delta > 2.0)

3. Performance optimization:
   - Only analyze files that were modified
   - Sample files > 10MB rather than reading entirely
   - Cache entropy values

## Technical Approach
- Implement entropy calculation function
- Create entropy comparison system
- Maintain entropy baseline database
- Flag suspicious entropy spikes

## Deliverables
- `entropy_analyzer.py` - Entropy calculation module
- `entropy_detector.py` - Change detection logic
- Unit tests for entropy calculations
- Benchmark different file types

## Testing
- Calculate entropy of various file types:
  - .txt, .docx, .pdf, .jpg, .zip
- Encrypt test files and verify entropy increase
- Test with legitimate encrypted files (password-protected ZIPs)
- Measure performance on large files