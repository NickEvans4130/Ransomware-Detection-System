"""Threat scoring algorithm.

Maps the six behavioral indicators to weighted scores (0-100) and
classifies the result into confidence levels:

    0-30:  NORMAL    - Normal activity
   31-50:  SUSPICIOUS - Suspicious, monitor closely
   51-70:  LIKELY    - Likely threat, prepare response
   71-100: CRITICAL  - Critical threat, immediate action

Action threshold: score >= 71 triggers immediate response.

Weights per indicator (from docs):
    mass_modification:      HIGH     (25)
    entropy_spike:          CRITICAL (30)
    extension_manipulation: HIGH     (25)
    directory_traversal:    MEDIUM   (10)
    suspicious_process:     MEDIUM   (10)
    deletion_pattern:       HIGH     (20)

Weights intentionally sum to 120 so that a combination of several strong
indicators easily crosses the 71 action threshold, but the final score
is clamped to 100.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Weight constants
WEIGHT_MASS_MODIFICATION = 25
WEIGHT_ENTROPY_SPIKE = 30
WEIGHT_EXTENSION_MANIPULATION = 25
WEIGHT_DIRECTORY_TRAVERSAL = 10
WEIGHT_SUSPICIOUS_PROCESS = 10
WEIGHT_DELETION_PATTERN = 20

INDICATOR_WEIGHTS: dict[str, int] = {
    "mass_modification": WEIGHT_MASS_MODIFICATION,
    "entropy_spike": WEIGHT_ENTROPY_SPIKE,
    "extension_manipulation": WEIGHT_EXTENSION_MANIPULATION,
    "directory_traversal": WEIGHT_DIRECTORY_TRAVERSAL,
    "suspicious_process": WEIGHT_SUSPICIOUS_PROCESS,
    "deletion_pattern": WEIGHT_DELETION_PATTERN,
}

# Confidence-level thresholds
THRESHOLD_NORMAL = 30
THRESHOLD_SUSPICIOUS = 50
THRESHOLD_LIKELY = 70
THRESHOLD_CRITICAL = 71  # action point

LEVEL_NORMAL = "NORMAL"
LEVEL_SUSPICIOUS = "SUSPICIOUS"
LEVEL_LIKELY = "LIKELY"
LEVEL_CRITICAL = "CRITICAL"


@dataclass
class ThreatScore:
    """Result of a threat-score evaluation for a single process."""
    process_id: int | None
    process_name: str | None
    score: int
    level: str
    triggered_indicators: dict[str, str]  # indicator -> detail string
    action_required: bool


def classify_level(score: int) -> str:
    """Map a numeric score to a confidence level string."""
    if score >= THRESHOLD_CRITICAL:
        return LEVEL_CRITICAL
    if score >= THRESHOLD_SUSPICIOUS + 1:  # 51-70
        return LEVEL_LIKELY
    if score >= THRESHOLD_NORMAL + 1:  # 31-50
        return LEVEL_SUSPICIOUS
    return LEVEL_NORMAL


def calculate_threat_score(
    indicator_results: dict[str, tuple[bool, str]],
    process_id: int | None = None,
    process_name: str | None = None,
) -> ThreatScore:
    """Compute a threat score from pattern-detector indicator results.

    Parameters
    ----------
    indicator_results:
        Dict of indicator_name -> (triggered, detail_string) as returned
        by ``PatternDetector.evaluate()``.
    """
    raw_score = 0
    triggered: dict[str, str] = {}

    for name, (is_triggered, detail) in indicator_results.items():
        if is_triggered:
            weight = INDICATOR_WEIGHTS.get(name, 0)
            raw_score += weight
            triggered[name] = detail

    score = min(raw_score, 100)
    level = classify_level(score)
    action_required = score >= THRESHOLD_CRITICAL

    if action_required:
        logger.warning(
            "CRITICAL threat score %d for pid %s (%s): %s",
            score, process_id, process_name, triggered,
        )

    return ThreatScore(
        process_id=process_id,
        process_name=process_name,
        score=score,
        level=level,
        triggered_indicators=triggered,
        action_required=action_required,
    )
