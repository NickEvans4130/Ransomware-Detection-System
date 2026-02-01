"""Shannon entropy calculation for file content analysis.

Computes byte-level entropy to distinguish normal files (~4-6 bits/byte),
compressed files (~6-7 bits/byte), and encrypted files (~7.5-8 bits/byte).
"""

import math
import os
import logging
from collections import Counter

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_SAMPLE_SIZE = 1024
LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB
LARGE_FILE_SAMPLE_COUNT = 3


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    H(X) = -sum(p(x) * log2(p(x))) for each byte value x.

    Returns a value between 0.0 (all identical bytes) and 8.0 (uniform
    distribution across all 256 byte values).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = np.zeros(256, dtype=np.int64)
    for byte in data:
        counts[byte] += 1

    probs = counts[counts > 0] / length
    return -float(np.sum(probs * np.log2(probs)))


def calculate_file_entropy(
    file_path: str,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> float | None:
    """Calculate entropy of a file, using sampling for performance.

    For files <= LARGE_FILE_THRESHOLD, reads the first `sample_size` bytes.
    For larger files, takes `LARGE_FILE_SAMPLE_COUNT` equally-spaced samples
    of `sample_size` bytes and returns the average entropy.

    Returns None if the file cannot be read.
    """
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        logger.debug("Cannot stat file: %s", file_path)
        return None

    if file_size == 0:
        return 0.0

    try:
        if file_size <= LARGE_FILE_THRESHOLD:
            with open(file_path, "rb") as f:
                data = f.read(sample_size)
            return shannon_entropy(data)

        # Multi-sample strategy for large files
        offsets = _sample_offsets(file_size, sample_size, LARGE_FILE_SAMPLE_COUNT)
        entropies = []
        with open(file_path, "rb") as f:
            for offset in offsets:
                f.seek(offset)
                data = f.read(sample_size)
                if data:
                    entropies.append(shannon_entropy(data))

        if not entropies:
            return None
        return sum(entropies) / len(entropies)

    except OSError:
        logger.debug("Cannot read file: %s", file_path)
        return None


def _sample_offsets(file_size: int, sample_size: int, count: int) -> list[int]:
    """Return equally-spaced byte offsets for sampling a large file."""
    if count <= 1:
        return [0]
    max_offset = max(0, file_size - sample_size)
    if max_offset == 0:
        return [0]
    step = max_offset / (count - 1)
    return [int(step * i) for i in range(count)]
