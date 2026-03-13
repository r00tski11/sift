"""Shannon entropy calculation for secrets detection."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Args:
        data: The string to analyze.

    Returns:
        Entropy value in bits. Higher values indicate more randomness.
        Empty strings return 0.0.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
