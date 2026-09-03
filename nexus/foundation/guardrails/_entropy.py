"""Shared Shannon-entropy helper used by InputGuard and OutputGuard.

Stdlib-only so guardrails stay dependency-free.
"""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits/char) of ``text``.

    Empty or single-character-repeated strings have entropy 0.0.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy
