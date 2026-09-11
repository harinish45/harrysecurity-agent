"""Benchmark suite contract — one interface for Cybench/NYU-CTF/InterCode-CTF
and our own bundled smoke suite."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Challenge:
    id: str
    category: str
    prompt: str
    # A response scores correct when `checker(response)` is True. Kept as a
    # plain callable (not an LLM judge) so scoring is deterministic and
    # reproducible run-over-run.
    checker: Callable[[str], bool] = field(default=lambda response: False)
    max_score: float = 1.0


@dataclass
class ChallengeResult:
    challenge_id: str
    category: str
    correct: bool
    response_excerpt: str


class Benchmark:
    """Base class for a benchmark-suite adapter."""

    key: str = "base"
    name: str = "Base Benchmark"

    def load(self) -> list[Challenge]:
        raise NotImplementedError


def regex_checker(pattern: str, flags: int = re.IGNORECASE) -> Callable[[str], bool]:
    compiled = re.compile(pattern, flags)
    return lambda response: bool(compiled.search(response or ""))
