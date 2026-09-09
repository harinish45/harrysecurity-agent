"""Adapters for the two published suites this repo does not bundle a real
dataset for: Cybench (40 professional CTF tasks) and NYU CTF Bench (200
challenges — the hardest of the three cited in the roadmap). Both return an
empty challenge list until real challenge data is placed under
``benchmarks/data/<suite>/`` (one JSON file per challenge: ``id``,
``category``, ``prompt``, ``answer_pattern``) — this keeps the adapter
interface real and pluggable without shipping licensed/large third-party
datasets in this repo.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from nexus.benchmarks.base import Benchmark, Challenge, regex_checker

_DATA_ROOT = Path("benchmarks") / "data"


def _load_from_disk(suite_key: str) -> list[Challenge]:
    suite_dir = _DATA_ROOT / suite_key
    if not suite_dir.is_dir():
        return []
    challenges = []
    for path in sorted(suite_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            challenges.append(Challenge(
                id=data["id"],
                category=data.get("category", "misc"),
                prompt=data["prompt"],
                checker=regex_checker(data["answer_pattern"]),
            ))
        # re.error wasn't caught here — one challenge file with an invalid
        # answer_pattern regex would crash the whole suite's load() instead
        # of being skipped like every other malformed-file case below.
        except (json.JSONDecodeError, KeyError, OSError, re.error):
            continue
    return challenges


class CybenchSuite(Benchmark):
    key = "cybench"
    name = "Cybench"

    def load(self) -> list[Challenge]:
        return _load_from_disk(self.key)


class NyuCtfSuite(Benchmark):
    key = "nyu_ctf"
    name = "NYU CTF Bench"

    def load(self) -> list[Challenge]:
        return _load_from_disk(self.key)
