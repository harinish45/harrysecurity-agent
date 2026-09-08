"""Pluggable benchmark-suite framework so "did the last change actually make
the agent better" has a measurable answer instead of a guess.

Standard suites cited by the field (Cybench, NYU CTF Bench, InterCode-CTF)
are wired as adapters (`nexus.benchmarks.suites.*`) but this repo does not
bundle their real datasets — `cybench`/`nyu_ctf` return an empty challenge
set with a clear note on how to enable them locally. `intercode_smoke` is a
small, fully self-contained suite bundled here so `nexus benchmark` is
runnable out of the box without any external dataset.
"""
from nexus.benchmarks.base import Benchmark, Challenge, ChallengeResult
from nexus.benchmarks.runner import BenchmarkRunner

__all__ = ["Benchmark", "Challenge", "ChallengeResult", "BenchmarkRunner"]
