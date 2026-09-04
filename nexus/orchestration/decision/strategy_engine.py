"""Chooses a mission's execution strategy from the *actual shape* of its
dependency-batched task graph — not a guess, a direct read of what the
scheduler is about to do."""
from __future__ import annotations


class StrategyEngine:
    @staticmethod
    def choose(batches: list[list[str]]) -> str:
        if not batches:
            return "sequential"
        if len(batches) == 1:
            return "parallel" if len(batches[0]) > 1 else "sequential"
        if any(len(b) > 1 for b in batches):
            return "mixed"
        return "sequential"

    @staticmethod
    def describe(batches: list[list[str]]) -> dict:
        strategy = StrategyEngine.choose(batches)
        return {
            "strategy": strategy,
            "batch_count": len(batches),
            "max_batch_width": max((len(b) for b in batches), default=0),
            "total_tasks": sum(len(b) for b in batches),
        }
