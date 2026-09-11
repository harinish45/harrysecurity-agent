from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from nexus.benchmarks.base import ChallengeResult
from nexus.foundation.guardrails.budget_guard import BudgetGuard
from nexus.intelligence.llm.router import LLMRouter

_HISTORY_PATH = Path("benchmarks") / "history.jsonl"


class BenchmarkRunner:
    def __init__(self, llm: LLMRouter | None = None):
        self.llm = llm or LLMRouter()

    def run(self, suite, *, mission_id: str = "benchmark") -> dict:
        challenges = suite.load()
        if not challenges:
            summary = {
                "suite": suite.key,
                "name": suite.name,
                "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total": 0,
                "correct": 0,
                "score": 0.0,
                "by_category": {},
                "note": f"No challenges available for suite '{suite.key}' — "
                        f"place data under benchmarks/data/{suite.key}/ to enable it.",
            }
            self._append_history(summary)
            return summary

        results: list[ChallengeResult] = []
        for challenge in challenges:
            system = "You are a precise security assistant. Answer concisely and directly."
            try:
                response = self.llm.complete(challenge.prompt, system=system, temperature=0.0)
                BudgetGuard.record(mission_id, challenge.prompt, response, label=f"benchmark:{challenge.id}")
            except Exception as exc:  # noqa: BLE001 - a failed call scores as incorrect, not a crash
                response = f"[error] {exc}"
            correct = False
            try:
                correct = bool(challenge.checker(response))
            except Exception:  # noqa: BLE001 - a broken checker shouldn't crash the run
                correct = False
            results.append(ChallengeResult(
                challenge_id=challenge.id, category=challenge.category,
                correct=correct, response_excerpt=response[:200],
            ))

        by_category: dict[str, dict] = {}
        for r in results:
            bucket = by_category.setdefault(r.category, {"total": 0, "correct": 0})
            bucket["total"] += 1
            bucket["correct"] += int(r.correct)
        for bucket in by_category.values():
            bucket["score"] = round(bucket["correct"] / bucket["total"], 3) if bucket["total"] else 0.0

        total = len(results)
        correct = sum(1 for r in results if r.correct)
        summary = {
            "suite": suite.key,
            "name": suite.name,
            "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total": total,
            "correct": correct,
            "score": round(correct / total, 3) if total else 0.0,
            "by_category": by_category,
            "results": [
                {"id": r.challenge_id, "category": r.category, "correct": r.correct}
                for r in results
            ],
        }
        self._append_history(summary)
        return summary

    @staticmethod
    def _append_history(summary: dict) -> None:
        _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _HISTORY_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary, default=str) + "\n")
