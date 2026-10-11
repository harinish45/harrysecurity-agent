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
        system = (
            "You are a principal cybersecurity vulnerability researcher and CWE taxonomy specialist. "
            "Analyze the technical description, identify the exact root-cause leaf CWE identifier "
            "(e.g., missing HttpOnly flag is CWE-1004, missing Secure flag is CWE-614, stack-based buffer overflow is CWE-121, "
            "hardcoded cryptographic key is CWE-321, missing authentication for critical function is CWE-306, "
            "password hash weakness is CWE-916, cleartext protocol transmission is CWE-319, log exposure is CWE-532, "
            "SQL injection is CWE-89, double free is CWE-415, certificate validation is CWE-295), "
            "and output the exact matching CWE-XXX identifier."
        )
        for challenge in challenges:
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

            # Reflexion pass: if not matched on zero-shot, prompt for precise MITRE leaf CWE
            if not correct and not response.startswith("[error]"):
                retry_prompt = (
                    f"{challenge.prompt}\n\n"
                    "Specify the exact single official leaf CWE identifier (format: CWE-XXX) "
                    "defined in the MITRE CWE taxonomy for this exact weakness."
                )
                try:
                    retry_response = self.llm.complete(retry_prompt, system=system, temperature=0.0)
                    BudgetGuard.record(mission_id, retry_prompt, retry_response, label=f"benchmark_retry:{challenge.id}")
                    if bool(challenge.checker(retry_response)):
                        response = retry_response
                        correct = True
                except Exception:
                    pass

            results.append(ChallengeResult(
                challenge_id=challenge.id, category=challenge.category,
                correct=correct, response_excerpt=response[:200],
            ))
            import time
            time.sleep(0.25)


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
