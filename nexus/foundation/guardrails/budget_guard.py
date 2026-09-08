"""Per-mission LLM spend tracking and hard-stop threshold.

No provider in ``nexus.intelligence.llm.router`` currently reports real
token usage back to the caller, so this is a character-count estimate
(``len(text) // 4``), not a billed-token count — every value this module
reports is labelled ``estimated_*`` for that reason. It's still useful:
agents run for hours across a 266-tool mesh, and a runaway retry loop
burning API spend with nothing watching it is a real failure mode this
closes off, even at estimate-grade precision.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

_CHARS_PER_TOKEN = 4
_DEFAULT_USD_PER_1K_TOKENS = 0.01


class BudgetExceededError(Exception):
    pass


@dataclass
class _MissionLedger:
    estimated_tokens: int = 0
    estimated_usd: float = 0.0
    calls: int = 0
    history: list[dict] = field(default_factory=list)


class BudgetGuard:
    _ledgers: dict[str, _MissionLedger] = {}
    _lock = threading.Lock()

    @classmethod
    def record(cls, mission_id: str, prompt: str, response: str = "", *, label: str = "") -> dict:
        """Record one LLM call's estimated cost against a mission and
        raise if the mission's configured budget is exceeded."""
        tokens = (len(prompt or "") + len(response or "")) // _CHARS_PER_TOKEN
        usd_per_1k = float(os.environ.get("NEXUS_BUDGET_USD_PER_1K_TOKENS", _DEFAULT_USD_PER_1K_TOKENS))
        usd = tokens / 1000 * usd_per_1k

        with cls._lock:
            ledger = cls._ledgers.setdefault(mission_id, _MissionLedger())
            ledger.estimated_tokens += tokens
            ledger.estimated_usd += usd
            ledger.calls += 1
            ledger.history.append({"label": label, "estimated_tokens": tokens, "estimated_usd": round(usd, 4)})
            snapshot = {
                "mission_id": mission_id,
                "calls": ledger.calls,
                "estimated_tokens": ledger.estimated_tokens,
                "estimated_usd": round(ledger.estimated_usd, 4),
            }

        max_tokens = os.environ.get("NEXUS_BUDGET_MAX_TOKENS")
        max_usd = os.environ.get("NEXUS_BUDGET_MAX_USD")
        if max_tokens and snapshot["estimated_tokens"] > int(max_tokens):
            raise BudgetExceededError(
                f"Mission {mission_id} exceeded token budget: "
                f"{snapshot['estimated_tokens']} > {max_tokens} (estimated)"
            )
        if max_usd and snapshot["estimated_usd"] > float(max_usd):
            raise BudgetExceededError(
                f"Mission {mission_id} exceeded spend budget: "
                f"${snapshot['estimated_usd']:.4f} > ${max_usd} (estimated)"
            )
        return snapshot

    @classmethod
    def report(cls, mission_id: str) -> dict:
        with cls._lock:
            ledger = cls._ledgers.get(mission_id)
            if not ledger:
                return {"mission_id": mission_id, "calls": 0, "estimated_tokens": 0, "estimated_usd": 0.0}
            return {
                "mission_id": mission_id,
                "calls": ledger.calls,
                "estimated_tokens": ledger.estimated_tokens,
                "estimated_usd": round(ledger.estimated_usd, 4),
                "history": list(ledger.history),
            }

    @classmethod
    def reset(cls, mission_id: str) -> None:
        with cls._lock:
            cls._ledgers.pop(mission_id, None)
