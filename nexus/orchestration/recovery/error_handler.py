"""Classifies a failure so callers can decide whether retrying makes sense —
a guardrail block or a bad-input error will never succeed on retry, while a
timeout or connection reset might."""
from __future__ import annotations

_TRANSIENT_MARKERS = (
    "timeout", "timed out", "connection", "temporarily unavailable",
    "rate limit", "429", "503", "reset by peer", "unreachable",
)
_GUARDRAIL_MARKERS = (
    "guardrail", "blocked", "out_of_scope", "out of scope", "requires_credentials",
    "scope guard", "legal guard", "escalation", "unauthorized",
)


class ErrorHandler:
    @staticmethod
    def classify(error: str | BaseException) -> str:
        text = str(error).lower()
        if any(m in text for m in _GUARDRAIL_MARKERS):
            return "guardrail"
        if any(m in text for m in _TRANSIENT_MARKERS):
            return "transient"
        return "permanent"

    @classmethod
    def should_retry(cls, error: str | BaseException) -> bool:
        return cls.classify(error) == "transient"

    @classmethod
    def describe(cls, error: str | BaseException, *, context: str = "") -> dict:
        kind = cls.classify(error)
        return {"kind": kind, "context": context, "message": str(error), "retryable": kind == "transient"}
