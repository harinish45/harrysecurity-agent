"""Agent-level evaluation: precision/recall for `debate_consensus_agent`
against a small labeled set of true-positive/false-positive findings, and
execution-latency benchmarks across any set of registered agents.

Separate from `nexus.benchmarks.runner`/`Benchmark` (those score raw LLM
Q&A-style challenges against a regex checker) — this module scores an
*agent's own decision*, which needs ground-truth labels rather than a
pattern match on free text.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_LATENCY_HISTORY_PATH = Path("benchmarks") / "latency_history.jsonl"
_DEBATE_EVAL_HISTORY_PATH = Path("benchmarks") / "debate_eval_history.jsonl"


@dataclass
class LabeledFinding:
    finding: dict
    expected: str  # "real" or "false_positive"


# A small, hand-labeled set spanning both classes so precision and recall
# are both meaningful (an all-real or all-false-positive set would let a
# degenerate always-say-X strategy score perfectly on one metric).
DEBATE_EVAL_CASES: list[LabeledFinding] = [
    LabeledFinding(
        finding={"title": "SQL Injection confirmed via UNION-based payload", "severity": "critical",
                  "confidence": "low", "evidence": "UNION SELECT null,version()-- returned DB version string",
                  "tool": "webapp.sqli_scan"},
        expected="real",
    ),
    LabeledFinding(
        finding={"title": "Reflected input in error page", "severity": "medium", "confidence": "low",
                  "evidence": "Server echoed the request path back inside a generic 404 page, no script execution observed",
                  "tool": "webapp.xss_scan"},
        expected="false_positive",
    ),
    LabeledFinding(
        finding={"title": "Weak TLS cipher suite offered", "severity": "medium", "confidence": "low",
                  "evidence": "Server accepted TLS_RSA_WITH_3DES_EDE_CBC_SHA on port 443",
                  "tool": "network.tls_scan"},
        expected="real",
    ),
    LabeledFinding(
        finding={"title": "Open port flagged as vulnerable service", "severity": "low", "confidence": "low",
                  "evidence": "Port 80 open, banner grab returned no version string, scanner assumed default vulnerable config",
                  "tool": "network.port_scan"},
        expected="false_positive",
    ),
    LabeledFinding(
        finding={"title": "Default credentials accepted on admin panel", "severity": "critical", "confidence": "low",
                  "evidence": "POST /admin/login with admin:admin returned 302 redirect to /admin/dashboard with a valid session cookie",
                  "tool": "webapp.default_creds"},
        expected="real",
    ),
    LabeledFinding(
        finding={"title": "Directory listing enabled", "severity": "low", "confidence": "low",
                  "evidence": "GET /assets/ returned an Apache autoindex page listing only public static CSS/JS files",
                  "tool": "webapp.dir_enum"},
        expected="false_positive",
    ),
]


async def evaluate_debate_consensus(llm=None) -> dict:
    """Run `debate_consensus_agent` against `DEBATE_EVAL_CASES` and compute
    precision/recall/F1 for its "real" verdicts against the labels above.
    Cases where the two debate passes disagree (consensus == "disagreement")
    count as an abstention — excluded from precision/recall, tracked
    separately as `abstained`, since escalating an ambiguous case to a human
    is the intended behavior, not a wrong answer."""
    from nexus.agents.orchestrator.debate_consensus_agent import DebateConsensusAgent

    findings = []
    for case in DEBATE_EVAL_CASES:
        f = dict(case.finding)
        f.setdefault("id", f"EVAL-{len(findings) + 1:03d}")
        f["validation_status"] = "review"  # debate_consensus_agent only debates "review" findings
        findings.append(f)

    agent = DebateConsensusAgent(llm=llm) if llm is not None else DebateConsensusAgent()
    result = await agent.run("Evaluate debate consensus precision/recall", target="eval", findings=findings)
    metadata = result.get("metadata", {})
    resolved_by_id = {r["id"]: r["consensus"] for r in metadata.get("resolved", [])}
    escalated_ids = {r["id"] for r in metadata.get("escalated", [])}

    tp = fp = fn = tn = abstained = 0
    predictions = []
    for f, case in zip(findings, DEBATE_EVAL_CASES):
        fid = f["id"]
        if fid in escalated_ids:
            abstained += 1
            predictions.append({"id": fid, "expected": case.expected, "predicted": "abstained"})
            continue
        predicted = resolved_by_id.get(fid, "unknown")
        predictions.append({"id": fid, "expected": case.expected, "predicted": predicted})
        if predicted == "real" and case.expected == "real":
            tp += 1
        elif predicted == "real" and case.expected == "false_positive":
            fp += 1
        elif predicted == "false_positive" and case.expected == "real":
            fn += 1
        elif predicted == "false_positive" and case.expected == "false_positive":
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    summary = {
        "suite": "debate_consensus_eval",
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_cases": len(DEBATE_EVAL_CASES),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "abstained": abstained,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "predictions": predictions,
    }
    _DEBATE_EVAL_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _DEBATE_EVAL_HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(summary, default=str) + "\n")
    return summary


async def benchmark_agent_latency(agent_names: list[str] | None = None, *, target: str = "127.0.0.1") -> dict:
    """Time each named agent's `.run()` call once against a lightweight
    target and record wall-clock latency. Agents that need real network
    access will be slow/fail here the same way they would in a mission —
    that's the point (this measures the agent as actually invoked, not a
    mocked shortcut) — a failure is recorded with its latency, not skipped."""
    from nexus.agents.agent_registry import get_agent, list_agents

    if agent_names is None:
        names = [name for name, cls in list_agents() if cls is not None]
    else:
        names = agent_names

    results = []
    for name in names:
        try:
            agent_cls = get_agent(name)
        except KeyError:
            results.append({"agent": name, "status": "not_found", "latency_ms": None})
            continue

        started = time.perf_counter()
        status = "completed"
        try:
            agent = agent_cls()
            await agent.run("latency benchmark", target=target)
        except Exception as exc:  # noqa: BLE001 - latency is measured whether or not the call succeeds
            status = f"error: {exc}"
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        results.append({"agent": name, "status": status, "latency_ms": elapsed_ms})

    summary = {
        "run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_count": len(results),
        "results": sorted(results, key=lambda r: r["latency_ms"] or 0, reverse=True),
    }
    _LATENCY_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LATENCY_HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(summary, default=str) + "\n")
    return summary
