"""Autonomous (rule-based) vulnerability triage.

Everything in this module is deterministic, rule-driven automation — NOT a
learned or statistical model. "Autonomous" here means "runs end-to-end
without a human making per-finding judgment calls, via fixed and documented
rules"; it does not mean self-improving, trained, or ML-based in any sense.

``Triage.prioritize`` computes a ``priority_score`` for each finding as::

    severity_weight[severity] * confidence_weight[confidence] + asset_bonus

and returns the findings sorted by that score, descending. It never mutates
the original ``severity``/``confidence`` fields — ``priority_score`` is
added as a new key on a copy of each finding dict.

``Triage.deduplicate`` clusters near-duplicate findings — same
``affected_asset`` plus a title similarity (via
``difflib.SequenceMatcher``, case-insensitive) at or above
``similarity_threshold`` — and keeps one representative per cluster (the
one with the highest severity, tie-broken by confidence). The findings that
get dropped are not silently discarded: their ``references`` are merged
into the kept finding's ``references`` list. Clustering is a simple greedy
single pass (each not-yet-consumed finding seeds a cluster, later findings
that match it join that cluster) rather than a full pairwise transitive
closure — good enough for the "obviously the same finding reported by two
overlapping tool runs" case this targets, not a general clustering engine.
"""
from __future__ import annotations

import difflib
from typing import Any, Optional

# Rationale: coarse, explainable weights. Higher severity/confidence should
# dominate the score, but confidence still meaningfully discounts a
# high-severity-but-shaky finding rather than ignoring confidence entirely.
_SEVERITY_WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}
_CONFIDENCE_WEIGHT = {"certain": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "tentative": 0.15}

# Flat bonus applied when a finding's affected_asset is in the caller's
# critical_assets list — enough to noticeably reorder results without
# letting a low-severity finding on a critical asset outrank a genuinely
# critical-severity finding elsewhere.
_CRITICAL_ASSET_BONUS = 20.0

_SEVERITY_RANK = ("info", "low", "medium", "high", "critical")
_CONFIDENCE_RANK = ("tentative", "low", "medium", "high", "certain")


def _title_similarity(a: str, b: str) -> float:
    """Case-insensitive title similarity ratio in [0, 1].

    Shared with ``nexus.advanced.patch_validation``, which uses the same
    approach to decide whether a re-run finding is "the same issue" as an
    original one.
    """
    return difflib.SequenceMatcher(None, str(a).lower().strip(), str(b).lower().strip()).ratio()


def _severity_rank(finding: dict[str, Any]) -> int:
    sev = str(finding.get("severity", "info")).lower()
    return _SEVERITY_RANK.index(sev) if sev in _SEVERITY_RANK else 0


def _confidence_rank(finding: dict[str, Any]) -> int:
    conf = str(finding.get("confidence", "medium")).lower()
    return _CONFIDENCE_RANK.index(conf) if conf in _CONFIDENCE_RANK else 0


class Triage:
    """Rule-driven finding prioritization and near-duplicate merging."""

    def prioritize(
        self,
        findings: list[dict[str, Any]],
        *,
        critical_assets: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        critical_assets_set = set(critical_assets or [])
        scored: list[dict[str, Any]] = []
        for f in findings:
            g = dict(f)
            sev = str(g.get("severity", "info")).lower()
            conf = str(g.get("confidence", "medium")).lower()
            sev_w = _SEVERITY_WEIGHT.get(sev, _SEVERITY_WEIGHT["info"])
            conf_w = _CONFIDENCE_WEIGHT.get(conf, _CONFIDENCE_WEIGHT["medium"])
            score = sev_w * conf_w
            if g.get("affected_asset") in critical_assets_set:
                score += _CRITICAL_ASSET_BONUS
            g["priority_score"] = round(score, 3)
            scored.append(g)
        scored.sort(key=lambda g: g["priority_score"], reverse=True)
        return scored

    def deduplicate(
        self,
        findings: list[dict[str, Any]],
        *,
        similarity_threshold: float = 0.85,
    ) -> list[dict[str, Any]]:
        items = [dict(f) for f in findings]
        consumed = [False] * len(items)
        kept: list[dict[str, Any]] = []

        for i, fi in enumerate(items):
            if consumed[i]:
                continue
            cluster = [i]
            consumed[i] = True
            for j in range(i + 1, len(items)):
                if consumed[j]:
                    continue
                fj = items[j]
                if fi.get("affected_asset") != fj.get("affected_asset"):
                    continue
                if _title_similarity(fi.get("title", ""), fj.get("title", "")) >= similarity_threshold:
                    cluster.append(j)
                    consumed[j] = True

            best_idx = max(cluster, key=lambda k: (_severity_rank(items[k]), _confidence_rank(items[k])))
            best = dict(items[best_idx])
            merged_refs = list(best.get("references") or [])
            for k in cluster:
                if k == best_idx:
                    continue
                for ref in (items[k].get("references") or []):
                    if ref not in merged_refs:
                        merged_refs.append(ref)
            if merged_refs:
                best["references"] = merged_refs
            kept.append(best)

        return kept
