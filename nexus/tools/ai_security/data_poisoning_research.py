#!/usr/bin/env python3
"""
NEXUS-STRIKE — ai_security.data_poisoning_research
Domain: ai_security

Previously one of 13 tools sharing byte-for-byte identical fake logic
(DNS resolve + bare HTTP GET on `/`, unrelated to data poisoning research
at all). Caught during a follow-up audit. Data-poisoning research
(detecting mislabeled/adversarially-crafted samples, outlier/influence
analysis, label-flip detection) genuinely requires access to the actual
TRAINING CORPUS a model was (or would be) trained on — a bare network
target (a domain/IP/URL) exposes none of that; it's a live host, not a
dataset. This is a distinct gap from model_evaluation.py (which needs a
model + held-out eval set, not the training data) — poisoning analysis
specifically needs the training-time data itself. Honestly reports
STATUS_REQUIRES_FILE instead of fabricating poisoning-risk scores.
"""
from __future__ import annotations

import csv
import json
import os
import statistics
from collections import Counter
from typing import Any

from nexus.foundation.schema import Finding, STATUS_COMPLETED, STATUS_NO_FINDINGS, STATUS_REQUIRES_FILE, tool_result
from nexus.tools.registry import tool_registry

_TOOL_NAME = "ai_security.data_poisoning_research"


def _load_rows(corpus_path: str) -> list[dict] | None:
    """Best-effort real load of a CSV or JSON-lines/array dataset. Returns None if unreadable/unsupported."""
    try:
        if corpus_path.lower().endswith(".csv"):
            with open(corpus_path, newline="", encoding="utf-8", errors="replace") as f:
                return list(csv.DictReader(f))
        if corpus_path.lower().endswith((".json", ".jsonl")):
            with open(corpus_path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            try:
                data = json.loads(text)
                return data if isinstance(data, list) else None
            except json.JSONDecodeError:
                return [json.loads(line) for line in text.splitlines() if line.strip()]
    except Exception:
        return None
    return None


def run(target: str, **kwargs: Any) -> dict:
    """Real statistical label-imbalance/duplicate/outlier analysis when a training corpus is provided; honest degrade otherwise."""
    target = (target or "").strip()
    corpus_path = kwargs.get("training_corpus_path")
    label_field = kwargs.get("label_field", "label")
    have_corpus = bool(corpus_path and os.path.isfile(corpus_path))

    if not have_corpus:
        return tool_result(
            _TOOL_NAME, target,
            status=STATUS_REQUIRES_FILE,
            summary=(
                f"Data-poisoning research (label-flip detection, outlier/duplicate analysis on training "
                f"samples) requires access to the actual training corpus a model was trained on — a "
                f"live network target ({target!r}) is a host, not a dataset, and exposes none of that "
                f"data. Pass training_corpus_path pointing at a local CSV/JSON dataset file to run a "
                f"real analysis."
            ),
            error="requires_file: no training corpus provided",
            metadata={"have_training_corpus": False},
        )

    rows = _load_rows(corpus_path)
    if rows is None:
        return tool_result(
            _TOOL_NAME, target,
            status=STATUS_REQUIRES_FILE,
            summary=f"'{corpus_path}' exists but could not be parsed as CSV or JSON/JSONL — "
                    "supported formats are .csv, .json (array of records), .jsonl (one record per line)",
            error="unsupported_or_unparseable_corpus_format",
            metadata={"have_training_corpus": True, "parsed": False},
        )

    findings: list[Finding] = []

    # Real label-distribution imbalance check (a genuine, low-cost poisoning/bias indicator).
    if rows and label_field in rows[0]:
        labels = [r.get(label_field) for r in rows if r.get(label_field) not in (None, "")]
        counts = Counter(labels)
        if len(counts) >= 2:
            total = sum(counts.values())
            majority_label, majority_n = counts.most_common(1)[0]
            majority_frac = majority_n / total
            if majority_frac > 0.9:
                findings.append(Finding(
                    title="Severe Label Imbalance in Training Corpus",
                    severity="medium",
                    confidence="certain",
                    affected_asset=corpus_path,
                    evidence=f"Real label-distribution count over {total} rows: label '{majority_label}' "
                             f"accounts for {majority_frac:.1%} of samples ({dict(counts)}). Severe "
                             "imbalance can mask a small number of poisoned/flipped-label samples and "
                             "also degrades model fairness independent of any attack.",
                    remediation="Investigate the minority-class samples individually; consider "
                                "stratified re-sampling and a label-provenance audit.",
                    tool=_TOOL_NAME,
                    references=["MITRE ATLAS AML.T0020"],
                ))

    # Real exact-duplicate-row detection (duplicated/near-duplicated samples are a known
    # low-effort poisoning vector — repeating a mislabeled sample to bias training).
    row_keys = [json.dumps(r, sort_keys=True) for r in rows]
    dup_counts = Counter(row_keys)
    duplicated = {k: c for k, c in dup_counts.items() if c > 1}
    if duplicated:
        total_dup_rows = sum(duplicated.values())
        findings.append(Finding(
            title="Duplicate Training Samples Detected",
            severity="low",
            confidence="certain",
            affected_asset=corpus_path,
            evidence=f"Real exact-match row hashing found {len(duplicated)} distinct row-values repeated "
                     f"a total of {total_dup_rows} times across {len(rows)} rows. Repeated samples "
                     "(especially a single mislabeled example duplicated many times) can be used to "
                     "bias a model disproportionately toward that sample.",
            remediation="Deduplicate the corpus and re-verify labels on any sample that appeared "
                        "an unusually high number of times.",
            tool=_TOOL_NAME,
            references=["MITRE ATLAS AML.T0020"],
        ))

    # Real numeric-column outlier check via IQR (statistics stdlib only, no external deps).
    numeric_fields: dict[str, list[float]] = {}
    for row in rows:
        for k, v in row.items():
            if k == label_field:
                continue
            try:
                numeric_fields.setdefault(k, []).append(float(v))
            except (TypeError, ValueError):
                continue
    for field, values in numeric_fields.items():
        if len(values) < 8:
            continue
        sorted_vals = sorted(values)
        q1 = statistics.median(sorted_vals[: len(sorted_vals) // 2])
        q3 = statistics.median(sorted_vals[(len(sorted_vals) + 1) // 2 :])
        iqr = q3 - q1
        if iqr <= 0:
            continue
        low, high = q1 - 3 * iqr, q3 + 3 * iqr
        outliers = [v for v in values if v < low or v > high]
        if outliers:
            findings.append(Finding(
                title=f"Statistical Outliers in Numeric Field '{field}'",
                severity="low",
                confidence="medium",
                affected_asset=corpus_path,
                evidence=f"Real IQR-based outlier check on field '{field}' ({len(values)} numeric values): "
                         f"{len(outliers)} value(s) fall outside [{low:.3g}, {high:.3g}] "
                         f"(sample outliers: {outliers[:5]}). Extreme outliers can indicate injected "
                         "adversarial samples, though legitimate rare events are a common false-positive cause.",
                remediation="Manually review the flagged rows for label correctness and plausibility "
                            "before excluding them.",
                tool=_TOOL_NAME,
                references=["MITRE ATLAS AML.T0020"],
            ))

    if not findings:
        return tool_result(
            _TOOL_NAME, target,
            status=STATUS_NO_FINDINGS,
            summary=f"Real statistical analysis of {len(rows)} rows in '{corpus_path}' found no severe "
                    "label imbalance, exact duplicates, or numeric outliers",
            metadata={"have_training_corpus": True, "parsed": True, "row_count": len(rows)},
        )
    return tool_result(
        _TOOL_NAME, target,
        status=STATUS_COMPLETED,
        findings=findings,
        summary=f"Real statistical data-poisoning-risk analysis of {len(rows)} rows in '{corpus_path}' "
                f"found {len(findings)} indicator(s). This is heuristic screening, not proof of poisoning "
                "— every flagged item needs manual review.",
        metadata={"have_training_corpus": True, "parsed": True, "row_count": len(rows)},
    )


tool_registry.register(_TOOL_NAME, run, metadata={
    "name": _TOOL_NAME,
    "domain": "ai_security",
    "status": "requires_file",
    "description": "Data-poisoning research requires the actual model training corpus, not obtainable "
                    "from a bare network target; honestly reports requires_file rather than fabricating "
                    "poisoning-risk scores",
    "parameters": {
        "target": "Target domain, IP, or URL (informational only — analysis needs the training corpus)",
        "training_corpus_path": "(optional) local path to the training dataset file or directory",
    },
})
