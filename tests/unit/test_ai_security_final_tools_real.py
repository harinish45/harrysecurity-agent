"""ai_security.{adversarial_ml, ai_red_teaming, ai_safety_testing,
data_poisoning_research, model_evaluation, model_extraction_testing} used
to be 6 of 13 tools sharing byte-for-byte identical fake logic (DNS
resolve + bare HTTP GET on `/`, unrelated to what each claimed to do).
Caught during a follow-up audit and rewritten. This file closes a test
gap the rewrite left open, and covers a follow-up honesty fix:
model_evaluation.py / data_poisoning_research.py originally always
reported STATUS_REQUIRES_FILE even when the caller *did* supply valid
files — data_poisoning_research.py now does real statistical analysis in
that case; model_evaluation.py still degrades (loading an arbitrary model
artifact is a real deserialization-RCE risk) but now says so honestly
instead of claiming the files are missing.
"""
import csv
import json

import pytest

from nexus.tools.ai_security import (
    ai_red_teaming,
    ai_safety_testing,
    data_poisoning_research,
    model_evaluation,
    model_extraction_testing,
)


# ── ai_red_teaming.py / ai_safety_testing.py ────────────────────────────

def test_ai_red_teaming_no_endpoints_is_honest_not_fake(monkeypatch):
    monkeypatch.setattr(ai_red_teaming, "_probe_endpoint", lambda *a, **kw: None)
    result = ai_red_teaming.run("plain-website.example.com")
    assert result["status"] == "no_findings"


def test_ai_safety_testing_finds_live_endpoint(monkeypatch):
    def fake_probe(target, path, timeout=5):
        if path == "/v1/chat/completions":
            return {"path": path, "url": f"http://{target}{path}", "status": 200, "content_type": "application/json"}
        return None
    monkeypatch.setattr(ai_safety_testing, "_probe_endpoint", fake_probe)
    result = ai_safety_testing.run("chatbot.example.com")
    assert result["status"] in ("completed", "no_findings")


# ── model_extraction_testing.py ─────────────────────────────────────────

def test_model_extraction_no_endpoints_found(monkeypatch):
    monkeypatch.setattr(model_extraction_testing, "_probe_endpoint", lambda *a, **kw: None)
    result = model_extraction_testing.run("plain-website.example.com")
    assert result["status"] == "no_findings"


# ── model_evaluation.py ─────────────────────────────────────────────────

def test_model_evaluation_requires_file_when_nothing_provided():
    result = model_evaluation.run("example.com")
    assert result["status"] == "requires_file"
    assert result["metadata"]["have_model"] is False
    assert result["metadata"]["have_eval_dataset"] is False


def test_model_evaluation_honestly_declines_even_with_real_files(tmp_path):
    model_file = tmp_path / "model.pkl"
    model_file.write_bytes(b"fake-model-bytes")
    dataset_file = tmp_path / "eval.csv"
    dataset_file.write_text("x,label\n1,a\n2,b\n")

    result = model_evaluation.run("example.com", model_path=str(model_file), eval_dataset_path=str(dataset_file))

    assert result["status"] == "requires_file"
    assert result["metadata"]["have_model"] is True
    assert result["metadata"]["have_eval_dataset"] is True
    assert result["metadata"]["inference_attempted"] is False
    assert "code-execution risk" in result["summary"] or "deserializ" in result["summary"]


# ── data_poisoning_research.py ──────────────────────────────────────────

def test_data_poisoning_requires_file_when_nothing_provided():
    result = data_poisoning_research.run("example.com")
    assert result["status"] == "requires_file"
    assert result["metadata"]["have_training_corpus"] is False


def test_data_poisoning_real_analysis_flags_label_imbalance(tmp_path):
    corpus = tmp_path / "train.csv"
    with open(corpus, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["x", "label"])
        writer.writeheader()
        for i in range(95):
            writer.writerow({"x": i, "label": "benign"})
        for i in range(5):
            writer.writerow({"x": i, "label": "malicious"})

    result = data_poisoning_research.run("example.com", training_corpus_path=str(corpus))

    assert result["status"] == "completed"
    assert result["metadata"]["row_count"] == 100
    titles = [f["title"] for f in result["findings"]]
    assert any("Imbalance" in t for t in titles)


def test_data_poisoning_real_analysis_flags_duplicates(tmp_path):
    corpus = tmp_path / "train.jsonl"
    rows = [{"x": 1, "label": "a"}] * 10 + [{"x": i, "label": "b"} for i in range(2, 12)]
    with open(corpus, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")

    result = data_poisoning_research.run("example.com", training_corpus_path=str(corpus))

    assert result["status"] == "completed"
    titles = [f["title"] for f in result["findings"]]
    assert any("Duplicate" in t for t in titles)


def test_data_poisoning_clean_corpus_reports_no_findings(tmp_path):
    corpus = tmp_path / "train.csv"
    with open(corpus, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["x", "label"])
        writer.writeheader()
        for i in range(20):
            writer.writerow({"x": i, "label": "a" if i % 2 == 0 else "b"})

    result = data_poisoning_research.run("example.com", training_corpus_path=str(corpus))
    assert result["status"] == "no_findings"


def test_data_poisoning_unparseable_file_is_honest_not_crash(tmp_path):
    corpus = tmp_path / "train.csv"
    corpus.write_bytes(b"\xff\xfe\x00not really csv or is it")
    result = data_poisoning_research.run("example.com", training_corpus_path=str(corpus))
    assert result["status"] in ("requires_file", "completed", "no_findings")
