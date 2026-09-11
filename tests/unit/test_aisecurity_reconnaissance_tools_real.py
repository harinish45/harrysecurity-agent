"""Real-logic tests for the 12 ai_security/reconnaissance tools that an
audit found were byte-for-byte identical fake stubs (a DNS resolve + bare
HTTP GET on `/`, unrelated to what each tool claimed to do):

  ai_security: adversarial_ml, ai_red_teaming, ai_safety_testing,
               data_poisoning_research, model_evaluation,
               model_extraction_testing
  reconnaissance: censys_search, email_harvest, github_recon,
               google_dorking, shodan_search, social_osint

(reconnaissance.cert_transparency and ai_security.llm_prompt_injection_testing
were already fixed in an earlier pass and are out of scope here.)

External HTTP/DNS calls (GitHub/Shodan/Censys APIs, generic endpoint
probes, and dnspython MX/TXT lookups) are all mocked — nothing here hits
a real external service or the real internet. email_harvest's real
technique turned out to be passive DNS-based recon (MX/SPF/DMARC), not an
HTTP fetch of the target's homepage, and social_osint's real technique is
a fixed-platform-URL presence check (GitHub/npm/PyPI/LinkedIn/X/
Crunchbase) rather than homepage meta-tag scraping — both are tested
against what they actually do, via mocked `dns.resolver.resolve`/
`socket.gethostbyname` and mocked `safe_urlopen` respectively.
"""
from __future__ import annotations

import json
import socket as socket_module
import urllib.error
from unittest.mock import patch

import pytest

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_FINDINGS,
    STATUS_REQUIRES_CREDENTIALS,
    STATUS_REQUIRES_FILE,
    STATUS_UNAVAILABLE,
)
from nexus.tools.ai_security import (
    adversarial_ml,
    ai_red_teaming,
    ai_safety_testing,
    data_poisoning_research,
    model_evaluation,
    model_extraction_testing,
)
from nexus.tools.reconnaissance import (
    censys_search,
    email_harvest,
    github_recon,
    google_dorking,
    shodan_search,
    social_osint,
)


# ── Shared fakes / helpers ───────────────────────────────────────────────────

class _FakeResp:
    """Minimal stand-in for the object `safe_urlopen()` returns."""

    def __init__(self, body: bytes, status: int = 200, headers=None):
        self._body = body
        self.status = status
        self.headers = headers or {}

    def read(self, *_a, **_kw):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _json_resp(obj, status=200):
    return _FakeResp(json.dumps(obj).encode("utf-8"), status=status, headers={"Content-Type": "application/json"})


def _endpoint_side_effect(live_url_substr: str, body: bytes = b'{"probability": 0.87}', content_type="application/json"):
    """A safe_urlopen side_effect: any request whose URL contains
    `live_url_substr` gets a 200 with `body`; every other URL gets a 404
    HTTPError (mimicking "no such endpoint"), matching how the real
    _probe_endpoint()/_probe_confidence_leak() helpers interpret 404."""

    def _effect(req, timeout=5, context=None, **kw):
        url = getattr(req, "full_url", None) or str(req)
        if live_url_substr in url:
            return _FakeResp(body, status=200, headers={"Content-Type": content_type})
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    return _effect


def _all_404_side_effect(req, timeout=5, context=None, **kw):
    url = getattr(req, "full_url", None) or str(req)
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


# ── ai_security.model_extraction_testing ────────────────────────────────────

def test_model_extraction_no_findings_when_no_endpoint_live():
    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=_all_404_side_effect):
        result = model_extraction_testing.run("example.com")
    assert result["status"] == STATUS_NO_FINDINGS
    assert not result["findings"]


def test_model_extraction_flags_confidence_leak_when_endpoint_live():
    effect = _endpoint_side_effect("/invocations", body=b'{"probability": 0.93, "label": "cat"}')
    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=effect), \
         patch("nexus.tools.ai_security.model_extraction_testing.safe_urlopen", side_effect=effect):
        result = model_extraction_testing.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("model-serving endpoint found" in t for t in titles)
    assert any("Confidence/probability leakage check" in t for t in titles)
    leak_finding = next(f for f in result["findings"] if "Confidence/probability leakage check" in f["title"])
    assert "probability" in leak_finding["evidence"]
    assert leak_finding["severity"] == "medium"


# ── ai_security.adversarial_ml ───────────────────────────────────────────────

def test_adversarial_ml_no_findings_when_no_endpoint_live():
    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=_all_404_side_effect):
        result = adversarial_ml.run("example.com")
    assert result["status"] == STATUS_NO_FINDINGS


def test_adversarial_ml_flags_score_exposure():
    effect = _endpoint_side_effect("/predict", body=b'{"logits": [0.1, 0.9]}')
    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=effect), \
         patch("nexus.tools.ai_security.model_extraction_testing.safe_urlopen", side_effect=effect):
        result = adversarial_ml.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("Adversarial-crafting feedback-channel check" in t for t in titles)
    finding = next(f for f in result["findings"] if "Adversarial-crafting feedback-channel check" in f["title"])
    assert finding["severity"] == "medium"
    assert "logit" in finding["evidence"]


# ── ai_security.ai_red_teaming ───────────────────────────────────────────────

def test_ai_red_teaming_no_findings_when_no_chat_endpoint():
    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=_all_404_side_effect):
        result = ai_red_teaming.run("example.com")
    assert result["status"] == STATUS_NO_FINDINGS


def test_ai_red_teaming_runs_technique_variety_and_detects_canary_echo():
    canary_holder = {}

    def effect(req, timeout=5, context=None, **kw):
        url = getattr(req, "full_url", None) or str(req)
        if "/api/chat" not in url:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        if req.data:
            payload = json.loads(req.data.decode("utf-8"))
            msg = payload.get("message", "")
            # Echo back any canary token found in the prompt, as a
            # vulnerable endpoint would.
            for token in msg.split():
                if token.startswith("NEXUS-CANARY-"):
                    canary_holder["last"] = token
                    return _FakeResp(json.dumps({"reply": token}).encode(), status=200,
                                      headers={"Content-Type": "application/json"})
            return _FakeResp(b'{"reply": "ok"}', status=200, headers={"Content-Type": "application/json"})
        return _FakeResp(b'{"ok": true}', status=200, headers={"Content-Type": "application/json"})

    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=effect), \
         patch("nexus.tools.ai_security.ai_red_teaming.safe_urlopen", side_effect=effect):
        result = ai_red_teaming.run("example.com", mission_id="test-mission")

    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["techniques"] == list(ai_red_teaming._TECHNIQUES.keys())
    echoed = [f for f in result["findings"] if "canary echoed back" in f["title"]]
    assert echoed, "expected at least one technique's canary to be echoed back in this fake-vulnerable server"
    assert any(f["severity"] == "high" for f in echoed)


# ── ai_security.ai_safety_testing ────────────────────────────────────────────

def test_ai_safety_testing_no_findings_when_no_chat_endpoint():
    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=_all_404_side_effect):
        result = ai_safety_testing.run("example.com")
    assert result["status"] == STATUS_NO_FINDINGS


def test_ai_safety_testing_detects_refusal_language():
    def effect(req, timeout=5, context=None, **kw):
        url = getattr(req, "full_url", None) or str(req)
        if "/api/chat" not in url:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return _FakeResp(b'{"reply": "REFUSED - I cannot assist with that."}', status=200,
                          headers={"Content-Type": "application/json"})

    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=effect), \
         patch("nexus.tools.ai_security.ai_safety_testing.safe_urlopen", side_effect=effect):
        result = ai_safety_testing.run("example.com")

    assert result["status"] == STATUS_COMPLETED
    refusal_findings = [f for f in result["findings"] if "refusal language observed (expected)" in f["title"]]
    assert refusal_findings


def test_ai_safety_testing_flags_missing_refusal_language():
    def effect(req, timeout=5, context=None, **kw):
        url = getattr(req, "full_url", None) or str(req)
        if "/api/chat" not in url:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return _FakeResp(b'{"reply": "Sure, here you go!"}', status=200,
                          headers={"Content-Type": "application/json"})

    with patch("nexus.tools.ai_security.llm_prompt_injection_testing.safe_urlopen", side_effect=effect), \
         patch("nexus.tools.ai_security.ai_safety_testing.safe_urlopen", side_effect=effect):
        result = ai_safety_testing.run("example.com")

    assert result["status"] == STATUS_COMPLETED
    flagged = [f for f in result["findings"] if "no refusal language observed" in f["title"]]
    assert flagged
    assert flagged[0]["severity"] == "medium"


# ── ai_security.model_evaluation (honest degrade) ────────────────────────────

def test_model_evaluation_requires_file_without_model_or_dataset():
    result = model_evaluation.run("example.com")
    assert result["status"] == STATUS_REQUIRES_FILE
    assert result["metadata"]["have_model"] is False
    assert result["metadata"]["have_eval_dataset"] is False
    assert "held-out" in result["summary"] or "held-out" in result["error"]


def test_model_evaluation_reports_which_inputs_are_present(tmp_path):
    model_file = tmp_path / "model.onnx"
    model_file.write_bytes(b"fake")
    result = model_evaluation.run("example.com", model_path=str(model_file))
    assert result["status"] == STATUS_REQUIRES_FILE
    assert result["metadata"]["have_model"] is True
    assert result["metadata"]["have_eval_dataset"] is False


# ── ai_security.data_poisoning_research (honest degrade) ─────────────────────

def test_data_poisoning_research_requires_file_without_corpus():
    result = data_poisoning_research.run("example.com")
    assert result["status"] == STATUS_REQUIRES_FILE
    assert result["metadata"]["have_training_corpus"] is False
    assert "training corpus" in result["summary"]


def test_data_poisoning_research_and_model_evaluation_have_distinct_explanations():
    poison_result = data_poisoning_research.run("example.com")
    eval_result = model_evaluation.run("example.com")
    assert poison_result["summary"] != eval_result["summary"]
    assert poison_result["error"] != eval_result["error"]


def test_data_poisoning_research_no_findings_on_clean_corpus(tmp_path):
    corpus = tmp_path / "training.csv"
    corpus.write_text("a,b,label\n1,2,0\n")
    result = data_poisoning_research.run("example.com", training_corpus_path=str(corpus))
    # data_poisoning_research.py actually loads and statistically analyzes a
    # provided corpus (label-imbalance/duplicate/outlier checks) rather than
    # honest-degrading once a file is present — a single clean row triggers
    # none of those checks, so this is real "ran and found nothing", not a
    # missing-file degrade.
    assert result["status"] == STATUS_NO_FINDINGS
    assert result["metadata"]["have_training_corpus"] is True
    assert result["metadata"]["row_count"] == 1


def test_data_poisoning_research_real_analysis_flags_imbalance_and_duplicates(tmp_path):
    lines = ["a,b,label"] + ["1,2,benign"] * 19 + ["5,9,malicious"]
    corpus = tmp_path / "training.csv"
    corpus.write_text("\n".join(lines) + "\n")
    result = data_poisoning_research.run("example.com", training_corpus_path=str(corpus))
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("Label Imbalance" in t for t in titles)
    assert any("Duplicate Training Samples" in t for t in titles)
    assert result["metadata"]["row_count"] == 20


# ── reconnaissance.censys_search ─────────────────────────────────────────────

def test_censys_search_requires_credentials_without_env(monkeypatch):
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)
    result = censys_search.run("example.com")
    assert result["status"] == STATUS_REQUIRES_CREDENTIALS
    assert not result["findings"]


def test_censys_search_real_parsing_with_credentials(monkeypatch):
    # censys_search.py was later migrated from the defunct legacy
    # search.censys.io/api/v2 Basic-Auth API (CENSYS_API_ID/SECRET) to the
    # current Censys Platform API, authenticated with a free Personal
    # Access Token (CENSYS_PAT) instead.
    monkeypatch.setenv("CENSYS_PAT", "free-token-123")
    payload = {"result": {"services": [
        {"port": 443, "service_name": "HTTPS", "software": [{"product": "nginx", "version": "1.25"}]},
    ]}}
    with patch("nexus.tools.reconnaissance.censys_search.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("nexus.tools.reconnaissance.censys_search.safe_urlopen", return_value=_json_resp(payload)):
        result = censys_search.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    assert len(result["findings"]) == 1
    assert "nginx" in result["findings"][0]["evidence"]


# ── reconnaissance.shodan_search ─────────────────────────────────────────────

def test_shodan_search_uses_free_internetdb_without_env(monkeypatch):
    # shodan_search.py was later fixed to default to Shodan's free,
    # unauthenticated InternetDB endpoint instead of requiring a paid
    # Search API key — SHODAN_API_KEY unset now means "use the free path",
    # not "requires_credentials".
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    payload = {"ip": "1.2.3.4", "ports": [80], "hostnames": [], "cpes": [], "vulns": []}
    with patch("nexus.tools.reconnaissance.shodan_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", return_value=_json_resp(payload)):
        result = shodan_search.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    assert result["metadata"]["source"] == "internetdb_free"


def test_shodan_search_real_parsing_with_key(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "fakekey")
    payload = {
        "ports": [22, 80],
        "data": [{"port": 22, "product": "OpenSSH", "data": "SSH-2.0-OpenSSH_8.0"}],
        "vulns": ["CVE-2021-1234"],
    }
    with patch("nexus.tools.reconnaissance.shodan_search.socket.gethostbyname", return_value="1.2.3.4"), \
         patch("nexus.tools.reconnaissance.shodan_search.safe_urlopen", return_value=_json_resp(payload)):
        result = shodan_search.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("OpenSSH" in t or "1.2.3.4:22" in t for t in titles)
    assert any("CVE" in t for t in titles)


# ── reconnaissance.github_recon ──────────────────────────────────────────────

def test_github_recon_no_findings_on_empty_search():
    payload = {"total_count": 0, "items": []}
    with patch("nexus.tools.reconnaissance.github_recon.safe_urlopen", return_value=_json_resp(payload)):
        result = github_recon.run("example.com")
    assert result["status"] == STATUS_NO_FINDINGS


def test_github_recon_real_parsing_with_results():
    payload = {"total_count": 2, "items": [
        {"repository": {"full_name": "someorg/leaky-repo"}, "path": "config/prod.env",
         "html_url": "https://github.com/someorg/leaky-repo/blob/main/config/prod.env"},
    ]}
    with patch("nexus.tools.reconnaissance.github_recon.safe_urlopen", return_value=_json_resp(payload)):
        result = github_recon.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    assert "someorg/leaky-repo" in result["findings"][0]["evidence"]


def test_github_recon_rate_limited_reports_unavailable():
    err = urllib.error.HTTPError("url", 403, "Forbidden", {}, None)
    with patch("nexus.tools.reconnaissance.github_recon.safe_urlopen", side_effect=err):
        result = github_recon.run("example.com")
    assert result["status"] == STATUS_UNAVAILABLE


# ── reconnaissance.google_dorking (always-real, no scraping) ────────────────

def test_google_dorking_returns_real_dork_query_content_not_just_an_error():
    result = google_dorking.run("example.com")
    assert result["status"] == STATUS_COMPLETED
    assert result["findings"], "google_dorking must return useful dork-query content, not just an error"
    all_queries = [q for cat in result["metadata"]["dork_queries"].values() for q in cat]
    assert any("site:example.com" in q for q in all_queries)
    assert any("filetype:pdf" in q for q in all_queries)
    assert any("inurl:admin" in q for q in all_queries)
    # every finding's evidence must actually carry query strings a human could run
    for f in result["findings"]:
        assert "site:" in f["evidence"]


# ── reconnaissance.email_harvest ─────────────────────────────────────────────
#
# email_harvest's real technique turned out to be passive DNS-based
# email-infrastructure recon (real MX record lookup + real SPF/DMARC TXT
# record checks via dnspython) plus optional candidate-address pattern
# generation for a supplied employee name — not a scrape of the target's
# own homepage HTML. It can't be pointed at a local HTTP server (there's no
# HTTP fetch in its real path at all), so these tests mock dnspython/socket.

from types import SimpleNamespace


def _mx_answer(host: str):
    return SimpleNamespace(exchange=host)


def _txt_answer(text: str):
    return SimpleNamespace(strings=[text.encode("utf-8")])


def _dns_resolve_side_effect(*, mx=None, spf=None, dmarc=None):
    mx = mx if mx is not None else []
    txt = [_txt_answer(spf)] if spf else []
    dmarc_txt = [_txt_answer(dmarc)] if dmarc else []

    def _resolve(qname, rdtype, lifetime=None):
        if rdtype == "MX":
            return [_mx_answer(h) for h in mx]
        if rdtype == "TXT":
            if str(qname).startswith("_dmarc."):
                if not dmarc_txt:
                    raise Exception("NXDOMAIN")
                return dmarc_txt
            if not txt:
                raise Exception("NXDOMAIN")
            return txt
        raise ValueError(f"unexpected rdtype {rdtype}")

    return _resolve


def test_email_harvest_real_dns_parsing_reports_present_spf_dmarc_and_mx():
    effect = _dns_resolve_side_effect(
        mx=["mail.corp-example.com."],
        spf="v=spf1 include:_spf.google.com ~all",
        dmarc="v=DMARC1; p=reject",
    )
    with patch("nexus.tools.reconnaissance.email_harvest.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("dns.resolver.resolve", side_effect=effect):
        result = email_harvest.run("corp-example.com")

    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("Mail infrastructure discovered" in t for t in titles)
    assert any("SPF record present" in t for t in titles)
    assert any("DMARC record present" in t for t in titles)
    assert result["metadata"]["mx_hosts"] == ["mail.corp-example.com"]
    assert result["metadata"]["spf_present"] is True
    assert result["metadata"]["dmarc_present"] is True


def test_email_harvest_flags_missing_spf_and_dmarc():
    effect = _dns_resolve_side_effect(mx=[], spf=None, dmarc=None)
    with patch("nexus.tools.reconnaissance.email_harvest.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("dns.resolver.resolve", side_effect=effect):
        result = email_harvest.run("corp-example.com")

    assert result["status"] == STATUS_COMPLETED
    titles = [f["title"] for f in result["findings"]]
    assert any("No SPF record found" in t for t in titles)
    assert any("No DMARC record found" in t for t in titles)
    spf_finding = next(f for f in result["findings"] if "No SPF record found" in f["title"])
    assert spf_finding["severity"] == "medium"


def test_email_harvest_generates_candidate_patterns_for_employee_name():
    effect = _dns_resolve_side_effect(mx=["mail.corp-example.com."], spf="v=spf1 ~all", dmarc="v=DMARC1; p=none")
    with patch("nexus.tools.reconnaissance.email_harvest.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("dns.resolver.resolve", side_effect=effect):
        result = email_harvest.run("corp-example.com", employee_name="Jane Doe")

    generated = result["metadata"]["generated_email_patterns"]
    assert "jane.doe@corp-example.com" in generated
    assert "jdoe@corp-example.com" in generated


def test_email_harvest_failed_on_dns_resolution_error():
    with patch("nexus.tools.reconnaissance.email_harvest.socket.gethostbyname",
               side_effect=socket_module.gaierror("no such host")):
        result = email_harvest.run("nonexistent-domain-xyz.invalid")
    assert result["status"] == STATUS_FAILED


# ── reconnaissance.social_osint ──────────────────────────────────────────────
#
# social_osint's real technique is a ToS-friendly HEAD-request presence
# check against a fixed list of public platform URL patterns (GitHub, npm,
# PyPI, LinkedIn, X, Crunchbase) — not a scrape of the target's own
# homepage. That means it can't be pointed at a local server (the URLs are
# hardcoded to the real platforms), so these tests mock safe_urlopen.

def test_social_osint_no_findings_when_no_presence():
    with patch("nexus.tools.reconnaissance.social_osint.safe_urlopen", side_effect=_all_404_side_effect):
        result = social_osint.run("some-obscure-org-name-xyz")
    assert result["status"] == STATUS_NO_FINDINGS


def test_social_osint_real_parsing_finds_platform_presence():
    def effect(req, timeout=6, context=None, **kw):
        url = getattr(req, "full_url", None) or str(req)
        if "github.com/acmecorp" in url and "orgs" not in url:
            return _FakeResp(b"", status=200)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    with patch("nexus.tools.reconnaissance.social_osint.safe_urlopen", side_effect=effect):
        result = social_osint.run("AcmeCorp")

    assert result["status"] == STATUS_COMPLETED
    assert len(result["findings"]) == 1
    assert "GitHub" in result["findings"][0]["title"]
    assert "github.com/acmecorp" in result["findings"][0]["evidence"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
