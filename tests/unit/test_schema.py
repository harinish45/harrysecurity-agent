"""Finding.id was documented as "Auto-assigned" but never actually was for
the common case (a Finding built from a plain dict, e.g. every agent that
returns {"title": ..., "severity": ...}) — it silently stayed "" all the way
through report generation, rendering as a blank ID everywhere."""
from nexus.foundation.schema import Finding, normalize_findings


def test_finding_gets_a_real_id_when_none_given():
    f = Finding(title="Open port 22", severity="medium")
    assert f.id
    assert f.id.startswith("F-")


def test_finding_keeps_an_explicitly_given_id():
    f = Finding(id="CUSTOM-001", title="x")
    assert f.id == "CUSTOM-001"


def test_two_findings_with_no_id_get_different_ids():
    """Random, not sequential — Finding objects are routinely built
    independently across concurrent FlowController batches, where a shared
    sequential counter isn't available."""
    a = Finding(title="a")
    b = Finding(title="b")
    assert a.id != b.id


def test_normalize_findings_backfills_id_for_dict_input():
    normalised = normalize_findings([{"title": "SQL injection", "severity": "critical"}])
    assert normalised[0]["id"]
    assert normalised[0]["id"] != ""


def test_normalize_findings_backfills_id_for_finding_instance_input():
    normalised = normalize_findings([Finding(title="XSS", severity="high")])
    assert normalised[0]["id"]


def test_normalize_findings_assigns_sequential_id_for_raw_string_input():
    normalised = normalize_findings(["Open port 22 detected (medium)"])
    assert normalised[0]["id"] == "F-001"
