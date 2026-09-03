"""Tests for nexus.advanced.notarization.

If opentimestamps-client isn't installed in the test environment, we only
assert the module imports cleanly and raises NotarizationError with the
documented message rather than crashing. If it IS installed, we also do a
real (network-touching) notarize()/verify() round trip against the live
OpenTimestamps calendar servers, marked so it can be skipped in offline
CI environments.
"""
import os

import pytest

from nexus.advanced.notarization import EvidenceNotary, NotarizationError, _HAVE_OTS


def test_module_imports_cleanly():
    # Importing this module must never raise, regardless of whether the
    # opentimestamps-client dependency is installed.
    import nexus.advanced.notarization  # noqa: F401


@pytest.mark.skipif(_HAVE_OTS, reason="opentimestamps-client IS installed; degraded-path test not applicable")
def test_raises_clear_error_when_dependency_missing(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("hello")
    notary = EvidenceNotary()
    with pytest.raises(NotarizationError, match="opentimestamps-client is not installed"):
        notary.notarize(str(evidence))


@pytest.mark.skipif(not _HAVE_OTS, reason="opentimestamps-client not installed")
def test_notarize_missing_file_raises(tmp_path):
    notary = EvidenceNotary()
    with pytest.raises(NotarizationError, match="No such file"):
        notary.notarize(str(tmp_path / "does_not_exist.txt"))


@pytest.mark.skipif(not _HAVE_OTS, reason="opentimestamps-client not installed")
@pytest.mark.skipif(
    os.environ.get("NEXUS_SKIP_NETWORK_TESTS") == "1",
    reason="network-touching test disabled via NEXUS_SKIP_NETWORK_TESTS",
)
def test_notarize_and_verify_pending_roundtrip(tmp_path):
    """Real round trip against the live OpenTimestamps calendar network.
    A stamp created moments ago is expected to come back as 'pending' —
    see the module docstring on why that's correct, not a bug."""
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("nexus-strike notarization test\n")

    notary = EvidenceNotary()
    ots_path = notary.notarize(str(evidence))
    assert os.path.isfile(ots_path)
    assert ots_path == str(evidence) + ".ots"

    status = notary.verify(str(evidence))
    assert status["state"] in ("pending", "confirmed")
    assert isinstance(status["digest"], str) and len(status["digest"]) == 64
    assert status["attestations"]  # at least one calendar accepted the digest

    # verify() also accepts the .ots path directly
    status2 = notary.verify(ots_path)
    assert status2["digest"] == status["digest"]


@pytest.mark.skipif(not _HAVE_OTS, reason="opentimestamps-client not installed")
def test_verify_missing_receipt_raises(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("hello")
    notary = EvidenceNotary()
    with pytest.raises(NotarizationError, match="No .ots receipt found"):
        notary.verify(str(evidence))
