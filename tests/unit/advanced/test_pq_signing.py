"""Tests for nexus.advanced.pq_signing.

If no post-quantum signing backend is available in this environment, we
only assert the module imports cleanly and raises PQSigningError with the
documented message. In this codebase's actual test environment,
cryptography>=45's built-in ML-DSA-65 support IS available, so we also
exercise a real generate/sign/verify/tamper-detect/persistence round trip
against an isolated, temp-dir-backed secrets vault (never the real one).
"""
import pytest

from nexus.advanced.pq_signing import PQSigner, PQSigningError, _HAVE_MLDSA
from nexus.foundation.secrets import SecretsManager


@pytest.fixture
def vault(tmp_path):
    return SecretsManager(vault_dir=tmp_path)


def test_module_imports_cleanly():
    import nexus.advanced.pq_signing  # noqa: F401


@pytest.mark.skipif(_HAVE_MLDSA, reason="ML-DSA IS available in this environment; degraded-path test not applicable")
def test_raises_clear_error_when_backend_missing(tmp_path, vault):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("hello")
    signer = PQSigner(vault=vault)
    with pytest.raises(PQSigningError, match="No post-quantum signing library available"):
        signer.sign_evidence(str(evidence))


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA backend not available in this environment")
def test_sign_and_verify_roundtrip(tmp_path, vault):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("nexus-strike pq signing test\n")

    signer = PQSigner(vault=vault)
    signature = signer.sign_evidence(str(evidence))
    assert isinstance(signature, bytes) and len(signature) > 0
    assert signer.verify_evidence(str(evidence), signature) is True


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA backend not available in this environment")
def test_verify_fails_on_tampered_file(tmp_path, vault):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("original content")

    signer = PQSigner(vault=vault)
    signature = signer.sign_evidence(str(evidence))

    evidence.write_text("tampered content")
    assert signer.verify_evidence(str(evidence), signature) is False


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA backend not available in this environment")
def test_verify_fails_on_wrong_signature(tmp_path, vault):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("some evidence")
    signer = PQSigner(vault=vault)
    signer.sign_evidence(str(evidence))
    assert signer.verify_evidence(str(evidence), b"not-a-real-signature") is False


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA backend not available in this environment")
def test_key_persists_across_signer_instances(tmp_path, vault):
    signer1 = PQSigner(vault=vault)
    pub1 = signer1.public_key_bytes()

    signer2 = PQSigner(vault=vault)
    pub2 = signer2.public_key_bytes()

    assert pub1 == pub2


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA backend not available in this environment")
def test_rotate_key_changes_public_key(tmp_path, vault):
    signer = PQSigner(vault=vault)
    pub_before = signer.public_key_bytes()
    pub_after = signer.rotate_key()
    assert pub_before != pub_after
    assert signer.public_key_bytes() == pub_after


@pytest.mark.skipif(not _HAVE_MLDSA, reason="ML-DSA backend not available in this environment")
def test_sign_missing_file_raises(tmp_path, vault):
    signer = PQSigner(vault=vault)
    with pytest.raises(PQSigningError, match="No such file"):
        signer.sign_evidence(str(tmp_path / "nope.txt"))
