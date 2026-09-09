"""ghidra_analysis.py/ida_analysis.py overclaimed capability (named "Ghidra
Analysis"/"IDA Analysis" but only ever did file-magic/hash inspection,
never invoked either tool) and tls_testing.py's findings had no explicit
severity (a weak cipher or expired cert silently landed at default "info"
since severity was only string-keyword-inferred). Caught during this
session's audit."""
import datetime
from unittest.mock import MagicMock, patch

import pytest

from nexus.tools.cryptography import tls_testing
from nexus.tools.reverse_engineering import ghidra_analysis, ida_analysis


# ── ghidra_analysis.py ───────────────────────────────────────────────────

def test_ghidra_analysis_honest_when_not_installed(tmp_path, monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    with patch("shutil.which", return_value=None):
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 20)
        result = ghidra_analysis.run(str(sample))

    joined = "\n".join(result["findings"])
    assert "Ghidra not detected" in joined
    assert "Full disassembly/decompilation was not performed" in joined
    assert "Ghidra headless analysis completed" not in joined


def test_ghidra_analysis_invokes_real_headless_when_found(tmp_path):
    # Mocking os.path.join/isfile globally corrupts tempfile.TemporaryDirectory's
    # own internal path handling (it uses os.path.join heavily) — mock
    # _find_analyze_headless directly instead, which is the actual
    # detection seam this test cares about. Ghidra invocation now goes
    # through nexus.tools.sandbox.run_subprocess (real CPU/memory limits
    # on an untrusted-binary decompile — see ghidra_analysis.py), so the
    # mock target moved from the removed direct `subprocess.run` call.
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 20)

    fake_result = MagicMock(stdout="INFO  Analysis complete.\n", stderr=None, returncode=0)
    with patch.object(ghidra_analysis, "_find_analyze_headless", return_value="/opt/ghidra/support/analyzeHeadless"), \
         patch("nexus.tools.reverse_engineering.ghidra_analysis.run_subprocess", return_value=fake_result) as mock_run:
        result = ghidra_analysis.run(str(sample))

    assert mock_run.called
    assert mock_run.call_args.kwargs.get("cpu_seconds") == ghidra_analysis._GHIDRA_CPU_LIMIT_S
    assert mock_run.call_args.kwargs.get("memory_mb") == ghidra_analysis._GHIDRA_MEMORY_LIMIT_MB
    joined = "\n".join(result["findings"])
    assert "Ghidra headless analysis completed" in joined
    assert "Ghidra not detected" not in joined


def test_ghidra_analysis_timeout_reported_honestly(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 20)

    with patch.object(ghidra_analysis, "_find_analyze_headless", return_value="/opt/ghidra/support/analyzeHeadless"), \
         patch(
             "nexus.tools.reverse_engineering.ghidra_analysis.run_subprocess",
             side_effect=ghidra_analysis.SandboxError("Command exceeded timeout of 60s: analyzeHeadless"),
         ):
        result = ghidra_analysis.run(str(sample))

    assert any("exceeded" in f and "timeout" in f for f in result["findings"])


def test_ghidra_analysis_resource_limit_violation_reported_honestly(tmp_path):
    """A pathologically-crafted sample driving the headless analyzer past
    its CPU/memory ceiling must be reported distinctly from a plain
    timeout — this is the resource-sandboxing layer added alongside the
    Ghidra migration to nexus.tools.sandbox.run_subprocess."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 20)

    with patch.object(ghidra_analysis, "_find_analyze_headless", return_value="/opt/ghidra/support/analyzeHeadless"), \
         patch(
             "nexus.tools.reverse_engineering.ghidra_analysis.run_subprocess",
             side_effect=ghidra_analysis.SandboxError(
                 "Command exceeded resource limit: memory usage 2100.0MB exceeded limit 2048.0MB: analyzeHeadless"
             ),
         ):
        result = ghidra_analysis.run(str(sample))

    joined = "\n".join(result["findings"])
    assert "CPU/memory limit" in joined
    assert "no disassembly results captured" in joined


# ── ida_analysis.py ───────────────────────────────────────────────────────

def test_ida_analysis_always_honest_about_no_headless_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 20)
    result = ida_analysis.run(str(sample))
    joined = "\n".join(result["findings"])
    assert "IDA Pro is a licensed product" in joined
    assert "Full disassembly/decompilation was not performed" in joined


# ── tls_testing.py ───────────────────────────────────────────────────────

class _FakeSSLSocket:
    def __init__(self, cipher_name, proto, not_after):
        self._cipher_name = cipher_name
        self._proto = proto
        self._not_after = not_after

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getpeercert(self):
        return {"subject": ((("commonName", "example.com"),),), "notAfter": self._not_after}

    def cipher(self):
        return (self._cipher_name, self._proto, 256)

    def version(self):
        return self._proto


def _fake_ctx(cipher_name, proto, not_after):
    ctx = MagicMock()
    ctx.wrap_socket.return_value = _FakeSSLSocket(cipher_name, proto, not_after)
    return ctx


def _future_cert_date(days: int) -> str:
    return (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(days=days)).strftime("%b %d %H:%M:%S %Y GMT")


def test_tls_testing_flags_weak_protocol_and_cipher_as_high_severity():
    ctx = _fake_ctx("RC4-SHA", "TLSv1", _future_cert_date(400))
    fake_conn = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.__exit__.return_value = False

    with patch("nexus.tools.cryptography.tls_testing.get_ssl_context", return_value=ctx), \
         patch("socket.create_connection", return_value=fake_conn):
        result = tls_testing.run("example.com", ports=[443])

    severities_by_title = {f["title"]: f["severity"] for f in result["findings"]}
    proto_finding = next(t for t in severities_by_title if t.startswith("TLS protocol"))
    cipher_finding = next(t for t in severities_by_title if t.startswith("TLS cipher"))
    assert severities_by_title[proto_finding] == "high"
    assert severities_by_title[cipher_finding] == "high"


def test_tls_testing_strong_config_is_info_severity():
    ctx = _fake_ctx("TLS_AES_256_GCM_SHA384", "TLSv1.3", _future_cert_date(400))
    fake_conn = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.__exit__.return_value = False

    with patch("nexus.tools.cryptography.tls_testing.get_ssl_context", return_value=ctx), \
         patch("socket.create_connection", return_value=fake_conn):
        result = tls_testing.run("example.com", ports=[443])

    assert all(f["severity"] == "info" for f in result["findings"])


def test_tls_testing_expiring_soon_certificate_is_medium_severity():
    ctx = _fake_ctx("TLS_AES_256_GCM_SHA384", "TLSv1.3", _future_cert_date(10))
    fake_conn = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.__exit__.return_value = False

    with patch("nexus.tools.cryptography.tls_testing.get_ssl_context", return_value=ctx), \
         patch("socket.create_connection", return_value=fake_conn):
        result = tls_testing.run("example.com", ports=[443])

    cert_finding = next(f for f in result["findings"] if f["title"].startswith("Certificate"))
    assert cert_finding["severity"] == "medium"


def test_tls_testing_expired_certificate_is_critical_severity():
    expired = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    ctx = _fake_ctx("TLS_AES_256_GCM_SHA384", "TLSv1.3", expired)
    fake_conn = MagicMock()
    fake_conn.__enter__.return_value = fake_conn
    fake_conn.__exit__.return_value = False

    with patch("nexus.tools.cryptography.tls_testing.get_ssl_context", return_value=ctx), \
         patch("socket.create_connection", return_value=fake_conn):
        result = tls_testing.run("example.com", ports=[443])

    cert_finding = next(f for f in result["findings"] if f["title"].startswith("Certificate"))
    assert cert_finding["severity"] == "critical"
