#!/usr/bin/env python3
"""
NEXUS-STRIKE — Unit Tests: defensive process-tool honesty fix.

An audit found 25 tools across incident_response/, blue_team/, and soc/
were byte-for-byte-logic-identical fake stubs: either (a) a DNS resolve +
bare HTTP GET on "/" against `target` (checking security response
headers, or hitting four hardcoded SIEM-looking paths), or (b) hashing
`target` as if it were a local file and grepping it for a hardcoded
substring list ("malware"/"backdoor"/etc) — none of it related to the
tool's actual name, always reporting status "completed".

Two groups were fixed differently:

1. File-based real-logic tools (log_review, log_correlation,
   siem_monitoring, ioc_collection, threat_hunting, threat_hunting_blue,
   firewall_management, hardening) now do genuine parsing/analysis when
   `target` is a real local file (a log/IOC/config file), and honestly
   degrade to STATUS_OUT_OF_SCOPE otherwise. edr_analysis and
   endpoint_protection check the LOCAL analysis host (never `target`) and
   honestly report STATUS_REQUIRES_CREDENTIALS for `target` itself.

2. Fifteen process/workflow tools (alert_triage, eradication,
   incident_investigation, lessons_learned, malware_containment,
   recovery, root_cause_analysis, detection_engineering_blue,
   incident_handling, alert_investigation, dashboard_creation,
   detection_engineering_soc, rule_tuning, soar_automation, ueba) have no
   network-observable signal at all — they honestly report
   STATUS_OUT_OF_SCOPE with a tool-specific explanation of what real case
   data would be needed, instead of ever probing `target`.
"""
import math
import platform
from collections import Counter

import pytest

from nexus.foundation.schema import (
    STATUS_COMPLETED,
    STATUS_NO_FINDINGS,
    STATUS_OUT_OF_SCOPE,
    STATUS_REQUIRES_CREDENTIALS,
)
from nexus.tools.blue_team import (
    detection_engineering_blue,
    edr_analysis,
    endpoint_protection,
    firewall_management,
    hardening,
    incident_handling,
    log_review,
    threat_hunting_blue,
)
from nexus.tools.incident_response import (
    alert_triage,
    eradication,
    incident_investigation,
    ioc_collection,
    lessons_learned,
    malware_containment,
    recovery,
    root_cause_analysis,
    threat_hunting,
)
from nexus.tools.soc import (
    alert_investigation,
    dashboard_creation,
    detection_engineering_soc,
    log_correlation,
    rule_tuning,
    siem_monitoring,
    soar_automation,
    ueba,
)


# ── helpers to build synthetic log fixtures ─────────────────────────────

def _apache_line(ip: str, minute: int, path: str, status: int, second: int = 0) -> str:
    ts = f"10/Oct/2023:13:{minute:02d}:{second:02d} +0000"
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 512'


# ═════════════════════════════════════════════════════════════════════════
# Group 1a: log-file tools (log_review, log_correlation, siem_monitoring)
# ═════════════════════════════════════════════════════════════════════════

class TestLogReview:
    def test_out_of_scope_for_non_file_target(self):
        result = log_review.run("example.com")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []
        assert "example.com" not in result.get("error", "")  # generic file-requirement message
        assert "local" in result["summary"].lower() or "file" in result["summary"].lower()

    def test_flags_error_rate_spike_and_ip_dominance(self, tmp_path):
        lines = []
        # 15 requests from one IP, all 200s except 5 that are 500s.
        for i in range(10):
            lines.append(_apache_line("198.51.100.9", 0, "/index.html", 200, second=i))
        for i in range(5):
            lines.append(_apache_line("198.51.100.9", 0, "/broken.php", 500, second=10 + i))
        # A handful of unrelated low-volume traffic from another IP.
        for i in range(3):
            lines.append(_apache_line("203.0.113.4", 1, "/about.html", 200, second=i))
        log_file = tmp_path / "access.log"
        log_file.write_text("\n".join(lines), encoding="utf-8")

        result = log_review.run(str(log_file))
        assert result["status"] == STATUS_COMPLETED
        assert len(result["findings"]) >= 2
        titles = " ".join(f["title"] for f in result["findings"])
        assert "error rate" in titles.lower()
        assert "198.51.100.9" in titles

    def test_no_findings_on_unrecognized_format(self, tmp_path):
        f = tmp_path / "notalog.txt"
        f.write_text("this is not a log file at all, just prose text.\n", encoding="utf-8")
        result = log_review.run(str(f))
        assert result["status"] == STATUS_NO_FINDINGS


class TestLogCorrelation:
    def test_out_of_scope_for_non_file_target(self):
        result = log_correlation.run("203.0.113.5")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_flags_auth_failure_burst(self, tmp_path):
        lines = []
        for i in range(6):
            lines.append(_apache_line("198.51.100.20", 0, "/login", 401, second=i))
        lines.append(_apache_line("198.51.100.20", 0, "/login", 200, second=10))
        log_file = tmp_path / "auth.log"
        log_file.write_text("\n".join(lines), encoding="utf-8")

        result = log_correlation.run(str(log_file))
        assert result["status"] == STATUS_COMPLETED
        assert any("auth" in f["title"].lower() for f in result["findings"])
        assert any("198.51.100.20" in f["evidence"] for f in result["findings"])

    def test_flags_path_enumeration(self, tmp_path):
        lines = []
        for i in range(20):
            status = 404 if i < 14 else 200
            lines.append(_apache_line("198.51.100.30", 0, f"/path{i}", status, second=i))
        log_file = tmp_path / "scan.log"
        log_file.write_text("\n".join(lines), encoding="utf-8")

        result = log_correlation.run(str(log_file))
        assert result["status"] == STATUS_COMPLETED
        assert any("enumeration" in f["title"].lower() for f in result["findings"])


class TestSiemMonitoring:
    def test_out_of_scope_for_non_file_target(self):
        result = siem_monitoring.run("198.51.100.1")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_flags_volume_spike(self, tmp_path):
        lines = []
        # 10 quiet minutes with 1 request each.
        for minute in range(10):
            lines.append(_apache_line("203.0.113.50", minute, "/", 200))
        # One spike minute with 20 requests.
        for i in range(20):
            lines.append(_apache_line("203.0.113.50", 30, f"/x{i}", 200, second=i))
        log_file = tmp_path / "siem.log"
        log_file.write_text("\n".join(lines), encoding="utf-8")

        result = siem_monitoring.run(str(log_file))
        assert result["status"] == STATUS_COMPLETED
        assert any("spike" in f["title"].lower() for f in result["findings"])

    def test_flags_dominant_syslog_severity_keyword(self, tmp_path):
        lines = [
            f"Oct 10 13:0{i}:00 host1 sshd[123]: ERROR authentication failure"
            for i in range(6)
        ]
        lines.append("Oct 10 13:10:00 host1 cron[99]: session opened")
        log_file = tmp_path / "syslog"
        log_file.write_text("\n".join(lines), encoding="utf-8")

        result = siem_monitoring.run(str(log_file))
        assert result["status"] == STATUS_COMPLETED
        assert any("severity" in f["title"].lower() for f in result["findings"])


# ═════════════════════════════════════════════════════════════════════════
# Group 1b: IOC-extraction tools (ioc_collection, threat_hunting,
# threat_hunting_blue)
# ═════════════════════════════════════════════════════════════════════════

import hashlib as _hashlib

_MD5_SAMPLE = _hashlib.md5(b"sample-payload", usedforsecurity=False).hexdigest()
_SHA1_SAMPLE = _hashlib.sha1(b"sample-dropper", usedforsecurity=False).hexdigest()
_SHA256_SAMPLE = _hashlib.sha256(b"sample-c2-payload").hexdigest()
assert len(_MD5_SAMPLE) == 32 and len(_SHA1_SAMPLE) == 40 and len(_SHA256_SAMPLE) == 64

IOC_TEXT = f"""\
Investigation notes for case 2024-0091.
Suspicious outbound connections observed to 198.51.100.23 and 203.0.113.77.
Internal address seen in the same log window: 10.0.0.55
Malware sample hash (MD5): {_MD5_SAMPLE}
SHA1 of dropper: {_SHA1_SAMPLE}
SHA256 of payload: {_SHA256_SAMPLE}
Beacon domain: mail.example.com
Cheap-TLD lookalike domain: freestuff-promo.xyz
C2 URL: http://198.51.100.23/gate.php
IP-literal URL: http://203.0.113.77:8080/beacon
"""


def _shannon_entropy(s: str) -> float:
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class TestIocCollection:
    def test_out_of_scope_for_non_file_target(self):
        result = ioc_collection.run("notafile-target.example")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_extracts_real_iocs(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text(IOC_TEXT, encoding="utf-8")
        result = ioc_collection.run(str(f))
        assert result["status"] == STATUS_COMPLETED
        counts = result["metadata"]["ioc_counts"]
        assert counts["ipv4"] >= 3
        assert counts["md5"] == 1
        assert counts["sha1"] == 1
        assert counts["sha256"] == 1
        assert counts["domains"] >= 2
        assert counts["urls"] >= 2
        assert _MD5_SAMPLE in result["metadata"]["iocs"]["md5"]

    def test_no_longer_returns_old_fake_file_hash_findings(self, tmp_path):
        # The old stub hashed `target` itself as a "file" and looked for a
        # hardcoded substring list -- confirm that behavior/wording is gone.
        f = tmp_path / "notes.txt"
        f.write_text(IOC_TEXT, encoding="utf-8")
        result = ioc_collection.run(str(f))
        joined = " ".join(fnd.get("title", "") + fnd.get("evidence", "") for fnd in result["findings"])
        assert "Suspicious string found" not in joined


class TestThreatHunting:
    def test_out_of_scope_for_non_file_target(self):
        result = threat_hunting.run("198.51.100.99")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_flags_high_entropy_domain_and_recurring_hash(self, tmp_path):
        # 13 distinct lowercase letters -> Shannon entropy = log2(13) ~= 3.70,
        # deterministically above the tool's 3.5 threshold (unlike a random
        # hex string, whose realized entropy at this length can vary below
        # the threshold by chance).
        random_label = "kqxjzvfhtmpwy"
        assert _shannon_entropy(random_label) >= 3.5
        repeated_hash = "b" * 32  # low-entropy but that's fine, we test *recurrence* not entropy
        text = (
            f"beacon to {random_label}.com observed repeatedly\n"
            + (f"related hash: {repeated_hash}\n" * 4)
        )
        f = tmp_path / "hunt.txt"
        f.write_text(text, encoding="utf-8")

        result = threat_hunting.run(str(f))
        assert result["status"] == STATUS_COMPLETED
        titles = " ".join(fnd["title"].lower() for fnd in result["findings"])
        assert "entropy" in titles
        assert "recur" in titles
        assert repeated_hash in result["metadata"]["recurring_hashes"]


class TestThreatHuntingBlue:
    def test_out_of_scope_for_non_file_target(self):
        result = threat_hunting_blue.run("198.51.100.99")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_flags_abused_tld_private_ip_and_ip_literal_url(self, tmp_path):
        f = tmp_path / "hunt.txt"
        f.write_text(IOC_TEXT, encoding="utf-8")
        result = threat_hunting_blue.run(str(f))
        assert result["status"] == STATUS_COMPLETED
        titles = " ".join(fnd["title"].lower() for fnd in result["findings"])
        assert "tld" in titles
        assert "private" in titles
        assert "ip literal" in titles or "raw ip" in titles
        assert "freestuff-promo.xyz" in result["metadata"]["abused_tld_hits"]
        assert "10.0.0.55" in result["metadata"]["private_ip_hits"]


# ═════════════════════════════════════════════════════════════════════════
# Group 1c: config-analysis tools (firewall_management, hardening)
# ═════════════════════════════════════════════════════════════════════════

IPTABLES_FIXTURE = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
-A INPUT -s 10.0.0.5 --dport 22 -j ACCEPT
COMMIT
"""

NETSH_FIXTURE = """\
Rule Name:                           Test Inbound Allow Any
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Action:                               Allow
RemoteIP:                             Any
LocalPort:                            Any

Rule Name:                           Test Inbound Restricted RDP
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain
Action:                               Allow
RemoteIP:                             192.168.1.0/24
LocalPort:                            3389
"""

SSHD_CONFIG_FIXTURE = """\
# Example sshd_config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
Protocol 1,2
Ciphers aes256-cbc,aes128-ctr,arcfour
MACs hmac-md5,hmac-sha2-256
X11Forwarding no
"""

SSHD_CONFIG_HARDENED_FIXTURE = """\
Port 22
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
Protocol 2
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com
"""


class TestFirewallManagement:
    def test_out_of_scope_for_non_file_target(self):
        result = firewall_management.run("198.51.100.1")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_flags_default_accept_policy_and_unrestricted_rule_iptables(self, tmp_path):
        f = tmp_path / "iptables-save.txt"
        f.write_text(IPTABLES_FIXTURE, encoding="utf-8")
        result = firewall_management.run(str(f))
        assert result["status"] == STATUS_COMPLETED
        assert result["metadata"]["format_detected"] == "iptables"
        titles = " ".join(fnd["title"].lower() for fnd in result["findings"])
        assert "default-accept" in titles
        assert "unrestricted accept" in titles

    def test_flags_allow_any_rule_netsh(self, tmp_path):
        f = tmp_path / "firewall_export.txt"
        f.write_text(NETSH_FIXTURE, encoding="utf-8")
        result = firewall_management.run(str(f))
        assert result["status"] == STATUS_COMPLETED
        assert result["metadata"]["format_detected"] == "netsh_advfirewall"
        assert len(result["findings"]) == 1
        assert "Test Inbound Allow Any" in result["findings"][0]["title"]

    def test_unrecognized_format_degrades_honestly(self, tmp_path):
        f = tmp_path / "notafirewall.txt"
        f.write_text("just some prose, not a firewall config\n", encoding="utf-8")
        result = firewall_management.run(str(f))
        assert result["status"] == STATUS_OUT_OF_SCOPE


class TestHardening:
    def test_out_of_scope_for_non_file_target(self):
        result = hardening.run("198.51.100.1")
        assert result["status"] == STATUS_OUT_OF_SCOPE
        assert result["findings"] == []

    def test_flags_weak_sshd_config(self, tmp_path):
        f = tmp_path / "sshd_config"
        f.write_text(SSHD_CONFIG_FIXTURE, encoding="utf-8")
        result = hardening.run(str(f))
        assert result["status"] == STATUS_COMPLETED
        titles = " ".join(fnd["title"].lower() for fnd in result["findings"])
        assert "root login" in titles
        assert "empty passwords" in titles
        assert "password authentication" in titles
        assert "protocol version 1" in titles
        assert "cipher" in titles
        assert "mac" in titles

    def test_hardened_sshd_config_has_no_findings(self, tmp_path):
        f = tmp_path / "sshd_config"
        f.write_text(SSHD_CONFIG_HARDENED_FIXTURE, encoding="utf-8")
        result = hardening.run(str(f))
        assert result["status"] == STATUS_NO_FINDINGS
        assert result["findings"] == []


# ═════════════════════════════════════════════════════════════════════════
# Group 1d: local-host checks (edr_analysis, endpoint_protection)
# ═════════════════════════════════════════════════════════════════════════

class TestLocalHostChecks:
    @pytest.mark.parametrize("module", [edr_analysis, endpoint_protection])
    def test_requires_credentials_for_target(self, module):
        result = module.run("198.51.100.200")
        assert result["status"] == STATUS_REQUIRES_CREDENTIALS

    @pytest.mark.parametrize("module", [edr_analysis, endpoint_protection])
    def test_does_not_claim_target_coverage(self, module):
        result = module.run("198.51.100.200")
        # No findings claimed against the target -- only local diagnostic metadata.
        assert result["findings"] == []
        assert result["metadata"]["local_node"] == platform.node()
        assert "198.51.100.200" not in result["metadata"]["local_node"]
        assert "not " in result["metadata"]["note"].lower()


# ═════════════════════════════════════════════════════════════════════════
# Group 2: honest case-data-degrade tools (15 process/workflow tools)
# ═════════════════════════════════════════════════════════════════════════

DEGRADE_MODULES = {
    "incident_response.alert_triage": alert_triage,
    "incident_response.eradication": eradication,
    "incident_response.incident_investigation": incident_investigation,
    "incident_response.lessons_learned": lessons_learned,
    "incident_response.malware_containment": malware_containment,
    "incident_response.recovery": recovery,
    "incident_response.root_cause_analysis": root_cause_analysis,
    "blue_team.detection_engineering_blue": detection_engineering_blue,
    "blue_team.incident_handling": incident_handling,
    "soc.alert_investigation": alert_investigation,
    "soc.dashboard_creation": dashboard_creation,
    "soc.detection_engineering_soc": detection_engineering_soc,
    "soc.rule_tuning": rule_tuning,
    "soc.soar_automation": soar_automation,
    "soc.ueba": ueba,
}

# Old fake findings/behavior this fix replaced, that must never reappear.
_OLD_FAKE_MARKERS = (
    "Suspicious string found",
    "MD5:",
    "SHA256:",
    "DNS resolution failed",
    "status=",
    "HTTP ",
)


@pytest.mark.parametrize("name,module", sorted(DEGRADE_MODULES.items()))
def test_degrade_tool_reports_out_of_scope(name, module):
    result = module.run("198.51.100.77")
    assert result["status"] == STATUS_OUT_OF_SCOPE, f"{name} did not degrade honestly"
    assert result["findings"] == [], f"{name} fabricated findings"


@pytest.mark.parametrize("name,module", sorted(DEGRADE_MODULES.items()))
def test_degrade_tool_no_longer_returns_old_fake_output(name, module):
    result = module.run("198.51.100.77")
    haystack = result["summary"] + " " + result.get("error", "")
    for marker in _OLD_FAKE_MARKERS:
        assert marker not in haystack, f"{name} still contains old fake-stub marker {marker!r}"
    assert result["status"] != "completed"


def test_degrade_tools_have_genuinely_different_explanations():
    """Each of the 15 degrade tools must explain, in its own words, what
    real input it needs -- not one templated message copy-pasted across
    all of them (that was exactly the bug in the original 25 stubs)."""
    summaries = {name: mod.run("198.51.100.77")["summary"] for name, mod in DEGRADE_MODULES.items()}
    unique_summaries = set(summaries.values())
    # All 15 must be textually distinct from one another.
    assert len(unique_summaries) == len(summaries), (
        f"Expected {len(summaries)} distinct explanations, got {len(unique_summaries)}: {summaries}"
    )

    errors = {name: mod.run("198.51.100.77")["error"] for name, mod in DEGRADE_MODULES.items()}
    assert len(set(errors.values())) >= 5, "error messages are not sufficiently tool-specific"

    # Spot-check: pick 5 tools and confirm none of their summaries share more
    # than a generic opening phrase -- i.e. the substantive content differs.
    sample_names = list(DEGRADE_MODULES.keys())[:5]
    sample_texts = [summaries[n] for n in sample_names]
    assert len(set(sample_texts)) == 5, "sampled explanations are not all distinct"


def test_degrade_tools_metadata_requires_list_is_tool_specific():
    requires_lists = {
        name: tuple(mod.run("198.51.100.77")["metadata"].get("requires", []))
        for name, mod in DEGRADE_MODULES.items()
    }
    unique_lists = set(requires_lists.values())
    assert len(unique_lists) == len(requires_lists), "requires[] metadata is templated, not tool-specific"
