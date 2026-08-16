from nexus.analysis import Evidence, correlate


def test_correlate_merges_equivalent_observations_and_keeps_provenance():
    findings = correlate(
        [
            Evidence("nmap-1", "nmap", "web01", "Open SSH service", severity="medium", fingerprint="ssh:22", description="22/tcp is reachable"),
            Evidence("scanner-7", "scanner", " web01 ", "open   ssh service", severity="high", fingerprint="SSH:22", description="SSH service detected"),
        ]
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.evidence_ids == ("nmap-1", "scanner-7")
    assert finding.sources == ("nmap", "scanner")
    assert len(finding.descriptions) == 2


def test_correlate_separates_different_ports():
    evidence = [
        Evidence("a", "scanner", "host", "Open SSH", fingerprint="ssh:22"),
        Evidence("b", "scanner", "host", "Open SSH", fingerprint="ssh:2222"),
    ]
    assert len(correlate(evidence)) == 2
