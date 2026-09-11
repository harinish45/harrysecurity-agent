from nexus.advanced.asm_monitor import AttackSurfaceMonitor


class _StubExecutor:
    """Stands in for ToolExecutor: returns canned results per (tool, target) call,
    and each call pops the next scripted result so successive calls can differ
    (baseline run vs. later check_for_changes runs)."""

    def __init__(self, script):
        # script: dict[(tool_name, target)] -> list of result dicts, consumed in order
        self.script = {k: list(v) for k, v in script.items()}
        self.calls = []

    def run(self, tool_name, target, **kwargs):
        self.calls.append((tool_name, target))
        queue = self.script[(tool_name, target)]
        return queue.pop(0) if len(queue) > 1 else queue[0]


def _result(findings):
    return {"tool": "network.port_scan", "target": "host1", "status": "completed", "findings": findings, "summary": "", "error": "", "metadata": {}}


def test_run_baseline_stores_results_per_target_tool():
    baseline_findings = [{"affected_asset": "host1", "title": "Open port 22", "tool": "network.port_scan", "severity": "low"}]
    stub = _StubExecutor({("network.port_scan", "host1"): [_result(baseline_findings)]})
    mon = AttackSurfaceMonitor(["host1"], executor=stub)
    baseline = mon.run_baseline(["network.port_scan"])
    assert ("host1", "network.port_scan") in baseline
    assert baseline[("host1", "network.port_scan")]["findings"] == baseline_findings


def test_check_for_changes_detects_new_and_resolved_findings():
    old_finding = {"affected_asset": "host1", "title": "Open port 22", "tool": "network.port_scan", "severity": "low"}
    new_finding = {"affected_asset": "host1", "title": "Open port 8080", "tool": "network.port_scan", "severity": "medium"}

    stub = _StubExecutor({
        ("network.port_scan", "host1"): [
            _result([old_finding]),  # baseline run
            _result([new_finding]),  # check_for_changes run: old resolved, new appears
        ],
    })
    mon = AttackSurfaceMonitor(["host1"], executor=stub)
    mon.run_baseline(["network.port_scan"])
    changes = mon.check_for_changes(["network.port_scan"])

    types = {c["type"] for c in changes}
    assert types == {"new", "resolved"}
    new_change = next(c for c in changes if c["type"] == "new")
    resolved_change = next(c for c in changes if c["type"] == "resolved")
    assert new_change["finding"]["title"] == "Open port 8080"
    assert resolved_change["finding"]["title"] == "Open port 22"


def test_run_forever_invokes_callback_and_respects_max_iterations(monkeypatch):
    finding = {"affected_asset": "host1", "title": "Open port 22", "tool": "network.port_scan", "severity": "low"}
    stub = _StubExecutor({
        ("network.port_scan", "host1"): [_result([]), _result([finding])],
    })
    mon = AttackSurfaceMonitor(["host1"], executor=stub)
    mon.run_baseline(["network.port_scan"])

    seen = []
    monkeypatch.setattr("nexus.advanced.asm_monitor.time.sleep", lambda s: None)
    mon.run_forever(["network.port_scan"], interval_seconds=0, on_change=seen.append, max_iterations=2)

    assert len(seen) == 1  # only the iteration that found a new finding calls back
    assert seen[0][0]["type"] == "new"
