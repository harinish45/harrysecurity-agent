from nexus.runtime.tool_metrics import ToolExecutionMetric, ToolMetricsStore


def metric(metric_id="m1", tool="network.port_scan", status="completed"):
    return ToolExecutionMetric(
        metric_id=metric_id,
        mission_id="mission-1",
        job_id="job-1",
        tool_name=tool,
        status=status,
        started_at="2026-08-16T18:00:00Z",
        finished_at="2026-08-16T18:00:01Z",
        queue_wait_ms=10,
        execution_ms=1000,
        stdout_bytes=100,
        stderr_bytes=10,
        evidence_count=2,
        finding_count=1,
        resource_class="network",
    )


def test_metric_validates_and_serializes():
    payload = metric().to_dict()
    assert payload["execution_ms"] == 1000
    assert payload["evidence_count"] == 2


def test_metrics_store_is_bounded_and_filterable():
    store = ToolMetricsStore(max_records=2)
    store.add(metric("m1"))
    store.add(metric("m2", tool="webapp.crawler"))
    store.add(metric("m3", status="failed"))

    assert [item.metric_id for item in store.list()] == ["m2", "m3"]
    assert len(store.list(tool_name="webapp.crawler")) == 1
    assert store.summary()["records"] == 2
    assert store.summary()["failed"] == 1


def test_negative_metrics_are_rejected():
    bad = metric()
    bad = ToolExecutionMetric(**{**bad.to_dict(), "execution_ms": -1})
    try:
        bad.validate()
    except ValueError as exc:
        assert "execution_ms" in str(exc)
    else:
        raise AssertionError("negative execution metrics must fail validation")
