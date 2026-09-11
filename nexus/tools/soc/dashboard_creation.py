#!/usr/bin/env python3
"""
NEXUS-STRIKE — soc tool: Dashboard Creation
Domain: soc

Building a SOC dashboard means defining a data source/query against an
already-indexed data set — the SIEM index name, its field schema, and the
KPIs to visualize — and calling that SIEM's own dashboard API. This
previously did a DNS resolve on `target` and GET'd four hardcoded paths
(`/alerts`, `/logs`, `/api/v1/alerts`, `/siem`) against it, reporting
whatever HTTP status came back as "completed" — those paths have nothing
to do with building a dashboard — caught during this session's audit.
Dashboards are built against indexed data in a SIEM's own API/UI, not
derived from a target IP/domain. Now it honestly reports
STATUS_OUT_OF_SCOPE instead of fabricating a dashboard from an unrelated
HTTP probe.
"""
from nexus.foundation.schema import STATUS_OUT_OF_SCOPE, tool_result
from nexus.tools.registry import tool_registry


def run(target: str, **kwargs) -> dict:
    """soc tool: Dashboard Creation"""
    return tool_result(
        "soc.dashboard_creation", target,
        status=STATUS_OUT_OF_SCOPE,
        summary=f"Building a SOC dashboard referencing {target} requires a data-source/query "
                f"definition — the SIEM index name, field schema, and the KPIs to visualize — "
                f"dashboards are built against indexed data in a SIEM's own API/UI, not "
                f"derived from a target IP/domain",
        error="requires_case_data: no data-source/query definition supplied",
        metadata={
            "requires": [
                "SIEM index/data-source name and field schema",
                "KPI/metric definitions to visualize",
                "target SIEM platform (Splunk/Elastic/Sentinel/etc.) for its dashboard API",
            ],
        },
    )


# Register with tool registry
tool_registry.register("soc.dashboard_creation", run, metadata={
    "name": "soc.dashboard_creation",
    "domain": "soc",
    "status": "out_of_scope",
    "description": "soc tool: dashboard creation requires a SIEM data-source/query "
                    "definition and KPI spec — honestly reports STATUS_OUT_OF_SCOPE for a "
                    "bare network target instead of fabricating a dashboard",
    "parameters": {
        "target": "Target domain, IP, or URL (not used — this tool requires case data, see description)",
    },
})
