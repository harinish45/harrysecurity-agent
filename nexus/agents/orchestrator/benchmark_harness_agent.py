"""BaseAgent wrapper around ``nexus.benchmarks`` so the standard suites can
be invoked like any other agent (`nexus agent run benchmark_harness_agent`)
in addition to the dedicated `nexus benchmark` CLI command.
"""
from __future__ import annotations

from nexus.agents.base_agent import BaseAgent
from nexus.benchmarks.runner import BenchmarkRunner
from nexus.benchmarks.suites import SUITES
from nexus.foundation.schema import STATUS_COMPLETED, STATUS_FAILED, tool_result


class BenchmarkHarnessAgent(BaseAgent):
    name = "benchmark_harness_agent"
    description = "orchestrator agent that scores the agent stack against Cybench/NYU-CTF/InterCode-CTF-style suites"

    async def run(self, task: str, target: str = "", **kwargs) -> dict:
        suite_key = kwargs.get("suite", "intercode_ctf")
        suite_cls = SUITES.get(suite_key)
        if not suite_cls:
            return tool_result(
                self.name, target or "unknown", status=STATUS_FAILED,
                error=f"Unknown suite '{suite_key}'. Available: {', '.join(sorted(SUITES))}",
            )

        mission_id = kwargs.get("mission_id", "benchmark")
        runner = BenchmarkRunner()
        summary = runner.run(suite_cls(), mission_id=mission_id)

        return tool_result(
            self.name, target or suite_key,
            status=STATUS_COMPLETED,
            findings=[],
            summary=f"{summary['name']}: {summary['correct']}/{summary['total']} "
                    f"({summary['score'] * 100:.1f}%){' — ' + summary['note'] if summary.get('note') else ''}",
            metadata=summary,
        )
