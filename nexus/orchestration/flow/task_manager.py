"""Turns a flat list of task/phase dicts into dependency-respecting,
priority-ordered execution batches — the shape task_planner_agent's output
already has (`id`, `depends_on`, `priority`) and that engine.py's mission
plan now carries too."""
from __future__ import annotations

from typing import Any

from nexus.orchestration.scheduler.dependency_graph import DependencyGraph
from nexus.orchestration.scheduler.priority_queue import PriorityQueue


class TaskManager:
    @staticmethod
    def plan(tasks: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        if not tasks:
            return []

        normalized = []
        for i, t in enumerate(tasks):
            t = dict(t)
            t.setdefault("id", f"T{i + 1}")
            normalized.append(t)
        by_id = {t["id"]: t for t in normalized}

        graph = DependencyGraph()
        for t in normalized:
            graph.add_task(t["id"], depends_on=t.get("depends_on") or [])

        batches: list[list[dict[str, Any]]] = []
        for batch_ids in graph.batches():
            pq = PriorityQueue()
            for tid in batch_ids:
                pq.push(by_id[tid], priority=by_id[tid].get("priority", "medium"))
            batches.append(pq.drain_sorted())
        return batches
