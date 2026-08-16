"""Evidence correlation and attack-path analysis primitives."""

from .attack_surface import Asset, AttackSurface, Service
from .evidence import CorrelatedFinding, Evidence, correlate
from .graph import AttackGraph, GraphEdge, GraphNode, PathResult

__all__ = [
    "Asset",
    "AttackGraph",
    "AttackSurface",
    "CorrelatedFinding",
    "Evidence",
    "GraphEdge",
    "GraphNode",
    "PathResult",
    "Service",
    "correlate",
]
