"""NEXUS-STRIKE — advanced/experimental capability modules.

Each module here is self-contained and documents, in its own docstring,
exactly what it does and does not do. Most are real, working
implementations honestly scoped to what's actually buildable without
training data, funded infrastructure, or a multi-tenant deployment this
project doesn't have (see the docstrings of adversarial_ml, rl_simulation,
federated_learning, and deepfake_detection specifically — those four raise
NotImplementedError with a stated reason rather than faking a capability).

Import submodules directly, e.g.:

    from nexus.advanced.threat_modeling import ThreatModeler
    from nexus.advanced.triage import Triage
    from nexus.advanced.asm_monitor import AttackSurfaceMonitor
    from nexus.advanced.supply_chain import SupplyChainScanner
    from nexus.advanced.patch_validation import PatchValidator
    from nexus.advanced.notarization import EvidenceNotary
    from nexus.advanced.pq_signing import PQSigner
    from nexus.advanced.honeypot import CanaryListener
    from nexus.advanced.ga_fuzzer import GeneticFuzzer
    from nexus.advanced.neurosymbolic import NeuroSymbolicExplainer
    from nexus.advanced.threat_radar import ThreatRadar
    from nexus.advanced.adversarial_ml import AdversarialMLDefense
    from nexus.advanced.rl_simulation import AdversarialSimulation
    from nexus.advanced.federated_learning import FederatedThreatLearning
    from nexus.advanced.deepfake_detection import DeepfakeDetector
"""
from __future__ import annotations

from . import threat_modeling
from . import triage
from . import asm_monitor
from . import supply_chain
from . import patch_validation
from . import notarization
from . import pq_signing
from . import honeypot
from . import ga_fuzzer
from . import neurosymbolic
from . import threat_radar
from . import adversarial_ml
from . import rl_simulation
from . import federated_learning
from . import deepfake_detection

__all__ = [
    "threat_modeling", "triage", "asm_monitor", "supply_chain", "patch_validation",
    "notarization", "pq_signing", "honeypot", "ga_fuzzer",
    "neurosymbolic", "threat_radar",
    "adversarial_ml", "rl_simulation", "federated_learning", "deepfake_detection",
]
