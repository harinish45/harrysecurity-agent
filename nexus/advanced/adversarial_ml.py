"""Adversarial ML defense -- honest stub, not a working feature.

**What this would be:** a detector that identifies attacker-crafted inputs
designed to fool a first-party machine-learning classifier -- e.g. an
adversarial perturbation on an image, a crafted feature vector meant to
flip a malware-detection model's verdict, or a prompt-injection payload
targeting an in-house triage model. This is a well-studied subfield
(evasion attacks, adversarial examples, robustness testing) with real
techniques (adversarial training, input sanitization, ensemble
disagreement detection, certified robustness bounds).

**Why a genuine working version isn't buildable in this engineering pass:**
NEXUS does not currently run any first-party ML classifier over
attacker-controlled input anywhere in this codebase. Its "AI" surface is
entirely third-party LLM orchestration (OpenAI/Anthropic/Ollama/etc, see
``nexus.intelligence.llm.router.LLMRouter``) used for report generation,
explanation, and chat -- NEXUS does not own, train, or control the weights
of those models, so there is no first-party model here to defend against
adversarial evasion. Building an "adversarial ML defense" against a model
NEXUS doesn't run would be pure theater: there would be nothing real to
evaluate it against, and no way to demonstrate it actually detects
anything.

**What would need to exist first:** a first-party classifier trained and
operated by NEXUS itself -- for example a local finding-triage model, an
anomaly-detection model over scan telemetry, or a malware/traffic
classifier -- with real training data, a real threat model for what an
adversary controls, and a real evaluation harness. Only once such a model
exists does "defend it against adversarial evasion" become a buildable,
testable feature rather than a description of someone else's model.
"""
from __future__ import annotations

from typing import Any


class AdversarialMLDefense:
    """Placeholder for a future adversarial-ML-evasion detector. See module
    docstring for why this raises rather than pretending to work."""

    def detect_evasion(self, input_data: Any) -> dict[str, Any]:
        raise NotImplementedError(
            "NEXUS does not run a first-party ML classifier on "
            "attacker-controlled input -- it calls out to third-party LLM "
            "APIs (OpenAI/Anthropic/Ollama) for orchestration, which are "
            "not NEXUS's own model to defend against adversarial evasion. "
            "A genuine adversarial-ML-defense feature requires a "
            "first-party classifier to exist first (e.g. a local "
            "finding-triage or anomaly-detection model) -- this module is "
            "a placeholder for that future state, not a working defense "
            "today."
        )
