# NEXUS-STRIKE Self-Improving Architecture

## Objective

NEXUS-STRIKE should improve its reliability and efficiency from measured execution outcomes without silently changing authorization, target scope, legal constraints, or risk policy.

## Layered control loop

```text
Mission
  -> Policy / Scope
  -> Planner
  -> Capability Router
  -> Tool Profile
  -> Scheduler
  -> Worker / Adapter
  -> Telemetry
  -> Evidence
  -> Findings / Graph
  -> Outcome Evaluation
  -> Learning Record
  -> Bounded Recommendation
  -> Human / Policy Approval
  -> Versioned Profile Update
```

## Improvement layers

1. **Contract assurance** — every registered tool must be callable and have a serializable execution profile.
2. **Adapter conformance** — tool adapters normalize success, failure, timeout and evidence outcomes.
3. **Runtime telemetry** — capture latency, timeout rate, failure class and evidence/finding yield without secrets.
4. **Baseline analytics** — maintain rolling performance baselines by tool, capability and environment class.
5. **Anomaly detection** — flag unusual latency, failure or evidence-yield changes for review.
6. **Recommendation engine** — propose profile or workflow improvements from sufficient observations.
7. **Approval gate** — recommendations cannot modify protected policy fields automatically.
8. **Versioned rollout** — approved changes are versioned and can be rolled back.
9. **Canary evaluation** — new profiles can be evaluated against a bounded validation corpus before wider use.
10. **Regression gate** — a degraded success/evidence rate blocks promotion.

## Protected invariants

The learning loop must never autonomously modify:

- authorization requirements
- legal/scope constraints
- allowed targets
- credential policy
- risk ceilings
- destructive-operation policy
- human approval requirements

These remain explicit control-plane decisions.

## Tool capability assurance

The registry exposes `assurance_report()` so the platform can measure contract health for the complete registered tool catalog. A tool is not considered healthy merely because it is present in the registry.

Health requires:

- callable implementation
- execution profile
- valid profile serialization
- deterministic metadata

## Real-result validation

A future conformance harness should classify tools into:

- `static`: pure parser/transformer; deterministic fixture tests
- `sandbox`: safe execution against controlled fixtures
- `integration`: dependency-backed test environment
- `external`: requires an explicitly authorized target and is never executed by CI

CI validates the first three classes. External tools must expose capability metadata and an operator-controlled validation workflow; CI must never probe arbitrary external targets.

## Performance model

Maintain measurements for:

- queue wait
- execution duration (median/p95)
- timeout rate
- non-zero failure rate
- retry rate
- evidence yield
- finding yield
- resource class

The planner can use these observations to choose among eligible tools, but only after authorization and scope filtering.

## Promotion rule

A learned recommendation is eligible for promotion only when:

- enough observations exist
- the recommendation does not touch protected policy
- the baseline comparison is statistically meaningful for the available sample
- regression tests pass
- the change is explicitly approved

This creates self-improvement without creating an uncontrolled autonomous policy engine.
