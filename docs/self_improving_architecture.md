# NEXUS-STRIKE Self-Improving Architecture

NEXUS-STRIKE improves reliability and efficiency from measured outcomes without silently changing authorization, scope, legal constraints, or risk policy.

## Layered control loop

```text
Mission -> Policy/Scope -> Planner -> Capability Router -> Tool Profile
       -> Scheduler -> Worker/Adapter -> Telemetry -> Evidence
       -> Findings/Graph -> Outcome Evaluation -> Learning Record
       -> Bounded Recommendation -> Explicit Approval -> Versioned Update
```

## Improvement layers

1. Contract assurance: callable implementation, profile and serialization health.
2. Adapter conformance: normalized success, failure, timeout and evidence outcomes.
3. Runtime telemetry: latency, failure class, timeout and evidence/finding yield without secrets.
4. Baseline analytics: rolling measurements by tool, capability and environment class.
5. Anomaly detection: unusual latency, failures or evidence yield are surfaced for review.
6. Recommendation engine: proposes measurable workflow/profile improvements.
7. Approval gate: learned recommendations never bypass policy controls.
8. Versioned rollout: approved changes can be compared and rolled back.
9. Canary evaluation: changes can be tested against bounded validation fixtures.
10. Regression gate: degraded reliability/evidence yield blocks promotion.

## Protected invariants

The learning loop cannot autonomously modify authorization, legal/scope constraints, allowed targets, credential policy, risk ceilings, destructive-operation policy, or human-approval requirements.

## Real-result validation

Tools are classified as `static`, `sandbox`, `integration`, or `external`. CI validates static/sandbox/integration classes using deterministic fixtures and controlled environments. External validation requires an explicitly authorized target and is never performed against arbitrary targets by CI.

## Performance model

Track queue wait, execution duration (median/p95), timeout rate, non-zero failures, retry rate, evidence yield, finding yield and resource class. Tool selection uses these observations only after authorization and scope filtering.

## Promotion rule

A recommendation requires sufficient observations, must not touch protected policy, must pass regression validation, and requires explicit approval before a versioned profile/workflow change is applied.
