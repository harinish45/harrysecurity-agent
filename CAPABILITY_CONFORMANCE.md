# Capability Conformance Contract

A capability is not considered production-ready because it is listed in the feature matrix.

Promotion is evidence-based:

`REGISTERED -> CALLABLE -> CONTRACT_VALID -> EXECUTABLE -> EVIDENCE_VALID -> RESULT_VALID -> RELIABLE -> PRODUCTION_READY`

Validation layers:

1. Importability / registry presence
2. Typed execution contract
3. Policy and scope eligibility
4. Controlled fixture/sandbox execution
5. Output normalization
6. Evidence provenance and integrity
7. Independent result validation
8. Reliability/performance observation
9. Regression and canary evaluation
10. Explicit production promotion

A capability may be advertised in planning views while remaining non-executable or non-production-ready. The UI and reports must preserve this distinction.