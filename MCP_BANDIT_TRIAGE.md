# MCP Bandit triage

The MCP control plane is intentionally read-only and does not invoke subprocesses, shell commands, arbitrary URLs, credentials, or dynamic evaluation.

Security Hardening currently fails at the repository-wide Bandit stage while functional CI passes. The exact Bandit finding is not exposed by the Actions log endpoint, so the PR remains unmerged until the finding can be reproduced or identified by the next Actions run.

Triage rule: do not suppress Bandit findings without a concrete justification. Refactor the flagged code or dependency boundary instead.
