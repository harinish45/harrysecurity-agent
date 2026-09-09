## What changed

<!-- Summary of the change and why. Link any related issue. -->

## Type of change

- [ ] New tool (`nexus/tools/<domain>/<name>.py`)
- [ ] New/changed agent
- [ ] Bug fix
- [ ] Guardrail / security change
- [ ] Reporting / dashboard change
- [ ] Docs only
- [ ] Other

## Checklist

- [ ] `python -m nexus verify` passes (confirms every tool module imports and registers cleanly)
- [ ] `pytest tests -q -k "not slow" --ignore=tests/unit/test_automotive_tools.py` passes locally
- [ ] `ruff check <files you touched>` is clean
- [ ] New/changed tools return the standard `tool_result(...)` contract (`tool`, `domain`, `target`, `status`, `findings`) — see CONTRIBUTING.md
- [ ] All outbound HTTP goes through `nexus.foundation.net.safe_urlopen()`, not raw `urllib`/`requests`
- [ ] A tool that can't do real work without something unavailable (hardware, a paid API key, a licensed dataset) returns an honest `STATUS_REQUIRES_*`/`STATUS_UNAVAILABLE` result instead of a fabricated finding
- [ ] No secrets, API keys, or `.env` contents included in this PR or its test fixtures
- [ ] Added/updated tests for the behavior this PR changes (not just an import/smoke check — see `tests/unit/test_tools_smoke.py`'s docstring for why smoke-only isn't sufficient on its own)

## How was this tested?

<!--
Real output beats a description — paste the actual command + result. If you
tested live against a real target, say which one (only ever a target you're
authorized to test, matching NEXUS_ALLOWED_TARGETS / this project's legal
requirements — see SECURITY.md's Safe Harbor section).
-->

## Anything reviewers should look at closely?

<!-- Optional — e.g. "not sure this is the right severity default" -->
