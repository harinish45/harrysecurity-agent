# Contributing to NEXUS-STRIKE

Thank you for your interest in contributing to NEXUS-STRIKE! This document provides guidelines and instructions for adding new tools, modifying existing ones, and ensuring code quality.

## 🛠️ Adding a New Tool

1. **Location**: Place your new tool in the appropriate domain directory under `nexus/tools/<domain>/`.
2. **Naming Convention**: Use `snake_case` for file names (e.g., `sql_injection.py`).
3. **Signature**: Every tool must implement the following signature:
   ```python
   def run(target: str, **kwargs: Any) -> dict:
       ...
   ```
4. **Registration**: Always register your tool at the bottom of the file:
   ```python
   from nexus.tools.registry import tool_registry
   
   tool_registry.register("domain.tool_name", run, metadata={
       "name": "domain.tool_name",
       "domain": "domain",
       "status": "completed",
       "description": "Brief description of what the tool does",
       "parameters": {"target": "Target description"},
   })
   ```
5. **Return Contract**: The `run` function must return a dictionary compatible with `tool_result` containing:
   - `tool`: The tool name (e.g., `"domain.tool_name"`)
   - `domain`: The domain name
   - `target`: The target being scanned
   - `status`: One of `"completed"`, `"no_findings"`, `"failed"`, or `"unavailable"`
   - `findings`: A list of `Finding` objects from `nexus.foundation.schema`

## 🧪 Testing Requirements

- **Unit Tests**: Add a smoke test for your tool in `tests/unit/test_tools_smoke.py` if it requires special handling.
- **Integration Tests**: If your tool interacts with external systems, add mock-based integration tests in `tests/integration/`.
- **Verification**: Run `python -m nexus verify` to ensure your tool is importable and registered correctly.
- **Linting**: Ensure your code passes `ruff check` before submitting a PR.

## 📝 Code Style

- Use type hints for all function arguments and return values.
- Include comprehensive docstrings (Google style) for all public functions.
- Keep implementations read-only and proof-of-concept. **Never** include actual destructive exploitation code.
- Gracefully handle missing dependencies by returning `status: "unavailable"` with a helpful remediation message.

## 🚀 Pull Request Process

1. Create a feature branch: `git checkout -b feat/your-feature-name`
2. Make your changes and ensure all tests pass: `pytest tests/ -v`
3. Run verification: `python -m nexus verify`
4. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/).
5. Open a Pull Request against the `main` branch.

## 📜 Code of Conduct

By participating in this project, you agree to maintain a respectful and professional environment. Harassment, discrimination, or malicious contributions will not be tolerated.