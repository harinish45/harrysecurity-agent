install:
	python -m pip install -e .

dev:
	python -m pip install -e ".[dev]"

run:
	nexus run --target 127.0.0.1

mcp:
	@echo "MCP server is not implemented yet; use the CLI command only when a future release enables it."


tools:
	nexus tools

agents:
	nexus agents

test:
	python -m pytest tests/ -v

lint:
	ruff check .

verify:
	python -m nexus verify

build:
	python -m build

check: lint verify test build
