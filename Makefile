install:
	pip install -e .
run:
	nexus run --target example.com
mcp:
	nexus mcp --port 8888
tools:
	nexus tools
agents:
	nexus agents
test:
	pytest tests/unit -v
