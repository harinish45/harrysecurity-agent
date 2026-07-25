"""Offline checks that prevent false 'all tools work' claims.

These tests intentionally import every bundled tool but never call a tool
against a network target. Real assessments belong in separately authorised
engagement tests.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import socket
import threading

import nexus.tools as tools_package
from nexus.tools.registry import tool_registry


def test_every_tool_module_imports_and_has_a_compatible_entrypoint():
    failures = []
    modules = [
        item.name
        for item in pkgutil.walk_packages(tools_package.__path__, "nexus.tools.")
        if not item.ispkg
    ]
    for name in modules:
        module = importlib.import_module(name)
        run = getattr(module, "run", None)
        if run is None:
            continue
        if not callable(run):
            failures.append(f"{name}: run is not callable")
            continue
        signature = inspect.signature(run)
        if "target" not in signature.parameters and not any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            failures.append(f"{name}: run cannot accept a target")
    assert not failures, "\n".join(failures)


def test_registry_contains_executable_tools():
    assert tool_registry.count >= 200
    for name, metadata in tool_registry.list_tools().items():
        assert callable(tool_registry.get(name))
        assert metadata.get("domain") == name.split(".", 1)[0]


def test_port_scanner_detects_a_real_local_listener():
    """Exercise socket probing without touching an external target."""
    from nexus.tools.network.port_scan import run

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    ready = threading.Event()

    def accept_once():
        ready.set()
        connection, _ = listener.accept()
        connection.close()

    worker = threading.Thread(target=accept_once, daemon=True)
    worker.start()
    ready.wait(timeout=1)
    try:
        result = run("127.0.0.1", ports=[port])
    finally:
        listener.close()
    assert result["status"] == "completed"
    assert any(f"{port}" in str(finding) for finding in result["findings"])
