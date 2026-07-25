#!/usr/bin/env python3
"""
NEXUS-STRIKE Command Line Interface
Rich CLI with commands for running missions, managing tools/agents, and configuring providers.
"""
import asyncio
import importlib
import inspect
import json
import pkgutil
import sys
import typer
from pathlib import Path

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from nexus.foundation.config import config
from nexus.foundation.logging import logger
from nexus.tools.registry import tool_registry
from nexus.agents.agent_registry import list_agents, get_agent_count
from nexus.intelligence.llm.router import LLMRouter

app = typer.Typer(
    name="nexus",
    help="NEXUS-STRIKE: The Ultimate AI-Powered Cybersecurity Platform",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console(
    legacy_windows=False,
    emoji=sys.platform != "win32",
    force_terminal=True,
)

@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Target domain, IP, or URL"),
    engagement: Path = typer.Option(None, "--engagement", "-e", exists=True, readable=True, help="Engagement JSON created by `nexus engage`"),
    mode: str = typer.Option("guided", "--mode", "-m",
                             help="Execution mode: [bold]autonomous[/], [bold]guided[/], [bold]tool[/], [bold]interactive[/]"),
    mission: str = typer.Option("mission-001", "--mission", "--id", help="Mission identifier"),
    objective: str = typer.Option("full_assessment", "--objective", "-o",
                                  help="Mission objective: full_assessment, quick_scan, vuln_scan, osint"),
    provider: str = typer.Option(None, "--provider", "-p",
                                 help="LLM provider: openai, anthropic, openrouter, ollama, groq, deepseek, omniroute, custom"),
):
    """🚀 Launch a security assessment mission."""
    engagement_record = None
    if engagement is not None:
        try:
            engagement_record = json.loads(engagement.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"Invalid engagement JSON: {exc}") from exc
        scope = engagement_record.get("scope")
        authorization = engagement_record.get("authorization_reference")
        if not isinstance(scope, list) or not all(isinstance(item, str) and item.strip() for item in scope):
            raise typer.BadParameter("Engagement record requires a non-empty string scope list")
        if not isinstance(authorization, str) or not authorization.strip():
            raise typer.BadParameter("Engagement record requires an authorization reference")
        config.nexus_allowed_targets = ",".join(scope)
        from nexus.foundation.guardrails.scope_guard import ScopeGuard
        ScopeGuard.validate(target)

    console.print(Panel.fit(
        "🏴‍☠️ [bold green]NEXUS-STRIKE[/] v0.1.0 — Ultimate AI-Powered Cybersecurity Platform",
        style="bold green",
    ))

    # Show provider info
    router = LLMRouter(provider=provider)
    provider_info = router.get_provider_info()
    console.print(f"[dim]LLM Provider: [cyan]{provider_info['active_provider']}[/] | "
                  f"Model: [cyan]{provider_info['model']}[/] | "
                  f"Available: [cyan]{', '.join(provider_info['available_providers'])}[/][/]")

    # Run the orchestration engine
    from nexus.orchestration.engine import OrchestrationEngine
    engine = OrchestrationEngine(llm_provider=provider)

    async def _run():
        result = await engine.run_mission(
            target=target,
            mission_id=mission,
            mode=mode,
            objective=objective,
            engagement=engagement_record,
        )
        return result

    result = asyncio.run(_run())

    # Display results
    if result.get("status") == "blocked":
        console.print(f"[red]❌ Mission blocked: {result.get('error', 'Unknown error')}[/]")
        raise typer.Exit(1)

    console.print(f"\n[bold green]✅ Mission {mission} completed[/]")
    console.print(f"[bold]Target:[/] {target}")
    console.print(f"[bold]Mode:[/] {mode}")
    console.print(f"[bold]Objective:[/] {objective}")
    console.print(f"[bold]Phases planned:[/] {len(result.get('plan', []))}")
    console.print(f"[bold]Findings:[/] {len(result.get('findings', []))}")
    console.print(f"[bold]LLM Provider:[/] {result.get('llm_provider', {}).get('active_provider', 'unknown')}")
    if result.get("report_path"):
        console.print(f"[bold]Report:[/] {result['report_path']}")

    # Show plan
    if result.get("plan"):
        plan_table = Table(title="Mission Plan", box=box.ROUNDED)
        plan_table.add_column("Phase", style="cyan")
        plan_table.add_column("Agent", style="green")
        plan_table.add_column("Task", style="white")
        for i, phase in enumerate(result["plan"], 1):
            plan_table.add_row(str(i), phase.get("agent", "?"), phase.get("task", "?")[:60])
        console.print(plan_table)

    console.print("[yellow]💡 Full agent execution with real tools coming in Phase 2+[/]")
    console.print("[dim]Run [bold]nexus tools[/] to see all registered tools[/]")
    console.print("[dim]Run [bold]nexus agents[/] to see all registered agents[/]")
    console.print("[dim]Run [bold]nexus providers[/] to see LLM provider status[/]")


@app.command()
def mcp(
    port: int = typer.Option(8888, "--port", "-p", help="MCP server port"),
):
    """🔌 Start the Model Context Protocol (MCP) server for IDE integration."""
    console.print(f"[cyan]Starting NEXUS-STRIKE MCP Server on port {port}...[/]")
    console.print("[dim]Connect your MCP client (Claude Desktop, Cursor, etc.) to this port.[/]")
    console.print("[yellow]MCP Server implementation coming in Phase 2.[/]")


@app.command("engage")
def engage(
    client: str = typer.Option(None, "--client", prompt="Client or asset owner"),
    scope: str = typer.Option(None, "--scope", prompt="Approved targets (comma-separated)"),
    authorization_reference: str = typer.Option(
        None, "--authorization-reference", prompt="Written authorization / ticket reference"
    ),
    rules_of_engagement: str = typer.Option(
        "Non-destructive validation only; no disruption, credential access, phishing, or data exfiltration.",
        "--rules-of-engagement",
        prompt="Rules of engagement",
    ),
    engagement_id: str = typer.Option("", "--id", help="Optional engagement identifier"),
    asset_owner: str = typer.Option("", "--asset-owner", help="Asset owner name/team"),
    asset_owner_contact: str = typer.Option("", "--asset-owner-contact", help="Asset owner contact email/phone"),
    approved_test_types: str = typer.Option(
        "network,webapp,reconnaissance",
        "--approved-test-types",
        help="Comma-separated approved test types",
    ),
    exclusions: str = typer.Option("", "--exclusions", help="Out-of-scope targets or test types"),
    emergency_stop_contact: str = typer.Option("", "--emergency-stop", help="Emergency stop contact"),
    authorization_expiry: str = typer.Option("", "--auth-expiry", help="Authorization expiry date (YYYY-MM-DD)"),
    start_window: str = typer.Option("", "--start-window", help="Test window start (YYYY-MM-DD HH:MM)"),
    end_window: str = typer.Option("", "--end-window", help="Test window end (YYYY-MM-DD HH:MM)"),
):
    """Interactively create an evidence record before an authorised assessment."""
    from datetime import datetime, timezone
    import hashlib

    cleaned_scope = [item.strip() for item in scope.split(",") if item.strip()]
    if not client.strip() or not cleaned_scope or not authorization_reference.strip():
        raise typer.BadParameter("client, scope, and authorization reference are required")
    safe_id = "".join(char if char.isalnum() or char in "-_" else "-" for char in engagement_id.strip())
    if not safe_id:
        safe_id = f"engagement-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"

    record = {
        "id": safe_id,
        "client": client.strip(),
        "asset_owner": asset_owner.strip() or "Not specified",
        "asset_owner_contact": asset_owner_contact.strip() or "Not specified",
        "scope": cleaned_scope,
        "authorization_reference": authorization_reference.strip(),
        "rules_of_engagement": rules_of_engagement.strip(),
        "approved_test_types": [t.strip() for t in approved_test_types.split(",") if t.strip()],
        "exclusions": exclusions.strip() or "None specified",
        "emergency_stop_contact": emergency_stop_contact.strip() or "Not specified",
        "authorization_expiry": authorization_expiry.strip() or "Not specified",
        "test_window_start": start_window.strip() or "Not specified",
        "test_window_end": end_window.strip() or "Not specified",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "created_by": "NEXUS-STRIKE CLI",
    }

    # Create a signed hash of the record for immutability
    record_str = json.dumps(record, sort_keys=True, default=str)
    record["record_hash"] = hashlib.sha256(record_str.encode()).hexdigest()

    path = Path("engagements") / f"{safe_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    console.print(f"[green]Engagement record saved: {path}[/]")
    console.print(f"[green]Record hash (SHA-256): {record['record_hash']}[/]")
    console.print("[yellow]Before running tools, set NEXUS_ALLOWED_TARGETS to this approved scope in .env.[/]")
    console.print("[yellow]Use --engagement <path> with `nexus run` to enforce engagement for non-local targets.[/]")


@app.command("preflight")
def preflight(
    strict: bool = typer.Option(False, "--strict", help="Exit non-zero when a recommended check is not ready"),
):
    """Check whether this host is ready for an authorised assessment."""
    import importlib.util
    from urllib.parse import urlparse
    import urllib.request

    checks = []
    for dependency in ("httpx", "fastapi", "pydantic", "yaml"):
        checks.append((f"Python dependency: {dependency}", importlib.util.find_spec(dependency) is not None, "Install project dependencies."))
    checks.append((
        "Written authorization acknowledgement",
        config.nexus_legal_ack == "I_HAVE_WRITTEN_AUTHORIZATION",
        "Set NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION after obtaining written approval.",
    ))
    checks.append((
        "Target allow-list",
        bool(str(config.nexus_allowed_targets).strip()),
        "Set NEXUS_ALLOWED_TARGETS to the approved hosts, wildcards, IPs, or CIDRs.",
    ))
    provider = LLMRouter()
    configured = provider.provider != "mock"
    checks.append(("LLM provider configured", configured, "Configure a supported cloud provider or local Ollama."))
    if provider.provider == "ollama":
        parsed = urlparse(config.ollama_base_url)
        if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
            try:
                with urllib.request.urlopen(f"{config.ollama_base_url.rstrip('/')}/models", timeout=2):
                    reachable = True
            except OSError:
                reachable = False
            checks.append(("Local Ollama endpoint reachable", reachable, "Start Ollama and pull the configured model."))

    table = Table(title="Assessment Preflight", box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Action", style="dim")
    failures = 0
    for label, ready, action in checks:
        table.add_row(label, "[green]READY[/]" if ready else "[yellow]NEEDS ATTENTION[/]", "" if ready else action)
        failures += not ready
    console.print(table)
    if strict and failures:
        raise typer.Exit(1)


@app.command("export-report")
def export_report(
    source: Path = typer.Argument(..., exists=True, readable=True, help="JSON file containing a findings array"),
    format: str = typer.Option(..., "--format", "-f", help="json, csv, html, or sarif"),
    output: Path = typer.Option(..., "--output", "-o", help="Output artifact path"),
):
    """Export normalized findings to a portable report artifact."""
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON input: {exc}") from exc
    findings = payload.get("findings", payload) if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        raise typer.BadParameter("Input must be a JSON findings array or an object with a findings array")
    from nexus.reporting.exporters.csv_export import CsvExport
    from nexus.reporting.exporters.html_export import HtmlExport
    from nexus.reporting.exporters.json_export import JsonExport
    from nexus.reporting.exporters.sarif_export import SarifExport

    exporters = {"json": JsonExport(), "csv": CsvExport(), "html": HtmlExport(), "sarif": SarifExport()}
    selected = exporters.get(format.lower())
    if selected is None:
        raise typer.BadParameter("format must be one of: json, csv, html, sarif")
    path = selected.export(findings, output)
    console.print(f"[green]Export written: {path}[/]")


@app.command()
def tools(
    domain: str = typer.Option(None, "--domain", "-d", help="Filter by domain (e.g., reconnaissance, webapp)"),
):
    """🔧 List all registered tools in the Tool Fabric."""
    all_tools = tool_registry.list_tools()

    if domain:
        domain_tools = {k: v for k, v in all_tools.items() if k.startswith(domain)}
        table = Table(title=f"Tool Fabric — {domain} ({len(domain_tools)} tools)", box=box.ROUNDED)
    else:
        table = Table(title=f"Tool Fabric ({tool_registry.count} tools across 29 domains)", box=box.ROUNDED)

    table.add_column("Tool Name", style="cyan")
    table.add_column("Domain", style="green")
    table.add_column("Status", style="green")

    tools_to_show = domain_tools if domain else all_tools
    for name in tools_to_show:
        domain_name = name.split(".")[0] if "." in name else "unknown"
        table.add_row(name, domain_name, "✅ Registered")

    console.print(table)
    console.print(f"\n[dim]Total: {len(tools_to_show)} tools | "
                  f"Run [bold]nexus tools --domain <name>[/] to filter[/]")


@app.command()
def agents(
    tier: str = typer.Option(None, "--tier", "-t", help="Filter by tier (orchestrator, offensive, defensive, etc.)"),
):
    """🤖 List all registered agents in the Agent Mesh."""
    all_agents = list_agents()

    if tier:
        filtered = [a for a in all_agents if a.endswith(f"_{tier}") or a.startswith(tier)]
        table = Table(title=f"Agent Mesh — {tier} ({len(filtered)} agents)", box=box.ROUNDED)
    else:
        table = Table(title=f"Agent Mesh ({get_agent_count()} agents across 6 tiers)", box=box.ROUNDED)

    table.add_column("Agent Name", style="cyan")
    table.add_column("Status", style="green")

    agents_to_show = filtered if tier else all_agents
    for name in agents_to_show:
        table.add_row(name, "✅ Registered")

    console.print(table)
    console.print(f"\n[dim]Total: {len(agents_to_show)} agents | "
                  f"Run [bold]nexus agents --tier <name>[/] to filter[/]")


@app.command()
def providers():
    """🌐 Show LLM provider configuration status."""
    router = LLMRouter()
    info = router.get_provider_info()

    table = Table(title="LLM Provider Status", box=box.ROUNDED)
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Model", style="yellow")
    table.add_column("Configured", style="white")

    all_providers = [
        ("openai", "OpenAI", config.openai_api_key is not None),
        ("anthropic", "Anthropic Claude", config.anthropic_api_key is not None),
        ("openrouter", "OpenRouter", config.openrouter_api_key is not None),
        ("ollama", "Ollama (Local)", True),  # Always available
        ("nvidia", "NVIDIA NIM", config.nvidia_api_key is not None),
        ("azure", "Azure OpenAI", config.azure_openai_api_key is not None),
        ("groq", "Groq", config.groq_api_key is not None),
        ("deepseek", "DeepSeek", config.deepseek_api_key is not None),
        ("omniroute", "Omniroute", config.omniroute_api_key is not None),
        ("custom", "Custom", config.custom_api_key is not None),
    ]

    for key, name, configured in all_providers:
        status = "🟢 Active" if key == info["active_provider"] else ("🔵 Available" if configured else "⚪ Not configured")
        model = getattr(config, f"{key}_model", "N/A")
        table.add_row(name, status, model, "✅" if configured else "❌")

    console.print(table)
    console.print(f"\n[bold]Active Provider:[/] [cyan]{info['active_provider']}[/]")
    console.print(f"[bold]Active Model:[/] [cyan]{info['model']}[/]")
    console.print(f"\n[dim]Set [bold]LLM_PROVIDER=<name>[/] in .env to change the active provider[/]")


@app.command()
def config_show():
    """⚙️ Show current NEXUS-STRIKE configuration."""
    table = Table(title="NEXUS-STRIKE Configuration", box=box.ROUNDED)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    settings = [
        ("Mode", config.nexus_mode),
        ("Log Level", config.nexus_log_level),
        ("LLM Provider", config.llm_provider),
        ("Temperature", str(config.llm_temperature)),
        ("Max Tokens", str(config.llm_max_tokens)),
        ("Sandbox Enabled", str(config.nexus_sandbox_enabled)),
        ("Auto Approve", str(config.nexus_auto_approve)),
        ("Max Concurrent Tools", str(config.nexus_max_concurrent_tools)),
        ("Tool Timeout (s)", str(config.nexus_tool_timeout)),
        ("Allowed Targets", config.nexus_allowed_targets),
        ("Legal Ack", "✅ Set" if config.nexus_legal_ack else "❌ Not set"),
        ("Rate Limit (calls/window)", f"{config.nexus_rate_limit_calls}/{config.nexus_rate_limit_window}s"),
        ("MCP Port", str(config.nexus_mcp_port)),
    ]

    for setting, value in settings:
        table.add_row(setting, value)

    console.print(table)


@app.command("verify")
def verify():
    """Run an offline integrity check for every bundled security tool."""
    import nexus.tools as tools_package

    module_names = [
        item.name
        for item in pkgutil.walk_packages(tools_package.__path__, "nexus.tools.")
        if not item.ispkg
    ]
    failures = []
    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
            run = getattr(module, "run", None)
            if run is not None and not callable(run):
                failures.append(f"{module_name}: run is not callable")
            elif callable(run):
                signature = inspect.signature(run)
                accepts_target = "target" in signature.parameters or any(
                    parameter.kind is inspect.Parameter.VAR_KEYWORD
                    for parameter in signature.parameters.values()
                )
                if not accepts_target:
                    failures.append(f"{module_name}: run does not accept target")
        except Exception as exc:
            failures.append(f"{module_name}: {type(exc).__name__}: {exc}")

    table = Table(title="Offline Tool Verification", box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")
    table.add_row("Importable tool modules", f"{len(module_names) - len(failures)}/{len(module_names)}")
    table.add_row("Registered tools", str(tool_registry.count))
    table.add_row("Failures", str(len(failures)))
    console.print(table)
    if failures:
        for failure in failures:
            console.print(f"[red]FAIL[/] {failure}")
        raise typer.Exit(1)
    console.print("[green]All bundled tool modules imported and expose a compatible callable interface.[/]")


@app.command()
def version():
    """📦 Show version information."""
    console.print(Panel.fit(
        "[bold green]NEXUS-STRIKE[/] v0.2.0\n"
        "[dim]The Ultimate AI-Powered Cybersecurity Platform[/]\n\n"
        "29 security domains | 263 tools | 50 agents | 6 patterns | 10 LLM providers",
        style="bold",
    ))


@app.command("live")
def live(
    target: str = typer.Option("127.0.0.1", "--target", "-t", help="Target IP or hostname to scan"),
    host: str = typer.Option("localhost", "--host", "-H", help="Target hostname for DNS resolution"),
    ports: str = typer.Option(None, "--ports", "-p", help="Comma-separated port list (default: top ports)"),
    llm_url: str = typer.Option(None, "--llm-url", help="LLM gateway URL (default: from env or Ollama)"),
    llm_model: str = typer.Option(None, "--llm-model", help="LLM model name"),
):
    """🚀 Run the live AI cybersecurity agent against a target."""
    import sys
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    scripts_dir = os.path.join(os.path.dirname(_project_root), "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)

    if ports:
        try:
            custom_ports = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            console.print("[red]Invalid port list. Use comma-separated numbers.[/]")
            raise typer.Exit(1)
    else:
        custom_ports = None

    from scripts.live_agent import main as live_main
    live_main(target=target, host=host)


def main():
    app()


if __name__ == "__main__":
    main()
