#!/usr/bin/env python3
"""
NEXUS-STRIKE Command Line Interface
Rich CLI with commands for running missions, managing tools/agents, and configuring providers.
"""
import asyncio
import typer
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
    help="🏴‍☠️ NEXUS-STRIKE: The Ultimate AI-Powered Cybersecurity Platform",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Target domain, IP, or URL"),
    mode: str = typer.Option("guided", "--mode", "-m",
                             help="Execution mode: [bold]autonomous[/], [bold]guided[/], [bold]tool[/], [bold]interactive[/]"),
    mission: str = typer.Option("mission-001", "--mission", "--id", help="Mission identifier"),
    objective: str = typer.Option("full_assessment", "--objective", "-o",
                                  help="Mission objective: full_assessment, quick_scan, vuln_scan, osint"),
    provider: str = typer.Option(None, "--provider", "-p",
                                 help="LLM provider: openai, anthropic, openrouter, ollama, groq, deepseek, omniroute, custom"),
):
    """🚀 Launch a security assessment mission."""
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


@app.command()
def version():
    """📦 Show version information."""
    console.print(Panel.fit(
        "[bold green]NEXUS-STRIKE[/] v0.1.0\n"
        "[dim]The Ultimate AI-Powered Cybersecurity Platform[/]\n\n"
        "29 security domains | 500+ tools | 54 agents | 6 patterns | 9 LLM providers",
        style="bold",
    ))


def main():
    app()


if __name__ == "__main__":
    main()