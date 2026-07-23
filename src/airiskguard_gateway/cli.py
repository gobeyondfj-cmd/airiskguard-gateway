from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timedelta
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text

from airiskguard_gateway.config import (
    CONFIG_DIR, DATA_DIR, RUN_DIR, LOG_DIR,
    GatewayConfig, DEFAULT_CONFIG_YAML,
)
from airiskguard_gateway.proxy.cert import CertManager

console = Console()
PID_FILE = RUN_DIR / "airiskguard-gateway.pid"
DAEMON_LOG = LOG_DIR / "airiskguard-gateway.log"


@click.group()
def main() -> None:
    """AIRiskGuard Gateway — AI traffic management for developer teams."""
    pass


@main.command()
@click.option("--config", "-c", type=click.Path(), help="Path to config.yaml")
@click.option("--daemon", "-d", is_flag=True, help="Run as background daemon")
@click.option("--mode", type=click.Choice(["api", "proxy"]), default="api",
              help="api: HTTP API proxy (recommended for Claude Code/SDKs). proxy: transparent HTTPS proxy.")
def start(config: str | None, daemon: bool, mode: str) -> None:
    """Start the gateway proxy."""
    cfg = GatewayConfig.load(Path(config) if config else None)
    _setup_logging(cfg.log_level)

    if daemon:
        _daemonize(cfg)
        return

    cert_path = CertManager().cert_pem_path()

    console.print(f"\n[bold cyan]◆ AIRiskGuard Gateway[/] v0.5.0  [dim](mode: {mode})[/]")
    console.print(f"  Listening on [green]{cfg.listen_host}:{cfg.listen_port}[/]")
    console.print()

    if mode == "api":
        console.print("  [bold]Set these in your shell:[/]")
        console.print(f"    [yellow]export ANTHROPIC_BASE_URL=http://{cfg.listen_host}:{cfg.listen_port}/anthropic[/]  [dim]# Claude Code[/]")
        console.print(f"    [yellow]export OPENAI_BASE_URL=http://{cfg.listen_host}:{cfg.listen_port}/openai[/]      [dim]# Codex CLI / OpenAI[/]")
        console.print(f"  [dim]No CA cert needed in API mode.[/]")
    else:
        _install_cert_if_needed()
        console.print("  [bold]Set these in your shell:[/]")
        console.print(f"    [yellow]export HTTPS_PROXY=http://{cfg.listen_host}:{cfg.listen_port}[/]")
        console.print(f"    [yellow]export NODE_EXTRA_CA_CERTS={cert_path}[/]  [dim]# for Claude Code[/]")

    console.print()
    console.print(f"  Secrets: [cyan]{cfg.on_secrets_detected}[/]  PII: [cyan]{cfg.on_pii_detected}[/]")
    console.print(f"  Audit log: [dim]{cfg.audit.resolved_path()}[/]")
    console.print()
    console.print("  Press [dim]Ctrl+C[/] to stop.\n")

    if mode == "api":
        import uvicorn
        from airiskguard_gateway.audit.logger import AuditLogger
        from airiskguard_gateway.policy.engine import PolicyEngine
        from airiskguard_gateway.routing.engine import RoutingEngine
        from airiskguard_gateway.scanner.engine import ScanEngine
        from airiskguard_gateway.proxy.api_server import create_api_server

        logger = AuditLogger(cfg)
        scanner = ScanEngine(cfg)
        policy = PolicyEngine(cfg)
        router = RoutingEngine(
            rules=cfg.routing.parsed_rules(),
            destinations=cfg.routing.parsed_destinations(),
            sticky_sessions=cfg.routing.sticky_sessions,
            session_ttl_hours=cfg.routing.session_ttl_hours,
        )
        app = create_api_server(cfg, logger, scanner, policy, router)
        try:
            uvicorn.run(app, host=cfg.listen_host, port=cfg.listen_port, log_level="warning")
        except KeyboardInterrupt:
            console.print("\n[dim]Gateway stopped.[/]")
    else:
        from airiskguard_gateway.proxy.server import run_proxy
        try:
            asyncio.run(run_proxy(cfg))
        except KeyboardInterrupt:
            console.print("\n[dim]Gateway stopped.[/]")


@main.command()
def setup() -> None:
    """First-time setup: generate CA cert, install to trust store, and print shell config."""
    import platform

    console.print("\n[bold cyan]◆ AIRiskGuard Gateway — Setup[/]\n")

    # Step 1: generate + install cert
    console.print("[bold]Step 1[/] — Generating CA certificate...")
    cert_mgr = CertManager()
    cert_mgr.ensure_cert()
    console.print(f"  CA cert: [cyan]{cert_mgr.cert_pem_path()}[/]")

    console.print("[bold]Step 2[/] — Installing to system trust store...")
    result = cert_mgr.install_to_system()
    console.print(f"  {result}")

    # Step 3: generate default config
    cfg_path = CONFIG_DIR / "config.yaml"
    if not cfg_path.exists():
        console.print("[bold]Step 3[/] — Writing default config...")
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(DEFAULT_CONFIG_YAML)
        console.print(f"  Config: [cyan]{cfg_path}[/]")
    else:
        console.print(f"[bold]Step 3[/] — Config already exists: [dim]{cfg_path}[/]")

    cfg = GatewayConfig.load()
    cert_path = cert_mgr.cert_pem_path()

    # Step 4: print shell setup instructions
    console.print("\n[bold]Step 4[/] — Add these to your shell config:\n")

    shell_file = "~/.zshrc" if platform.system() == "Darwin" else "~/.bashrc"
    console.print(f"  [dim]# Add to {shell_file}[/]")
    console.print()
    console.print(f"  [bold]API mode[/] [dim](recommended — no CA cert needed):[/]")
    console.print(f"  [yellow]export ANTHROPIC_BASE_URL=http://{cfg.listen_host}:{cfg.listen_port}/anthropic[/]  [dim]# Claude Code[/]")
    console.print(f"  [yellow]export OPENAI_BASE_URL=http://{cfg.listen_host}:{cfg.listen_port}/openai[/]      [dim]# Codex CLI[/]")
    console.print()
    console.print(f"  [bold]Transparent proxy mode[/] [dim](for Cursor and other tools):[/]")
    console.print(f"  [yellow]export HTTPS_PROXY=http://{cfg.listen_host}:{cfg.listen_port}[/]")
    console.print(f"  [yellow]export NODE_EXTRA_CA_CERTS={cert_path}[/]")
    console.print()

    # Per-tool instructions
    console.print("[bold]Claude Code[/]")
    console.print(f"  [yellow]export ANTHROPIC_BASE_URL=http://{cfg.listen_host}:{cfg.listen_port}/anthropic[/]")
    console.print()
    console.print("[bold]OpenAI Codex CLI[/]")
    console.print(f"  [yellow]export OPENAI_BASE_URL=http://{cfg.listen_host}:{cfg.listen_port}/openai[/]")
    console.print()
    console.print("[bold]Cursor[/]")
    console.print(f"  Settings → Features → HTTP Proxy → [yellow]http://{cfg.listen_host}:{cfg.listen_port}[/]")
    console.print()
    console.print("[bold]Start the gateway:[/]")
    console.print("  [cyan]airiskguard-gateway start[/]              [dim]# API mode (default, no cert needed)[/]")
    console.print("  [cyan]airiskguard-gateway start --mode proxy[/]  [dim]# Transparent proxy mode[/]")
    console.print()
    console.print("[bold]Verify it's working:[/]")
    console.print("  1. Start: [cyan]airiskguard-gateway start[/]")
    console.print("  2. Make any AI request through Claude Code or Cursor")
    console.print("  3. Check: [cyan]airiskguard-gateway logs --tail 5[/]")
    console.print()
    console.print("[green]Setup complete.[/]\n")



    """Stop the background daemon."""
    if not PID_FILE.exists():
        console.print("[yellow]No running gateway daemon found.[/]")
        return
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        PID_FILE.unlink(missing_ok=True)
        console.print("[yellow]Invalid PID file — removed.[/]")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        PID_FILE.unlink(missing_ok=True)
        console.print(f"[green]Gateway daemon (PID {pid}) stopped.[/]")
    except ProcessLookupError:
        PID_FILE.unlink(missing_ok=True)
        console.print("[yellow]Process not found — PID file removed.[/]")
    except PermissionError:
        console.print(f"[red]Permission denied to stop PID {pid}.[/]")


@main.command()
def status() -> None:
    """Show gateway status and recent stats."""
    running = _check_running()
    cfg = GatewayConfig.load()

    console.print(f"\n[bold]◆ AIRiskGuard Gateway[/]\n")

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="dim", width=20)
    info.add_column("Value")
    info.add_row("Status", "[green]● Running[/]" if running else "[red]○ Stopped[/]")
    info.add_row("Listen", f"{cfg.listen_host}:{cfg.listen_port}")
    info.add_row("Secrets detected", cfg.on_secrets_detected)
    info.add_row("PII detected", cfg.on_pii_detected)
    info.add_row("Model allowlist", "[green]enabled[/]" if cfg.model_allowlist_enabled else "[dim]disabled[/]")
    info.add_row("Policy server", cfg.policy_server.url or "[dim]not configured (free tier)[/]")
    info.add_row("Audit log", str(cfg.audit.resolved_path()))
    console.print(info)

    # Stats from last hour
    audit_path = cfg.audit.resolved_path()
    if audit_path.exists():
        from airiskguard_gateway.audit.logger import AuditLogger
        logger = AuditLogger(cfg)
        since = datetime.now(UTC) - timedelta(hours=1)
        events = logger.tail(n=10_000, since=since)

        blocked = sum(1 for e in events if e.get("action_taken") == "blocked")
        redacted = sum(1 for e in events if e.get("action_taken") == "redacted")
        providers: dict[str, int] = {}
        for e in events:
            p = e.get("provider", "unknown")
            providers[p] = providers.get(p, 0) + 1

        console.print()
        stats = Table(show_header=False, box=None, padding=(0, 2))
        stats.add_column("Key", style="dim", width=20)
        stats.add_column("Value")
        stats.add_row("Last hour requests", str(len(events)))
        stats.add_row("Blocked", f"[red]{blocked}[/]" if blocked else "0")
        stats.add_row("Redacted", f"[yellow]{redacted}[/]" if redacted else "0")
        if providers:
            stats.add_row("Providers", ", ".join(f"{k}({v})" for k, v in sorted(providers.items(), key=lambda x: -x[1])))
        console.print("[dim]Last hour:[/]")
        console.print(stats)


@main.command()
@click.option("--tail", "-n", default=50, help="Number of events to show")
@click.option("--follow", "-f", is_flag=True, help="Follow log in real time")
@click.option("--since", default=None, help="Time filter: 1h, 30m, 24h, 7d")
@click.option("--blocked-only", is_flag=True, help="Show only blocked requests")
@click.option("--provider", default=None, help="Filter by provider (anthropic, openai, azure_openai)")
def logs(tail: int, follow: bool, since: str | None, blocked_only: bool, provider: str | None) -> None:
    """View audit logs."""
    cfg = GatewayConfig.load()
    from airiskguard_gateway.audit.logger import AuditLogger
    logger = AuditLogger(cfg)

    since_dt: datetime | None = None
    if since:
        since_dt = _parse_since(since)

    if follow:
        _follow_log(cfg.audit.resolved_path(), blocked_only, provider)
        return

    events = logger.tail(n=tail, since=since_dt)

    if blocked_only:
        events = [e for e in events if e.get("action_taken") == "blocked"]
    if provider:
        events = [e for e in events if e.get("provider") == provider]

    if not events:
        console.print("[dim]No events found.[/]")
        return

    table = Table(title="Audit Log", show_lines=False, show_edge=True)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Provider", width=12)
    table.add_column("Model", width=26)
    table.add_column("Dir", width=8)
    table.add_column("Action", width=10)
    table.add_column("#", width=4, justify="right")

    for e in events:
        action = e.get("action_taken", "")
        if action == "blocked":
            action_str = "[red]blocked[/]"
        elif action == "redacted":
            action_str = "[yellow]redacted[/]"
        else:
            action_str = "[dim]allowed[/]"

        ts = e.get("timestamp", "")[:19].replace("T", " ")
        model = e.get("model", "")
        if len(model) > 26:
            model = model[:23] + "..."

        table.add_row(
            ts,
            e.get("provider", ""),
            model,
            e.get("direction", ""),
            action_str,
            str(len(e.get("findings", []))),
        )

    console.print(table)
    console.print(f"[dim]Showing {len(events)} event(s). Audit log: {cfg.audit.resolved_path()}[/]")


@main.command("install-cert")
def install_cert() -> None:
    """Generate CA certificate and install to system trust store."""
    console.print("[bold]Generating CA certificate...[/]")
    cert_mgr = CertManager()
    cert_mgr.ensure_cert()
    console.print(f"  CA cert: [cyan]{cert_mgr.cert_pem_path()}[/]")
    console.print("\n[bold]Installing to system trust store...[/]")
    result = cert_mgr.install_to_system()
    console.print(f"  {result}")
    console.print(f"\n[green]Done.[/] Set [yellow]NODE_EXTRA_CA_CERTS={cert_mgr.cert_pem_path()}[/] for Claude Code.")


@main.command("keys")
def keys_cmd() -> None:
    """Show API key status for all configured providers."""
    from airiskguard_gateway.config import BUILTIN_PROVIDERS
    cfg = GatewayConfig.load()
    providers = cfg.resolved_providers()

    table = Table(title="Provider API Keys", show_lines=False)
    table.add_column("Provider", style="cyan", width=14)
    table.add_column("Env Var", style="dim", width=24)
    table.add_column("Status", width=10)
    table.add_column("Key (masked)", style="dim", width=20)

    for name, p in providers.items():
        if name == "ollama":
            table.add_row(name, "(none)", "[dim]n/a[/]", "[dim]local model[/]")
            continue
        source, masked = p.key_status()
        if source == "missing":
            status = "[red]✗ missing[/]"
            masked = ""
        elif source == "env":
            status = "[green]✓ env[/]"
        else:
            status = "[yellow]✓ config[/]"
        env_var = p.api_key_env or "—"
        table.add_row(name, env_var, status, masked)

    console.print(table)
    console.print()
    console.print("[dim]Set env vars in your shell, or add to config.yaml:[/]")
    console.print("[dim]  api_keys:[/]")
    console.print("[dim]    anthropic: sk-ant-...[/]")
    console.print("[dim]    openai: sk-...[/]")
    console.print("[dim]    deepseek: sk-...[/]")
    console.print()
    console.print(f"[dim]Config: {CONFIG_DIR / 'config.yaml'}[/]")



@click.argument("key", required=False)
def license_cmd(key: str | None) -> None:
    """Validate a license key. Pass the key as argument or set AIRISKGUARD_LICENSE env var."""
    from airiskguard_gateway.license import validate_license
    status = validate_license(license_key=key)
    if status.valid:
        console.print(f"[green]License valid.[/] {status.reason}")
        if status.subscription_id:
            console.print(f"  Subscription: [dim]{status.subscription_id}[/]")
    else:
        console.print(f"[red]License invalid.[/] {status.reason}")
        console.print("\nGet a license at [cyan]https://airiskguard.ai/#pricing[/]")


@main.group()
def config() -> None:
    """Manage gateway configuration."""
    pass


@config.command("show")
def config_show() -> None:
    """Print current configuration."""
    cfg_path = CONFIG_DIR / "config.yaml"
    if cfg_path.exists():
        console.print(f"[dim]{cfg_path}[/]\n")
        console.print(cfg_path.read_text())
    else:
        console.print("[dim]No config file found at[/] " + str(cfg_path))
        console.print("[dim]Using built-in defaults. Run[/] airiskguard-gateway config init [dim]to create one.[/]")


@config.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing config")
def config_init(force: bool) -> None:
    """Write default config.yaml to ~/.config/airiskguard-gateway/config.yaml."""
    cfg_path = CONFIG_DIR / "config.yaml"
    if cfg_path.exists() and not force:
        console.print(f"[yellow]Config already exists:[/] {cfg_path}")
        console.print("Use [bold]--force[/] to overwrite.")
        return
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(DEFAULT_CONFIG_YAML)
    console.print(f"[green]Config written to[/] {cfg_path}")


# ── Internal helpers ─────────────────────────────────────────────────────────

def _install_cert_if_needed() -> None:
    cert_mgr = CertManager()
    if not (CONFIG_DIR / "mitmproxy-ca.pem").exists():
        console.print("[dim]First run — generating CA certificate...[/]")
        cert_mgr.ensure_cert()
        console.print("[dim]Installing to system trust store...[/]")
        result = cert_mgr.install_to_system()
        console.print(f"[dim]{result}[/]\n")


def _check_running() -> bool:
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, ProcessLookupError, PermissionError):
        return False


def _daemonize(cfg: GatewayConfig) -> None:
    if sys.platform == "win32":
        console.print("[red]Daemon mode is not supported on Windows. Run without --daemon.[/]")
        return

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    pid = os.fork()
    if pid > 0:
        console.print(f"[green]◆ Gateway daemon started[/] (PID {pid})")
        console.print(f"  Log: [dim]{DAEMON_LOG}[/]")
        console.print(f"  Stop: [dim]airiskguard-gateway stop[/]")
        return

    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        sys.exit(0)

    PID_FILE.write_text(str(os.getpid()))

    with open(DAEMON_LOG, "a") as log_fd:
        os.dup2(log_fd.fileno(), sys.stdout.fileno())
        os.dup2(log_fd.fileno(), sys.stderr.fileno())

    from airiskguard_gateway.proxy.server import run_proxy
    asyncio.run(run_proxy(cfg))


def _parse_since(since: str) -> datetime:
    now = datetime.now(UTC)
    s = since.strip().lower()
    try:
        if s.endswith("h"):
            return now - timedelta(hours=int(s[:-1]))
        if s.endswith("m"):
            return now - timedelta(minutes=int(s[:-1]))
        if s.endswith("d"):
            return now - timedelta(days=int(s[:-1]))
    except ValueError:
        pass
    return now - timedelta(hours=1)


def _follow_log(path: Path, blocked_only: bool, provider_filter: str | None) -> None:
    import json
    import time

    console.print("[dim]Following audit log (Ctrl+C to stop)...[/]\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()

    with open(path) as f:
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.15)
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if blocked_only and e.get("action_taken") != "blocked":
                    continue
                if provider_filter and e.get("provider") != provider_filter:
                    continue

                action = e.get("action_taken", "")
                if action == "blocked":
                    action_fmt = "[red]BLOCKED[/]"
                elif action == "redacted":
                    action_fmt = "[yellow]REDACTED[/]"
                else:
                    action_fmt = "[dim]allowed[/]"

                nfindings = len(e.get("findings", []))
                findings_fmt = f" [dim]{nfindings} finding(s)[/]" if nfindings else ""

                console.print(
                    f"[dim]{e.get('timestamp','')[:19]}[/]  "
                    f"[cyan]{e.get('provider',''):12}[/]  "
                    f"{e.get('model','')[:28]:28}  "
                    f"{action_fmt}{findings_fmt}"
                )
        except KeyboardInterrupt:
            pass


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
