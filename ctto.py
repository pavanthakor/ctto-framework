#!/usr/bin/env python3
"""CTTO - Credential Theft Technique Observatory

A modular cybersecurity research framework for studying credential
theft techniques and building detection telemetry.
"""

import argparse
import os
import signal
import sys
import threading
import time

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from core.engine import Engine
from dashboard.web_dashboard import serve_dashboard

console = Console()

BANNER = r"""
   _____ _______ _______ ____
  / ____|__   __|__   __/ __ \
 | |       | |     | | | |  | |
 | |       | |     | | | |  | |
 | |____   | |     | | | |__| |
  \_____|  |_|     |_|  \____/
"""

SUBTITLE = "Credential Theft Technique Observatory  [bold cyan]v1.0.0[/]"


def print_banner():
    text = Text(BANNER, style="bold red")
    console.print(Align.center(text))
    console.print(Align.center(SUBTITLE))
    console.print()


def build_engine(config_path):
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        t = progress.add_task("[cyan]Initialising engine...", total=None)
        engine = Engine(config_path=config_path)
        progress.update(t, description="[cyan]Connecting database...")
        engine._init_database()
        progress.update(t, description="[cyan]Loading modules...")
        engine._load_modules()
        engine._start_services()
        progress.update(t, description="[green]Engine ready")
    return engine


# ---------------------------------------------------------------------------
# Command: start
# ---------------------------------------------------------------------------
def cmd_start(args):
    print_banner()
    console.rule("[bold cyan]Starting CTTO Engine")

    engine = build_engine(args.config)

    mod_count = len(engine.loader.modules)
    attack_count = engine.db.get_attack_count()
    fw = engine.config.get("framework", {})
    db_path = engine.db.db_path

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column(style="white")
    info.add_row("Framework", fw.get("name", "CTTO"))
    info.add_row("Version", fw.get("version", "1.0.0"))
    info.add_row("Session", engine.session_id)
    info.add_row("Database", db_path)
    info.add_row("Modules loaded", str(mod_count))
    info.add_row("Attacks recorded", str(attack_count))
    info.add_row("Debug mode", "ON" if engine.debug else "OFF")

    console.print(Panel(info, title="[bold green]Engine Status", border_style="green"))
    console.print()
    console.print("[bold green][+][/] CTTO Engine initialized successfully.")
    engine.shutdown()


# ---------------------------------------------------------------------------
# Command: modules
# ---------------------------------------------------------------------------
def cmd_modules(args):
    print_banner()

    engine = build_engine(args.config)
    modules = engine.list_modules()

    if not modules:
        console.print(Panel("[yellow]No modules discovered.[/]", border_style="yellow"))
        engine.shutdown()
        return

    table = Table(
        title="Loaded Modules",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold white")
    table.add_column("Category", style="yellow")
    table.add_column("Author", style="dim white")
    table.add_column("Description", style="white")

    category_styles = {
        "auth": "red",
        "analysis": "blue",
        "fingerprinting": "magenta",
    }

    for m in modules:
        cat_style = category_styles.get(m["category"], "white")
        table.add_row(
            m["key"],
            m["name"],
            f"[{cat_style}]{m['category']}[/]",
            m["author"],
            m["description"] or "[dim]—[/]",
        )

    console.print(table)
    console.print(f"\n  [bold cyan]{len(modules)}[/] module(s) loaded\n")
    engine.shutdown()


# ---------------------------------------------------------------------------
# Command: dashboard
# ---------------------------------------------------------------------------
def cmd_dashboard(args):
    print_banner()
    console.rule("[bold cyan]CTTO Dashboard")

    engine = build_engine(args.config)
    attacks = engine.db.get_all_attacks()
    modules = engine.list_modules()
    fw = engine.config.get("framework", {})

    # ── top-left: framework info ──────────────────────────────────────
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="bold cyan", justify="right")
    info_table.add_column(style="white")
    info_table.add_row("Session", engine.session_id)
    info_table.add_row("Version", fw.get("version", "1.0.0"))
    info_table.add_row("Database", engine.db.db_path)
    info_table.add_row("Debug", "ON" if engine.debug else "OFF")
    info_panel = Panel(info_table, title="[bold green]Framework Info", border_style="green")

    # ── top-right: stats ─────────────────────────────────────────────
    stats_table = Table.grid(padding=(0, 2))
    stats_table.add_column(style="bold magenta", justify="right")
    stats_table.add_column(style="bold white")
    stats_table.add_row("Modules loaded", str(len(modules)))
    stats_table.add_row("Total attacks", str(len(attacks)))

    # unique IPs
    unique_ips = len({a["ip_address"] for a in attacks})
    stats_table.add_row("Unique source IPs", str(unique_ips))

    # method breakdown
    method_counts: dict[str, int] = {}
    for a in attacks:
        method_counts[a["method"]] = method_counts.get(a["method"], 0) + 1
    for method, count in sorted(method_counts.items(), key=lambda x: -x[1]):
        stats_table.add_row(f"  [{method}]", str(count))

    stats_panel = Panel(stats_table, title="[bold magenta]Attack Stats", border_style="magenta")

    # ── module table ─────────────────────────────────────────────────
    mod_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
    mod_table.add_column("Key", style="cyan")
    mod_table.add_column("Category", style="yellow")
    mod_table.add_column("Name")
    for m in modules:
        mod_table.add_row(m["key"], m["category"], m["name"])
    mod_panel = Panel(mod_table, title="[bold cyan]Modules", border_style="cyan")

    # ── recent attacks table ─────────────────────────────────────────
    atk_table = Table(box=box.SIMPLE_HEAD, header_style="bold red", show_lines=False)
    atk_table.add_column("Timestamp", style="dim white", no_wrap=True)
    atk_table.add_column("IP", style="red")
    atk_table.add_column("Username")
    atk_table.add_column("Method", style="yellow")
    atk_table.add_column("User-Agent", style="dim white")

    for a in attacks[-10:]:
        ts = str(a["timestamp"])[:19] if a["timestamp"] else "—"
        atk_table.add_row(ts, a["ip_address"], a["username"], a["method"], a["user_agent"])

    atk_panel = Panel(
        atk_table if attacks else Align.center("[dim]No attack attempts recorded yet.[/]"),
        title=f"[bold red]Recent Attacks (last {min(len(attacks), 10)})",
        border_style="red",
    )

    # ── lay it out ───────────────────────────────────────────────────
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=8),
        Layout(name="middle"),
        Layout(name="bottom"),
    )
    layout["top"].split_row(Layout(info_panel), Layout(stats_panel))
    layout["middle"].update(mod_panel)
    layout["bottom"].update(atk_panel)

    console.print(layout)
    engine.shutdown()


# ---------------------------------------------------------------------------
# Command: analyze
# ---------------------------------------------------------------------------
def cmd_analyze(args):
    print_banner()
    console.rule("[bold cyan]Module Analyzer")

    engine = build_engine(args.config)

    if args.module:
        targets = [args.module]
    else:
        targets = engine.loader.list_modules()
        if not targets:
            console.print(Panel("[yellow]No modules to analyze.[/]", border_style="yellow"))
            engine.shutdown()
            return
        console.print(f"[cyan]No module specified — running all [bold]{len(targets)}[/] module(s)...[/]\n")

    results_table = Table(
        title="Analysis Results",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
    )
    results_table.add_column("Module", style="cyan", no_wrap=True)
    results_table.add_column("Status", justify="center")
    results_table.add_column("Result", style="white")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Analyzing...", total=len(targets))
        for key in targets:
            progress.update(task, description=f"[cyan]Running [bold]{key}[/]...")
            try:
                result = engine.run_module(key)
                status = "[bold green]PASS[/]"
                result_str = str(result) if result is not None else "—"
            except Exception as exc:
                status = "[bold red]FAIL[/]"
                result_str = f"[red]{exc}[/]"
            results_table.add_row(key, status, result_str)
            progress.advance(task)

    console.print()
    console.print(results_table)

    # show updated attack count after run
    total = engine.db.get_attack_count()
    console.print(f"\n  [bold cyan]{total}[/] total attack attempt(s) in database\n")
    engine.shutdown()


# ---------------------------------------------------------------------------
# Command: run  (unified launcher — all services in one process)
# ---------------------------------------------------------------------------
def cmd_run(args):
    print_banner()
    console.rule("[bold cyan]Launching All CTTO Services")

    engine = build_engine(args.config)

    web_port   = args.web_port   or 8080
    api_port   = args.api_port   or 8081
    basic_port = args.basic_port or 8082
    dash_port  = args.dash_port  or 5000
    host       = args.host       or "0.0.0.0"

    # -- import module app factories directly so we can build servers ------
    from modules.auth.web_login import _make_app as make_web_app
    from modules.auth.api_auth import _make_api as make_api_app
    from modules.auth.basic_auth import _build_app as make_basic_app
    from werkzeug.serving import make_server as _make_server
    from dashboard.web_dashboard import app as dash_app

    # Set dashboard admin key from env (or a default for local dev)
    dash_key = os.environ.get("CTTO_DASHBOARD_KEY", "")

    servers = {}
    errors  = []

    # --- Web Login -------------------------------------------------------
    try:
        web_app = make_web_app(engine.logger, engine.db)
        servers["Web Login"]   = (_make_server(host, web_port, web_app),
                                  f"http://{host}:{web_port}/login")
    except Exception as e:
        errors.append(("Web Login", str(e)))

    # --- API Auth --------------------------------------------------------
    try:
        api_app = make_api_app(engine.logger, engine.db)
        servers["API Auth"]    = (_make_server(host, api_port, api_app),
                                  f"http://{host}:{api_port}/api/v1/login")
    except Exception as e:
        errors.append(("API Auth", str(e)))

    # --- Basic Auth ------------------------------------------------------
    # BasicAuth module expects the full module instance — create a shim
    class _Shim:
        engine_ref = engine
        def log(self, msg): engine.logger.info(msg)
        def log_attack(self, **kw): engine.db.log_attack(**kw)
    try:
        basic_app = make_basic_app(_Shim())
        servers["Basic Auth"] = (_make_server(host, basic_port, basic_app),
                                  f"http://{host}:{basic_port}/")
    except Exception as e:
        errors.append(("Basic Auth", str(e)))

    # --- Dashboard -------------------------------------------------------
    try:
        servers["Dashboard"]  = (_make_server(host, dash_port, dash_app),
                                  f"http://{host}:{dash_port}/")
    except Exception as e:
        errors.append(("Dashboard", str(e)))

    if errors:
        for name, err in errors:
            console.print(f"  [bold red]\\[FAIL][/] {name}: {err}")

    if not servers:
        console.print("[bold red]No services could start. Exiting.[/]")
        engine.shutdown()
        return

    # --- Start all servers in daemon threads -----------------------------
    threads = []
    for name, (srv, _url) in servers.items():
        t = threading.Thread(target=srv.serve_forever, daemon=True, name=name)
        t.start()
        threads.append(t)

    # --- Display live status panel ---------------------------------------
    table = Table(
        title="Running Services",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Service", style="bold white", no_wrap=True)
    table.add_column("URL", style="cyan")
    table.add_column("Status", justify="center")

    for name, (_srv, url) in servers.items():
        table.add_row(name, url, "[bold green]RUNNING[/]")
    for name, err in errors:
        table.add_row(name, "—", f"[bold red]FAILED[/]  {err}")

    console.print()
    console.print(table)
    console.print()

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan", justify="right")
    info.add_column(style="white")
    info.add_row("Session", engine.session_id)
    info.add_row("Services up", str(len(servers)))
    info.add_row("Attacks so far", str(engine.db.get_attack_count()))
    if dash_key:
        info.add_row("Dashboard key", f"X-CTTO-Admin-Key: {dash_key}")
    else:
        info.add_row("Dashboard key", "[yellow]Not set (export CTTO_DASHBOARD_KEY)[/]")
    info.add_row("Stop", "Press Ctrl+C")
    console.print(Panel(info, title="[bold green]CTTO is live", border_style="green"))

    # --- Block until Ctrl+C ----------------------------------------------
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Shutting down all services...[/]")
        for _name, (srv, _url) in servers.items():
            srv.shutdown()
        engine.shutdown()
        console.print("[bold green][+] All services stopped. Goodbye.[/]")


# ---------------------------------------------------------------------------
# Command: monitor
# ---------------------------------------------------------------------------
def cmd_monitor(args):
    print_banner()
    console.rule("[bold cyan]Live Attack Monitor")
    from core.live_monitor import start_monitor
    start_monitor()


# ---------------------------------------------------------------------------
# Command: export
# ---------------------------------------------------------------------------
def cmd_export(args):
    print_banner()
    console.rule("[bold cyan]Export Attack Report")

    from core.report_exporter import export_csv, export_json

    fmt = getattr(args, "format", "csv") or "csv"
    output = getattr(args, "output", None)

    if fmt == "json":
        path = export_json(output or "attack_report.json")
    else:
        path = export_csv(output or "attack_report.csv")

    console.print(f"[bold green][+][/] Report exported to [cyan]{path}[/]")


# ---------------------------------------------------------------------------
# Command: serve
# ---------------------------------------------------------------------------
def cmd_serve(args):
    print_banner()

    target_map = {
        "web-login": "auth/web_login",
        "api-auth": "auth/api_auth",
        "basic-auth": "auth/basic_auth",
    }

    if args.service == "dashboard":
        console.rule("[bold cyan]Starting Dashboard Service")
        serve_dashboard(host=args.host or "0.0.0.0", port=args.port or 5000)
        return

    module_key = target_map[args.service]
    console.rule(f"[bold cyan]Starting Service: {args.service}")

    engine = build_engine(args.config)
    try:
        kwargs = {}
        if args.host:
            kwargs["host"] = args.host
        if args.port:
            kwargs["port"] = args.port
        engine.run_module(module_key, **kwargs)
    finally:
        engine.shutdown()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="ctto",
        description="CTTO - Credential Theft Technique Observatory",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ctto run                         # launch ALL services at once\n"
            "  ctto start                       # show engine status\n"
            "  ctto modules                     # list loaded modules\n"
            "  ctto dashboard                   # rich terminal dashboard\n"
            "  ctto analyze                     # run all analysis modules\n"
            "  ctto analyze --module auth/basic_auth\n"
            "  ctto serve web-login --port 8080\n"
            "  ctto serve api-auth --port 8081\n"
            "  ctto serve basic-auth --port 8082\n"
            "  ctto serve dashboard --port 5000\n"
            "  ctto monitor                     # live attack feed\n"
            "  ctto export                      # export CSV report\n"
            "  ctto export --format json        # export JSON report\n"
        ),
    )
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config file")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("start", help="Start the CTTO engine and show status")
    sub.add_parser("modules", help="List all loaded modules")
    sub.add_parser("dashboard", help="Show live framework dashboard")

    run_parser = sub.add_parser("run", help="Launch ALL services in one process")
    run_parser.add_argument("--host", default=None, help="Bind host (default 0.0.0.0)")
    run_parser.add_argument("--web-port",   type=int, default=None, dest="web_port",   help="Web login port (default 8080)")
    run_parser.add_argument("--api-port",   type=int, default=None, dest="api_port",   help="API auth port (default 8081)")
    run_parser.add_argument("--basic-port", type=int, default=None, dest="basic_port", help="Basic auth port (default 8082)")
    run_parser.add_argument("--dash-port",  type=int, default=None, dest="dash_port",  help="Dashboard port (default 5000)")

    sub.add_parser("monitor", help="Live real-time attack feed in terminal")

    export_parser = sub.add_parser("export", help="Export attack report to file")
    export_parser.add_argument(
        "-f", "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)",
    )
    export_parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Output file path",
    )

    analyze_parser = sub.add_parser("analyze", help="Run module analysis")
    analyze_parser.add_argument(
        "-m", "--module",
        default=None,
        metavar="KEY",
        help="Module key to run (e.g. auth/basic_auth). Omit to run all modules.",
    )

    serve_parser = sub.add_parser("serve", help="Run long-lived CTTO services")
    serve_parser.add_argument(
        "service",
        choices=["web-login", "api-auth", "basic-auth", "dashboard"],
        help="Service to run",
    )
    serve_parser.add_argument("--host", default=None, help="Bind host")
    serve_parser.add_argument("--port", type=int, default=None, help="Bind port")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "run": cmd_run,
        "start": cmd_start,
        "modules": cmd_modules,
        "dashboard": cmd_dashboard,
        "analyze": cmd_analyze,
        "monitor": cmd_monitor,
        "export": cmd_export,
        "serve": cmd_serve,
    }

    try:
        dispatch[args.command](args)
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Interrupted.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()

