"""CTTO Live Attack Monitor — real-time terminal dashboard.

Usage:
    python3 ctto.py monitor
"""

import time

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box

from core.database import Database

console = Console()

DB_PATH = "data/ctto.db"


def start_monitor():
    """Poll the database every 2 seconds and render the latest attacks."""
    db = Database(DB_PATH)
    db.connect()

    console.print("[bold green]CTTO Live Attack Monitor[/]")
    console.print("[dim]Refreshing every 2 s — press Ctrl+C to stop[/]\n")

    def _build_table():
        attacks = db.get_recent_attacks(limit=20)

        table = Table(
            title="Recent Credential Attacks",
            box=box.ROUNDED,
            border_style="red",
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("Time", style="dim white", no_wrap=True)
        table.add_column("IP", style="red")
        table.add_column("Username", style="bold white")
        table.add_column("Method", style="yellow")
        table.add_column("Threat", justify="center")
        table.add_column("User-Agent", style="dim", max_width=40)

        for a in attacks:
            ts = str(a["timestamp"])[:19] if a["timestamp"] else "—"
            score = a.get("threat_score", 0)
            if score >= 60:
                score_style = f"[bold red]{score}[/]"
            elif score >= 30:
                score_style = f"[bold yellow]{score}[/]"
            else:
                score_style = f"[green]{score}[/]"
            table.add_row(
                ts,
                a["ip_address"],
                a["username"] or "[dim]—[/]",
                a["method"],
                score_style,
                (a.get("user_agent") or "")[:40],
            )

        return table

    try:
        with Live(_build_table(), console=console, refresh_per_second=1) as live:
            while True:
                time.sleep(2)
                live.update(_build_table())
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Monitor stopped.[/]")
    finally:
        db.close()
