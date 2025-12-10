from autorecon.core.scanner.socket_port_scanner import PortLevel
from autorecon.core.scanner.alive_scanner import AliveLevel
from rich.table import Table
from rich.console import Console
from rich.panel import Panel

def alive_results_table(results):
    console = Console()

    if isinstance(results, dict):
        results = [results]

    table = Table(
        title="Alive Scan Results",
        header_style="bold cyan",
        border_style="cyan",
        show_lines=False,
    )

    table.add_column("Host", style="bold white")
    table.add_column("HTTP", justify="center")
    table.add_column("URL", style="bright_blue")
    table.add_column("Status", justify="center")  

    for r in results:
        level = r["level"]          
        status = r.get("status")    
        url = r.get("url") or "-"
        alive = r.get("alive", False)

        if level == "strong":
            symbol = "💚"
            color = "green"
            label = "STRONG"
        elif level == "weak":
            symbol = "💛"
            color = "yellow"
            label = "WEAK"
        elif level == "dns_only":
            symbol = "💙"
            color = "blue"
            label = "DNS ONLY"
            
            if not status:
                status = "-"
            if not url or url == "-":
                url = "-"
        else:
            symbol = "❌"
            color = "red"
            label = "DEAD"
            
            if not status:
                status = "-"
            url = "-"

        if not alive and level == "strong":
            symbol = "❌"
            color = "red"
            label = "DEAD"

        table.add_row(
            r["host"],
            str(status) if status is not None else "-",
            url,
            f"[{color}]{symbol} {label}[/{color}]",
        )

    console.print(table)




def port_results_table(results):
    console = Console()

    table = Table(
        title="Port Scan Results",
        header_style="bold cyan",
        show_lines=True,
        border_style="cyan"
    )

    table.add_column("Host", style="bold white")
    table.add_column("IP", style="white")
    table.add_column("Port", justify="center", style="cyan")
    table.add_column("Level", justify="center")
    table.add_column("Symbol", justify="center")

    for r in results:
        level = r["level"]

        if level == PortLevel.SAFE.value:
            symbol = "💚"
            color = "green"
            label = "SAFE"
        elif level == PortLevel.MEDIUM.value:
            symbol = "💛"
            color = "yellow"
            label = "MEDIUM"
        elif level == PortLevel.HIGH.value:
            symbol = "🧡"
            color = "orange1"
            label = "HIGH"
        elif level == PortLevel.CRITICAL.value:
            symbol = "❤️"
            color = "red"
            label = "CRITICAL"
        elif level == PortLevel.WEB.value:
            symbol = "💙"
            color = "blue"
            label = "WEB"
        else:
            symbol = "❌"
            color = "red"
            label = "UNREACHABLE"

        table.add_row(
            f"[white]{r['host']}[/white]",
            f"[white]{r['ip']}[/white]",
            f"[cyan]{r['port']}[/cyan]",
            f"[{color}]{label}[/]",
            f"[{color}]{symbol}[/]"
        )

    console.print(table)


def rich_nmap_table(results, target):
    console = Console()

    console.print(Panel.fit(
        f"[bold cyan]Nmap Scan Results[/bold cyan]\n[white]Target:[/white] [bold yellow]{target}[/bold yellow]",
        border_style="cyan"
    ))

    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        show_lines=False,
    )

    table.add_column("Port", justify="center", style="bold white")
    table.add_column("State", justify="center")
    table.add_column("Service", justify="center", style="magenta")
    table.add_column("Version", justify="left", style="green")

    for r in results:
        if r["state"] == "open":
            state = "[bold green]● OPEN[/bold green]"
        elif r["state"] == "filtered":
            state = "[yellow]▲ FILTERED[/yellow]"
        else:
            state = f"[red]✖ {r['state'].upper()}[/red]"

        table.add_row(
            str(r["port"]),
            state,
            r.get("service") or "-",
            r.get("version") or "-"
        )

    console.print(table)
