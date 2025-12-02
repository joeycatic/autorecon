import click
from core.healthcheck import healthcheck
from core.scanner.alive_scanner import AliveScanner, AliveLevel
from core.scanner.socket_port_scanner import SocketPortScanner, PortLevel
from storage.alive_repo import save_alive_results, save_dead_results
from typing import Dict, Any


def format_alive_result_line(r: Dict[str, Any]) -> str:
    host = r["host"]
    level = r["level"]
    status = r.get("status")
    reason = r.get("reason")

    if level == AliveLevel.STRONG.value:
        symbol = "[💚]"
        color = "green"
        detail = f"{status} (strong)"
    elif level == AliveLevel.WEAK.value:
        symbol = "[💛]"
        color = "yellow"
        detail = f"{status} (weak)"
    elif level == AliveLevel.DNS_ONLY.value:
        symbol = "[💙]"
        color = "blue"
        detail = "DNS only / no HTTP"
    else:  
        symbol = "[❌]"
        color = "red"
        detail = reason or "dead"

    text = f"{symbol} {host} → {detail}"
    return click.style(text, fg=color)

def format_port_result_line(r: Dict[str, Any]) -> str:
    host = r["host"]
    ip = r["ip"]
    port = r["port"]
    level = r["level"]

    if level == PortLevel.SAFE.value:
        symbol = "[💚]"
        color = "green"
        level = PortLevel.SAFE.value
    elif level == PortLevel.MEDIUM.value:
        symbol = "[💛]"
        color = "yellow"
        level = PortLevel.MEDIUM.value
    elif level == PortLevel.HIGH.value:
        symbol = "[🧡]"
        color = 214
        level = PortLevel.HIGH.value
    elif level == PortLevel.CRITICAL.value:
        symbol = "[❤️]"
        color = "red"
        level = PortLevel.CRITICAL.value
    elif level == PortLevel.WEB.value:
        symbol = "[💙]"
        color = "blue"
        level = PortLevel.WEB.value
    else:  
        symbol = "[❌]"
        color = "red"
        level = "Unreacheable"

    text = f"{symbol} {level} {port} → {ip}"

    return click.style(text, color)
    


@click.group()
def cli():
    pass


@cli.command()
def check():
    result = healthcheck()
    click.echo(result)

@cli.command()
@click.option("--target", "-t", required=True, help="Target root domain, e. g. example.com")
def alive(target):
    """Scan for alive subdomains"""
    click.echo(click.style(f"[*] Scanning alive hosts for {target}", fg="cyan", bold=True))

    scanner = AliveScanner(target)
    results = scanner.scan()

    
    strong = weak = dns_only = dead = 0

    for r in results:
        line = format_alive_result_line(r)
        click.echo(line)

        match r["level"]:
            case AliveLevel.STRONG.value:
                strong += 1
            case AliveLevel.WEAK.value:
                weak += 1
            case AliveLevel.DNS_ONLY.value:
                dns_only += 1
            case AliveLevel.DEAD.value:
                dead += 1

    save_alive_results(results)

    click.echo()
    click.echo(click.style("Summary:", bold=True))
    click.echo(click.style(f"  STRONG   : {strong}", fg="green"))
    click.echo(click.style(f"  WEAK     : {weak}", fg="yellow"))
    click.echo(click.style(f"  DNS_ONLY : {dns_only}", fg="blue"))
    click.echo(click.style(f"  DEAD     : {dead}", fg="red"))
    click.echo(click.style("Results saved to MongoDB (alive_hosts).", fg="magenta"))

@cli.command()
@click.option("--target", "-t", required=True, help="Target root domain, e. g. example.com")
@click.option("--profile", "-p", required=False, help="Specify ports")
def port(target, profile):
    """Scan for open ports"""
    click.echo(click.style(f"[*] Scanning alive ports for {target}", fg="cyan", bold=True))
    click.echo("")

    scanner = SocketPortScanner(target)
    results = scanner.scan()

    safe = medium = high = critical = web = 0

    for r in results:
        line = format_port_result_line(r)
        click.echo(line)

        match r["level"]:
            case PortLevel.SAFE.value:
                safe += 1
            case PortLevel.MEDIUM.value:
                medium += 1
            case PortLevel.HIGH.value:
                high += 1
            case PortLevel.CRITICAL.value:
                critical += 1
            case PortLevel.WEB.value:
                web += 1

    click.echo()
    click.echo(click.style("Summary:", bold=True))
    click.echo(click.style(f"  SAFE     : {safe}", fg="green"))
    click.echo(click.style(f"  MEDIUM   : {medium}", fg="yellow"))
    click.echo(click.style(f"  HIGH     : {high}", fg=214))
    click.echo(click.style(f"  CRITICAL : {critical}", fg="red"))
    click.echo(click.style(f"  WEB      : {web}", fg="blue"))
    #click.echo(click.style("Results saved to MongoDB (alive_hosts).", fg="magenta"))

@cli.command()
@click.option("--target", required=True, help="Target root domain, e. g. example.com")
def detailed_port_scan(target):
    pass


if __name__ == "__main__":
    cli()