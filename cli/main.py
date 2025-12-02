import click
from core.healthcheck import healthcheck
from core.scanner.alive_scanner import AliveScanner, AliveLevel
from storage.alive_repo import save_alive_results, save_dead_results
from typing import Dict, Any


def format_result_line(r: Dict[str, Any]) -> str:
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


@click.group()
def cli():
    pass


@cli.command()
def check():
    result = healthcheck()
    click.echo(result)

@cli.command()
@click.option("--target", required=True, help="Target root domain, e. g. example.com")
def alive(target):
    """Scan for alive subdomains"""
    click.echo(click.style(f"[*] Scanning alive hosts for {target}", fg="cyan", bold=True))

    scanner = AliveScanner(target)
    results = scanner.scan()

    
    strong = weak = dns_only = dead = 0

    for r in results:
        line = format_result_line(r)
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


if __name__ == "__main__":
    cli()
