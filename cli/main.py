import click
import re
from core.healthcheck import healthcheck
from core.scanner.alive_scanner import AliveScanner, AliveLevel
from core.scanner.socket_port_scanner import SocketPortScanner, PortLevel
from core.scanner.nmap_port_scanner import NmapPortScanner
from storage.alive_repo import save_alive_results
from storage.open_port_repo import save_open_port_results
from utils.cli_formatting import alive_results_table, port_results_table, rich_nmap_table

PORT_RANGE_REGEX = re.compile(r"^\d{1,5}-\d{1,5}$")

def validate_port_range(ctx, param, value):
    if value is None:
        return None

    if not PORT_RANGE_REGEX.match(value):
        raise click.BadParameter("Format must be <start>-<end>, e.g. 10-200")

    start, end = map(int, value.split("-"))

    if start < 1 or end > 65535:
        raise click.BadParameter("Port range must be between 1 and 65535")

    if start > end:
        raise click.BadParameter("Start port must be less than end port")

    return start, end
    

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
    click.echo()

    scanner = AliveScanner(target)
    results = scanner.scan()
    
    strong = weak = dns_only = dead = 0

    alive_results_table(results)
    for r in results:
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
    click.echo(f"Scan finished in {scanner.duration:.2f} seconds")


@cli.command()
@click.option("--target", "-t", required=True, help="Target root domain, e. g. example.com")
@click.option("--ports", "-p", required=False, callback=validate_port_range, help="Choose a port range, <int>-<int>")
@click.option("--fast", is_flag=True, help="Fast port scan")
def port(target, ports, fast):
    """Scan for open ports"""
    click.echo(click.style(f"[*] Scanning open ports for {target}", fg="cyan", bold=True))
    click.echo()

    scanner = None
    results = None

    scanner = SocketPortScanner(target)

    if fast:
        results = scanner.fast_scan()
    else:
        results = scanner.scan()

    safe = medium = high = critical = web = 0

    port_results_table(results)

    for r in results:
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

    save_open_port_results(results)

    click.echo()
    click.echo(click.style("Summary:", bold=True))
    click.echo(click.style(f"  SAFE     : {safe}", fg="green"))
    click.echo(click.style(f"  MEDIUM   : {medium}", fg="yellow"))
    click.echo(click.style(f"  HIGH     : {high}", fg=214))
    click.echo(click.style(f"  CRITICAL : {critical}", fg="red"))
    click.echo(click.style(f"  WEB      : {web}", fg="blue"))
    click.echo(click.style("Results saved to MongoDB (open_ports).", fg="magenta"))
    click.echo(f"Scan finished in {scanner.duration:.2f} seconds")


@cli.command()
@click.option("--target", "-t", required=True, help="Target root domain, e. g. example.com")
@click.option("--ports", "-p", default="1-1000", show_default=True, callback=validate_port_range)
@click.option("--aggressive", "-a", is_flag=True, help="Fast port scan")
def nmap(target, ports, aggressive):
    click.echo(click.style(f"[*] Scanning open ports for {target}", fg="cyan", bold=True))
    click.echo("")

    print(ports)
    scanner = NmapPortScanner(target)

    start_port, end_port = ports or (1, 1000)
    results = scanner.scan(start_port, end_port, aggressive)

    rich_nmap_table(results, target)
    
    click.echo(f"Scan finished in {scanner.duration:.2f} seconds")

if __name__ == "__main__":
    cli()