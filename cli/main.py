import click
from core.healthcheck import healthcheck
from core.scanner.alive_scanner import AliveScanner
from storage.alive_repo import save_alive_results, save_dead_results


@click.group()
def cli():
    pass


@cli.command()
def check():
    result = healthcheck()
    click.echo(result)

@cli.command()
@click.option("--target", required=True)
def alive(target):
    """Scan for alive subdomains"""
    scanner = AliveScanner(target)
    results = scanner.scan()

    alive = []
    dead = []

    for r in results:
        if r["alive"]:
            print(f"[✓] {r['host']} ⇒ {r['status']}")
            alive.append(r)
        else:
            dead.append(r)
    
    if alive:
        save_alive_results(alive)
    
    if dead:
        save_dead_results(dead)
    print("\nSaved to database.")


if __name__ == "__main__":
    cli()
