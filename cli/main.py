import click
from core.healthcheck import healthcheck


@click.group()
def cli():
    pass


@cli.command()
def check():
    result = healthcheck()
    click.echo(result)


if __name__ == "__main__":
    cli()
