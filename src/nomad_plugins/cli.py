import asyncio
from pathlib import Path

import click

from nomad_plugins.catalogue import build_catalogue_snapshot, write_catalogue_snapshot
from nomad_plugins.crawler import find_plugins


@click.group()
def main() -> None:
    """Tools for working with the NOMAD plugin catalogue."""


@main.command()
@click.option(
    '--github-token',
    prompt='GitHub personal access token',
    help='Your GitHub personal access token to use when querying for plugins.',
    envvar='GITHUB_TOKEN',
    hide_input=True,
)
@click.option(
    '--output',
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help='Path where the catalogue snapshot JSON should be written.',
)
def crawl(github_token: str, output: Path) -> None:
    """Crawl plugin metadata and write a catalogue snapshot as JSON."""
    try:
        plugins = asyncio.run(find_plugins(github_token))
        snapshot = build_catalogue_snapshot(plugins)
        write_catalogue_snapshot(snapshot, output)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f'Wrote {len(plugins)} plugins to {output}')


if __name__ == '__main__':
    main()
