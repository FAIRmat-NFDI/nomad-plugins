import asyncio
import json
from pathlib import Path

import click

from nomad_plugins.catalogue import build_catalogue_snapshot, write_catalogue_snapshot
from nomad_plugins.config import load_catalogue_config
from nomad_plugins.crawler import find_plugins


@click.group()
def main() -> None:
    """Tools for working with the NOMAD plugin catalogue."""


@main.command()
@click.option(
    '--config',
    'config_path',
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help='Optional path to a catalogue configuration JSON file.',
)
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
def crawl(config_path: Path | None, github_token: str, output: Path) -> None:
    """Crawl plugin metadata and write a catalogue snapshot as JSON."""
    try:
        config = load_catalogue_config(config_path)
        result = asyncio.run(find_plugins(github_token, config=config))
        snapshot = build_catalogue_snapshot(result.plugins)
        write_catalogue_snapshot(snapshot, output)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    for diagnostics in result.search_diagnostics:
        click.echo(
            f'GitHub code search {diagnostics.query!r}: received '
            f'{diagnostics.fetched_count} result item(s) across '
            f'{diagnostics.page_count} page(s); latest reported total: '
            f'{diagnostics.total_count}.'
        )
    click.echo(f'Unique pyproject.toml candidates: {result.unique_candidate_count}.')
    click.echo(f'Wrote {len(result.plugins)} plugins to {output}')


@main.command()
@click.option(
    '--config',
    'config_path',
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help='Optional path to a catalogue configuration JSON file.',
)
def queries(config_path: Path | None) -> None:
    """Print the effective GitHub code-search configuration."""
    try:
        config = load_catalogue_config(config_path)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(
        json.dumps(
            config.model_dump(mode='json', by_alias=True),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == '__main__':
    main()
