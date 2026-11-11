import asyncio
import json
from pathlib import Path

import click

from nomad_plugins.catalogue import build_catalogue_snapshot, write_catalogue_snapshot
from nomad_plugins.config import load_catalogue_config
from nomad_plugins.crawler import Plugin, SearchCandidateAudit, find_plugins


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
@click.option(
    '--audit-searches',
    is_flag=True,
    help='List each search result, its discovery outcome, and final project kind.',
)
def crawl(
    config_path: Path | None,
    github_token: str,
    output: Path,
    audit_searches: bool,
) -> None:
    """Crawl plugin metadata and write a catalogue snapshot as JSON."""
    try:
        config = load_catalogue_config(config_path)
        result = asyncio.run(find_plugins(github_token, config=config))
        snapshot = build_catalogue_snapshot(result.plugins)
        write_catalogue_snapshot(snapshot, output)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    plugins_by_id = {plugin.id.casefold(): plugin for plugin in result.plugins}
    for query_diagnostics in result.search_diagnostics:
        diagnostics = query_diagnostics.search
        click.echo(
            f'GitHub code search {diagnostics.query!r}: received '
            f'{diagnostics.fetched_count} result item(s) across '
            f'{diagnostics.page_count} page(s); latest reported total: '
            f'{diagnostics.total_count}.'
        )
        if audit_searches:
            _print_search_audit(query_diagnostics.candidates, plugins_by_id)
    for query_diagnostics in result.repository_search_diagnostics:
        diagnostics = query_diagnostics.search
        click.echo(
            f'GitHub repository search {diagnostics.query!r}: received '
            f'{diagnostics.fetched_count} result item(s) across '
            f'{diagnostics.page_count} page(s); latest reported total: '
            f'{diagnostics.total_count}; considered: '
            f'{query_diagnostics.considered_count}; accepted: '
            f'{query_diagnostics.accepted_count}; existing code candidates: '
            f'{query_diagnostics.existing_candidate_count}; excluded: '
            f'{query_diagnostics.excluded_count}; missing root pyproject: '
            f'{query_diagnostics.missing_pyproject_count}; invalid pyproject: '
            f'{query_diagnostics.invalid_pyproject_count}; no NOMAD signal: '
            f'{query_diagnostics.no_signal_count}; '
            f'candidate cap reached: {diagnostics.candidate_limit_reached}; '
            f'GitHub result window exceeded: {diagnostics.result_limit_reached}; '
            f'incomplete_results: {diagnostics.incomplete_results}.'
        )
        if diagnostics.candidate_limit_reached or diagnostics.result_limit_reached:
            click.echo(
                f'Warning: repository search {diagnostics.query!r} is bounded; '
                'these results are not an exhaustive repository inventory.',
                err=True,
            )
        if audit_searches:
            _print_search_audit(query_diagnostics.candidates, plugins_by_id)
    click.echo(f'Unique pyproject.toml candidates: {result.unique_candidate_count}.')
    click.echo(f'Wrote {len(result.plugins)} plugins to {output}')


def _print_search_audit(
    candidates: tuple[SearchCandidateAudit, ...],
    plugins_by_id: dict[str, Plugin],
) -> None:
    click.echo(f'  Candidate audit ({len(candidates)} result item(s)):')
    for candidate in sorted(
        candidates,
        key=lambda entry: (entry.outcome, entry.candidate.casefold()),
    ):
        plugin = plugins_by_id.get(candidate.candidate.casefold())
        final_status = (
            f'exported as {plugin.project_kind}' if plugin else 'not exported'
        )
        click.echo(f'    {candidate.outcome}: {candidate.candidate} ({final_status})')


@main.command()
@click.option(
    '--config',
    'config_path',
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help='Optional path to a catalogue configuration JSON file.',
)
def queries(config_path: Path | None) -> None:
    """Print the effective GitHub discovery configuration."""
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
