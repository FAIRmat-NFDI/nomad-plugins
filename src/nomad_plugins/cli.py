import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import click

from nomad_plugins.crawler import PluginData, find_plugins


def _plugin_sort_key(plugin: PluginData) -> tuple[str, str]:
    return (plugin.data.name.casefold(), str(plugin.data.repository))


def _plugin_reference_sort_key(reference: dict[str, Any]) -> tuple[str, str]:
    return (
        str(reference.get('name', '')).casefold(),
        str(reference.get('location', '')),
    )


def serialize_crawler_result(plugins: list[PluginData]) -> str:
    """Serialize the current crawler model to deterministic JSON."""
    data = []
    for plugin in sorted(plugins, key=_plugin_sort_key):
        dumped_plugin = plugin.model_dump(mode='json', exclude_none=True)
        plugin_data = dumped_plugin['data']
        plugin_dependencies = plugin_data.get('plugin_dependencies')
        if plugin_dependencies:
            plugin_data['plugin_dependencies'] = sorted(
                plugin_dependencies,
                key=_plugin_reference_sort_key,
            )
        data.append(dumped_plugin)
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n'


def write_crawler_result(plugins: list[PluginData], output: Path) -> None:
    """Write crawler JSON atomically, leaving no partial output on failure."""
    content = serialize_crawler_result(plugins)
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            'w',
            encoding='utf-8',
            dir=output.parent,
            prefix=f'.{output.name}.',
            suffix='.tmp',
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output)
    except Exception:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        raise


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
    help='Path where the crawler JSON result should be written.',
)
def crawl(github_token: str, output: Path) -> None:
    """Crawl plugin metadata and write the current crawler result as JSON."""
    try:
        plugins = asyncio.run(find_plugins(github_token))
        write_crawler_result(plugins, output)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f'Wrote {len(plugins)} plugins to {output}')


if __name__ == '__main__':
    main()
