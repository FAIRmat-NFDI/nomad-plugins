import json
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from nomad_plugins.cli import main
from nomad_plugins.crawler import NomadPlugin, Plugin, PluginReference


def _plugin(
    name: str,
    *,
    plugin_dependencies: list[PluginReference] | None = None,
    plugin_entry_points: list[NomadPlugin] | None = None,
) -> Plugin:
    return Plugin(
        repository=f'https://github.com/example/{name}',
        stars=1,
        created='2024-01-01T00:00:00Z',
        last_updated='2024-01-02T00:00:00Z',
        owner='example',
        name=name,
        description=None,
        plugin_dependencies=plugin_dependencies or [],
        authors=[],
        maintainers=[],
        on_central=False,
        on_example_oasis=False,
        on_pypi=True,
        plugin_entry_points=plugin_entry_points or [],
    )


def test_crawl_writes_deterministic_current_model_json(tmp_path):
    output = tmp_path / 'plugins.json'
    plugins = [
        _plugin(
            'zeta-plugin',
            plugin_dependencies=[
                PluginReference(
                    name='zeta-dependency', location='https://example.test/z'
                ),
                PluginReference(
                    name='alpha-dependency', location='https://example.test/a'
                ),
            ],
            plugin_entry_points=[
                NomadPlugin(name='zeta.schema', module='zeta.schema:entry', type=None)
            ],
        ),
        _plugin('alpha-plugin'),
    ]

    with patch(
        'nomad_plugins.cli.find_plugins',
        new=AsyncMock(return_value=plugins),
    ) as find_plugins:
        result = CliRunner().invoke(
            main,
            [
                'crawl',
                '--github-token',
                'github-token',
                '--output',
                str(output),
            ],
        )

    assert result.exit_code == 0, result.output
    find_plugins.assert_awaited_once_with('github-token')
    assert output.read_text(encoding='utf-8').endswith('\n')

    data = json.loads(output.read_text(encoding='utf-8'))
    assert [plugin['name'] for plugin in data] == [
        'alpha-plugin',
        'zeta-plugin',
    ]
    assert [dependency['name'] for dependency in data[1]['plugin_dependencies']] == [
        'alpha-dependency',
        'zeta-dependency',
    ]
    assert 'type' not in data[1]['plugin_entry_points'][0]


def test_crawl_fails_without_replacing_existing_output_for_invalid_results(tmp_path):
    output = tmp_path / 'plugins.json'
    output.write_text('existing output', encoding='utf-8')

    with patch(
        'nomad_plugins.cli.find_plugins',
        new=AsyncMock(return_value=[object()]),
    ):
        result = CliRunner().invoke(
            main,
            [
                'crawl',
                '--github-token',
                'github-token',
                '--output',
                str(output),
            ],
        )

    assert result.exit_code != 0
    assert output.read_text(encoding='utf-8') == 'existing output'
    assert list(tmp_path.glob('*.tmp')) == []


def test_crawl_preserves_existing_output_for_serialization_error(tmp_path):
    output = tmp_path / 'plugins.json'
    output.write_text('existing output', encoding='utf-8')

    with (
        patch(
            'nomad_plugins.cli.find_plugins',
            new=AsyncMock(return_value=[_plugin('alpha-plugin')]),
        ),
        patch('nomad_plugins.cli.json.dumps', side_effect=TypeError('cannot encode')),
    ):
        result = CliRunner().invoke(
            main,
            [
                'crawl',
                '--github-token',
                'github-token',
                '--output',
                str(output),
            ],
        )

    assert result.exit_code != 0
    assert output.read_text(encoding='utf-8') == 'existing output'
    assert list(tmp_path.glob('*.tmp')) == []
