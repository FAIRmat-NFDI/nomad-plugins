import json
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from nomad_plugins.catalogue import CatalogueSnapshot
from nomad_plugins.cli import main
from nomad_plugins.crawler import DeploymentInfo, Plugin, RepositoryStatus
from nomad_plugins.pyproject import PluginEntryPoint


def _plugin(
    name: str,
    *,
    entrypoints: list[PluginEntryPoint] | None = None,
    plugin_types: list[str] | None = None,
    dependencies: list[str] | None = None,
) -> Plugin:
    return Plugin(
        id=f'github.com/example/{name}',
        name=name,
        repository_url=f'https://github.com/example/{name}',
        owner='example',
        entrypoints=entrypoints or [],
        plugin_types=plugin_types,
        dependencies=dependencies or [],
        status=RepositoryStatus(
            archived=False,
            fork=False,
            stars=1,
            created_at='2024-01-01T00:00:00Z',
            last_pushed_at='2024-01-02T00:00:00Z',
        ),
        deployment=DeploymentInfo(
            on_central=False,
            on_example_oasis=False,
        ),
        project_kind='plugin',
        registry_visible=True,
        metadata_source='pyproject.toml',
    )


def test_crawl_writes_deterministic_catalogue_snapshot_json(tmp_path):
    output = tmp_path / 'plugins.json'
    plugins = [
        _plugin(
            'zeta-plugin',
            dependencies=['zeta-dependency', 'alpha-dependency'],
            entrypoints=[
                PluginEntryPoint(
                    name='zeta.schema',
                    module='zeta.schema:entry',
                    type='schema',
                )
            ],
            plugin_types=['schema'],
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

    output_text = output.read_text(encoding='utf-8')
    CatalogueSnapshot.model_validate_json(output_text)
    data = json.loads(output_text)
    assert data['schemaVersion'] == '2.0.0'
    assert data['sourceSummary'] == {
        'pluginCount': 2,
        'projectKindCounts': {'plugin': 2},
        'registryVisibleCount': 2,
        'warningCount': 0,
    }
    assert [plugin['name'] for plugin in data['plugins']] == [
        'alpha-plugin',
        'zeta-plugin',
    ]
    assert data['plugins'][0]['pluginTypes'] is None
    assert data['plugins'][1]['dependencies'] == [
        'alpha-dependency',
        'zeta-dependency',
    ]
    assert data['plugins'][1]['entrypoints'][0]['type'] == 'schema'


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
        patch(
            'nomad_plugins.catalogue.json.dumps',
            side_effect=TypeError('cannot encode'),
        ),
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
