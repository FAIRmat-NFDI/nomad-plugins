import json
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from nomad_plugins.catalogue import CatalogueSnapshot
from nomad_plugins.cli import main
from nomad_plugins.config import PRIMARY_CODE_SEARCH_QUERY
from nomad_plugins.crawler import CrawlResult, DeploymentInfo, Plugin, RepositoryStatus
from nomad_plugins.github import GitHubSearchDiagnostics, GitHubSearchIncompleteError
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
        owner_type='Organization',
        entrypoints=entrypoints or [],
        plugin_types=plugin_types,
        dependencies=dependencies or [],
        status=RepositoryStatus(
            archived=False,
            fork=False,
            stars=1,
            created_at='2024-01-01T00:00:00Z',
            last_pushed_at='2024-01-02T00:00:00Z',
            default_branch='main',
        ),
        deployment=DeploymentInfo(
            on_central=False,
            on_example_oasis=False,
        ),
        project_kind='plugin',
        registry_visible=True,
        metadata_source='pyproject.toml',
    )


def _crawl_result(plugins: list[Plugin]) -> CrawlResult:
    return CrawlResult(
        plugins=plugins,
        search_diagnostics=[
            GitHubSearchDiagnostics(
                query=PRIMARY_CODE_SEARCH_QUERY,
                total_count=len(plugins),
                fetched_count=len(plugins),
                page_count=1,
                incomplete_results=False,
                result_limit_reached=False,
            )
        ],
        unique_candidate_count=len(plugins),
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
        new=AsyncMock(return_value=_crawl_result(plugins)),
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
    find_plugins.assert_awaited_once()
    assert find_plugins.await_args.args == ('github-token',)
    assert find_plugins.await_args.kwargs['config'].github.code_search_queries == [
        PRIMARY_CODE_SEARCH_QUERY,
        'nomad-lab in:file filename:pyproject.toml',
    ]
    assert output.read_text(encoding='utf-8').endswith('\n')

    output_text = output.read_text(encoding='utf-8')
    CatalogueSnapshot.model_validate_json(output_text)
    data = json.loads(output_text)
    assert (
        f"GitHub code search '{PRIMARY_CODE_SEARCH_QUERY}': received "
        '2 result item(s) across 1 page(s); '
        'latest reported total: 2.'
    ) in result.output
    assert 'Unique pyproject.toml candidates: 2.' in result.output
    assert data['schemaVersion'] == '2.1.0'
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
        new=AsyncMock(return_value=_crawl_result([object()])),
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
            new=AsyncMock(return_value=_crawl_result([_plugin('alpha-plugin')])),
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


def test_incomplete_search_fails_without_writing_output(tmp_path):
    output = tmp_path / 'plugins.json'
    diagnostics = GitHubSearchDiagnostics(
        query='query',
        total_count=10,
        fetched_count=1,
        page_count=1,
        incomplete_results=True,
        result_limit_reached=False,
    )

    with patch(
        'nomad_plugins.cli.find_plugins',
        new=AsyncMock(side_effect=GitHubSearchIncompleteError(diagnostics)),
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
    assert 'GitHub code search is incomplete' in result.output
    assert "query 'query'" in result.output
    assert not output.exists()


def test_queries_prints_packaged_configuration_without_credentials():
    result = CliRunner().invoke(main, ['queries'])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        'github': {
            'codeSearchQueries': [
                PRIMARY_CODE_SEARCH_QUERY,
                'nomad-lab in:file filename:pyproject.toml',
            ],
            'codeSearchRequestDelaySeconds': 6.5,
        }
    }


def test_crawl_accepts_custom_configuration(tmp_path):
    output = tmp_path / 'plugins.json'
    config_path = tmp_path / 'config.json'
    config_path.write_text(
        json.dumps(
            {
                'github': {
                    'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY],
                    'codeSearchRequestDelaySeconds': 0,
                }
            }
        ),
        encoding='utf-8',
    )

    with patch(
        'nomad_plugins.cli.find_plugins',
        new=AsyncMock(return_value=_crawl_result([])),
    ) as find_plugins:
        result = CliRunner().invoke(
            main,
            [
                'crawl',
                '--config',
                str(config_path),
                '--github-token',
                'github-token',
                '--output',
                str(output),
            ],
        )

    assert result.exit_code == 0, result.output
    config = find_plugins.await_args.kwargs['config']
    assert config.github.code_search_queries == [PRIMARY_CODE_SEARCH_QUERY]
    assert config.github.code_search_request_delay_seconds == 0
