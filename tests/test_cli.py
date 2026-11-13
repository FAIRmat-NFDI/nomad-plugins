import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from nomad_plugins.catalogue import (
    CatalogueSnapshot,
    build_catalogue_snapshot,
    write_catalogue_snapshot,
)
from nomad_plugins.cli import main
from nomad_plugins.config import PRIMARY_CODE_SEARCH_QUERY, load_catalogue_config
from nomad_plugins.crawler import (
    CodeQueryDiagnostics,
    CrawlResult,
    DeploymentInfo,
    Plugin,
    RepositoryQueryDiagnostics,
    RepositoryStatus,
    SearchCandidateAudit,
)
from nomad_plugins.github import GitHubSearchDiagnostics, GitHubSearchIncompleteError
from nomad_plugins.pyproject import PluginEntryPoint

SCHEMA_PATH = Path(__file__).resolve().parents[1] / 'plugin-catalogue.schema.json'


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
            CodeQueryDiagnostics(
                search=GitHubSearchDiagnostics(
                    query=PRIMARY_CODE_SEARCH_QUERY,
                    total_count=len(plugins),
                    fetched_count=len(plugins),
                    page_count=1,
                    incomplete_results=False,
                    result_limit_reached=False,
                )
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
    assert data['schemaVersion'] == '2.2.0'
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
    assert json.loads(result.output) == load_catalogue_config().model_dump(
        mode='json', by_alias=True
    )
    assert 'repositorySearchQueries' in result.output


def test_validate_accepts_generated_snapshot_without_credentials(tmp_path):
    output = tmp_path / 'plugins.json'
    write_catalogue_snapshot(build_catalogue_snapshot([_plugin('alpha')]), output)

    result = CliRunner().invoke(
        main,
        ['validate', '--input', str(output), '--schema', str(SCHEMA_PATH)],
    )

    assert result.exit_code == 0, result.output
    assert (
        f'Validated catalogue snapshot with 1 record(s) in {output}.' in result.output
    )


def test_validate_rejects_snapshot_model_error(tmp_path):
    output = tmp_path / 'plugins.json'
    data = build_catalogue_snapshot([_plugin('alpha')]).model_dump(
        mode='json', by_alias=True, exclude_none=True
    )
    data['sourceSummary']['pluginCount'] = 2
    output.write_text(json.dumps(data), encoding='utf-8')

    result = CliRunner().invoke(
        main,
        ['validate', '--input', str(output), '--schema', str(SCHEMA_PATH)],
    )

    assert result.exit_code != 0
    assert 'sourceSummary.pluginCount' in result.output


def test_validate_rejects_malformed_json(tmp_path):
    output = tmp_path / 'plugins.json'
    output.write_text('{', encoding='utf-8')

    result = CliRunner().invoke(
        main,
        ['validate', '--input', str(output), '--schema', str(SCHEMA_PATH)],
    )

    assert result.exit_code != 0
    assert 'Expecting property name' in result.output


def test_validate_rejects_json_schema_error_after_model_coercion(tmp_path):
    output = tmp_path / 'plugins.json'
    data = build_catalogue_snapshot([_plugin('alpha')]).model_dump(
        mode='json', by_alias=True, exclude_none=True
    )
    data['sourceSummary']['pluginCount'] = '1'
    output.write_text(json.dumps(data), encoding='utf-8')

    result = CliRunner().invoke(
        main,
        ['validate', '--input', str(output), '--schema', str(SCHEMA_PATH)],
    )

    assert result.exit_code != 0
    assert 'JSON Schema validation failed at sourceSummary/pluginCount' in result.output


def test_validate_rejects_outdated_schema(tmp_path):
    output = tmp_path / 'plugins.json'
    schema = tmp_path / 'schema.json'
    write_catalogue_snapshot(build_catalogue_snapshot([]), output)
    schema.write_text('{}', encoding='utf-8')

    result = CliRunner().invoke(
        main,
        ['validate', '--input', str(output), '--schema', str(schema)],
    )

    assert result.exit_code != 0
    assert 'out of date with the model' in result.output


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


def test_crawl_reports_bounded_repository_search_and_probe_outcomes(tmp_path):
    crawl_result = _crawl_result([])
    crawl_result.repository_search_diagnostics.append(
        RepositoryQueryDiagnostics(
            search=GitHubSearchDiagnostics(
                query='topic:north-tool',
                total_count=2000,
                fetched_count=100,
                page_count=1,
                incomplete_results=False,
                result_limit_reached=True,
                search_type='repository',
                candidate_limit_reached=True,
            ),
            considered_count=5,
            accepted_count=1,
            existing_candidate_count=1,
            excluded_count=0,
            missing_pyproject_count=1,
            invalid_pyproject_count=1,
            no_signal_count=1,
        )
    )
    with patch(
        'nomad_plugins.cli.find_plugins', new=AsyncMock(return_value=crawl_result)
    ):
        result = CliRunner().invoke(
            main,
            [
                'crawl',
                '--github-token',
                'token',
                '--output',
                str(tmp_path / 'out.json'),
            ],
        )
    assert result.exit_code == 0, result.output
    assert "GitHub repository search 'topic:north-tool'" in result.output
    assert 'latest reported total: 2000' in result.output
    assert 'accepted: 1' in result.output
    assert 'existing code candidates: 1' in result.output
    assert 'missing root pyproject: 1' in result.output
    assert 'invalid pyproject: 1' in result.output
    assert 'no NOMAD signal: 1' in result.output
    assert 'candidate cap reached: True' in result.output
    assert 'GitHub result window exceeded: True' in result.output
    assert 'incomplete_results: False' in result.output
    assert 'not an exhaustive repository inventory' in result.stderr


def test_crawl_search_audit_identifies_candidates_and_final_kinds(tmp_path):
    output = tmp_path / 'out.json'
    plugin = _plugin('plugin')
    dependent = _plugin('dependent').model_copy(
        update={'project_kind': 'nomad_dependent_package'}
    )
    crawl_result = _crawl_result([plugin, dependent])
    crawl_result.search_diagnostics[0] = CodeQueryDiagnostics(
        search=crawl_result.search_diagnostics[0].search,
        candidates=(
            SearchCandidateAudit('github.com/example/plugin', 'new_candidate'),
            SearchCandidateAudit('github.com/example/missing', 'new_candidate'),
        ),
    )
    crawl_result.repository_search_diagnostics.append(
        RepositoryQueryDiagnostics(
            search=GitHubSearchDiagnostics(
                query='topic:nomad-plugin',
                total_count=3,
                fetched_count=3,
                page_count=1,
                incomplete_results=False,
                result_limit_reached=False,
                search_type='repository',
            ),
            considered_count=3,
            accepted_count=1,
            existing_candidate_count=1,
            excluded_count=0,
            missing_pyproject_count=1,
            invalid_pyproject_count=0,
            no_signal_count=0,
            candidates=(
                SearchCandidateAudit('github.com/example/dependent', 'accepted_new'),
                SearchCandidateAudit(
                    'github.com/example/plugin', 'existing_code_candidate'
                ),
                SearchCandidateAudit('github.com/example/missing', 'missing'),
            ),
        )
    )
    with patch(
        'nomad_plugins.cli.find_plugins', new=AsyncMock(return_value=crawl_result)
    ):
        result = CliRunner().invoke(
            main,
            [
                'crawl',
                '--github-token',
                'token',
                '--audit-searches',
                '--output',
                str(output),
            ],
        )

    assert result.exit_code == 0, result.output
    assert (
        'new_candidate: github.com/example/plugin (exported as plugin)' in result.output
    )
    assert 'new_candidate: github.com/example/missing (not exported)' in result.output
    assert (
        'accepted_new: github.com/example/dependent '
        '(exported as nomad_dependent_package)'
    ) in result.output
    assert (
        'existing_code_candidate: github.com/example/plugin (exported as plugin)'
    ) in result.output
    assert 'missing: github.com/example/missing (not exported)' in result.output
    assert 'Candidate audit (' not in output.read_text(encoding='utf-8')

    with patch(
        'nomad_plugins.cli.find_plugins', new=AsyncMock(return_value=crawl_result)
    ):
        ordinary_result = CliRunner().invoke(
            main,
            ['crawl', '--github-token', 'token', '--output', str(output)],
        )
    assert ordinary_result.exit_code == 0, ordinary_result.output
    assert 'Candidate audit (' not in ordinary_result.output
