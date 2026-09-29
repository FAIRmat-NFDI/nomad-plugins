import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch

import pytest

from nomad_plugins.config import (
    PRIMARY_CODE_SEARCH_QUERY,
    CatalogueConfig,
    GitHubDiscoveryConfig,
)
from nomad_plugins.crawler import (
    DeploymentInfo,
    Plugin,
    RepositoryStatus,
    discover_code_search_candidates,
    find_plugins,
)
from nomad_plugins.github import (
    GitHubError,
    GitHubRepositorySummary,
    GitHubSearchDiagnostics,
    GitHubSearchResult,
    GitHubSearchResultItem,
)


def test_find_plugins_deduplicates_queries_and_keeps_nested_projects():
    expected_candidate_count = 2
    plugins = [
        _plugin('github.com/example/monorepo#packages/parser'),
        _plugin('github.com/example/monorepo#packages/schema'),
    ]
    repository = GitHubRepositorySummary(
        full_name='example/monorepo',
        html_url='https://github.com/example/monorepo',
    )
    parser_item = GitHubSearchResultItem(
        path='packages/parser/pyproject.toml',
        url='https://api.github.test/contents/parser-primary',
        repository=repository,
    )
    duplicate_parser_item = parser_item.model_copy(
        update={'url': 'https://api.github.test/contents/parser-secondary'}
    )
    schema_item = GitHubSearchResultItem(
        path='packages/schema/pyproject.toml',
        url='https://api.github.test/contents/schema',
        repository=repository,
    )
    secondary_query = 'nomad-lab in:file filename:pyproject.toml'
    primary_diagnostics = GitHubSearchDiagnostics(
        query=PRIMARY_CODE_SEARCH_QUERY,
        total_count=1,
        fetched_count=1,
        page_count=1,
        incomplete_results=False,
        result_limit_reached=False,
    )
    secondary_diagnostics = GitHubSearchDiagnostics(
        query=secondary_query,
        total_count=2,
        fetched_count=2,
        page_count=1,
        incomplete_results=False,
        result_limit_reached=False,
    )
    github_client = SimpleNamespace(
        search_code=AsyncMock(
            side_effect=[
                GitHubSearchResult(
                    items=[parser_item],
                    diagnostics=primary_diagnostics,
                ),
                GitHubSearchResult(
                    items=[duplicate_parser_item, schema_item],
                    diagnostics=secondary_diagnostics,
                ),
            ]
        ),
        fetch_repository=AsyncMock(return_value=SimpleNamespace()),
    )
    config = CatalogueConfig(
        github=GitHubDiscoveryConfig(
            code_search_queries=[PRIMARY_CODE_SEARCH_QUERY, secondary_query],
            code_search_request_delay_seconds=1,
        )
    )

    with (
        patch(
            'nomad_plugins.crawler.fetch_nomad_deployment_requirements',
            new=AsyncMock(return_value=set()),
        ),
        patch(
            'nomad_plugins.crawler.get_plugin',
            new=AsyncMock(side_effect=plugins),
        ) as get_plugin,
    ):
        result = asyncio.run(
            find_plugins(
                'github-token',
                config=config,
                github_client=github_client,
            )
        )

    assert github_client.search_code.await_args_list == [
        call(PRIMARY_CODE_SEARCH_QUERY, request_delay_seconds=1.0),
        call(secondary_query, request_delay_seconds=1.0),
    ]
    github_client.fetch_repository.assert_awaited_once_with('example/monorepo')
    assert {
        str(awaited.kwargs['item'].url) for awaited in get_plugin.await_args_list
    } == {
        'https://api.github.test/contents/parser-primary',
        'https://api.github.test/contents/schema',
    }
    assert result.search_diagnostics == [
        primary_diagnostics,
        secondary_diagnostics,
    ]
    assert result.unique_candidate_count == expected_candidate_count
    assert {plugin.id for plugin in result.plugins} == {
        'github.com/example/monorepo#packages/parser',
        'github.com/example/monorepo#packages/schema',
    }


def test_code_search_failure_identifies_active_query_and_preserves_cause():
    secondary_query = 'nomad-lab in:file filename:pyproject.toml'
    primary_diagnostics = GitHubSearchDiagnostics(
        query=PRIMARY_CODE_SEARCH_QUERY,
        total_count=0,
        fetched_count=0,
        page_count=1,
        incomplete_results=False,
        result_limit_reached=False,
    )
    original_error = GitHubError('GitHub API request failed with HTTP 503')
    github_client = SimpleNamespace(
        search_code=AsyncMock(
            side_effect=[
                GitHubSearchResult(items=[], diagnostics=primary_diagnostics),
                original_error,
            ]
        )
    )
    config = CatalogueConfig(
        github=GitHubDiscoveryConfig(
            code_search_queries=[PRIMARY_CODE_SEARCH_QUERY, secondary_query],
            code_search_request_delay_seconds=1,
        )
    )

    with pytest.raises(GitHubError) as exc_info:
        asyncio.run(discover_code_search_candidates(github_client, config))

    assert f'query {secondary_query!r}' in str(exc_info.value)
    assert exc_info.value.__cause__ is original_error
    assert github_client.search_code.await_args_list == [
        call(PRIMARY_CODE_SEARCH_QUERY, request_delay_seconds=1.0),
        call(secondary_query, request_delay_seconds=1.0),
    ]


def _plugin(plugin_id: str) -> Plugin:
    return Plugin(
        id=plugin_id,
        name='monorepo-plugin',
        repository_url='https://github.com/example/monorepo',
        owner='example',
        status=RepositoryStatus(archived=False, fork=False, stars=1),
        deployment=DeploymentInfo(
            on_central=False,
            on_example_oasis=False,
        ),
        project_kind='plugin',
        registry_visible=True,
        metadata_source='pyproject.toml',
    )
