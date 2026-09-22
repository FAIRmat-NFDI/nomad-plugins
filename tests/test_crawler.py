import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from nomad_plugins.crawler import (
    DeploymentInfo,
    Plugin,
    RepositoryStatus,
    find_plugins,
)
from nomad_plugins.github import (
    GitHubRepositorySummary,
    GitHubSearchDiagnostics,
    GitHubSearchResult,
    GitHubSearchResultItem,
)


def test_find_plugins_keeps_multiple_projects_from_one_repository():
    plugins = [
        _plugin('github.com/example/monorepo#packages/parser'),
        _plugin('github.com/example/monorepo#packages/schema'),
    ]
    repository = GitHubRepositorySummary(
        full_name='example/monorepo',
        html_url='https://github.com/example/monorepo',
    )
    search_items = [
        GitHubSearchResultItem(
            path='packages/parser/pyproject.toml',
            url='https://api.github.test/contents/parser',
            repository=repository,
        ),
        GitHubSearchResultItem(
            path='packages/schema/pyproject.toml',
            url='https://api.github.test/contents/schema',
            repository=repository,
        ),
    ]
    diagnostics = GitHubSearchDiagnostics(
        query='query',
        total_count=2,
        fetched_count=2,
        page_count=1,
        incomplete_results=False,
        result_limit_reached=False,
    )
    github_client = SimpleNamespace(
        search_code=AsyncMock(
            return_value=GitHubSearchResult(
                items=search_items,
                diagnostics=diagnostics,
            )
        ),
        fetch_repository=AsyncMock(return_value=SimpleNamespace()),
    )

    with (
        patch(
            'nomad_plugins.crawler.fetch_nomad_deployment_requirements',
            new=AsyncMock(return_value=set()),
        ),
        patch(
            'nomad_plugins.crawler.get_plugin',
            new=AsyncMock(side_effect=plugins),
        ),
    ):
        result = asyncio.run(find_plugins('github-token', github_client=github_client))

    github_client.search_code.assert_awaited_once()
    github_client.fetch_repository.assert_awaited_once_with('example/monorepo')
    assert result.search_diagnostics == diagnostics
    assert {plugin.id for plugin in result.plugins} == {
        'github.com/example/monorepo#packages/parser',
        'github.com/example/monorepo#packages/schema',
    }


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
