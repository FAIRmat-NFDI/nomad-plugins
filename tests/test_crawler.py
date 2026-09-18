import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from nomad_plugins.crawler import (
    DeploymentInfo,
    Plugin,
    RepositoryStatus,
    find_plugins,
)


def test_find_plugins_keeps_multiple_projects_from_one_repository():
    plugins = [
        _plugin('github.com/example/monorepo#packages/parser'),
        _plugin('github.com/example/monorepo#packages/schema'),
    ]
    search_items = [
        SimpleNamespace(repository=SimpleNamespace(full_name='example/monorepo')),
        SimpleNamespace(repository=SimpleNamespace(full_name='example/monorepo')),
    ]

    with (
        patch(
            'nomad_plugins.crawler.fetch_nomad_deployment_requirements',
            new=AsyncMock(return_value=set()),
        ),
        patch(
            'nomad_plugins.crawler.fetch_all_results_parallel_async',
            new=AsyncMock(return_value=search_items),
        ) as fetch_search_results,
        patch(
            'nomad_plugins.crawler.get_plugin',
            new=AsyncMock(side_effect=plugins),
        ),
    ):
        result = asyncio.run(find_plugins('github-token'))

    fetch_search_results.assert_awaited_once()
    assert {plugin.id for plugin in result} == {
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
