import asyncio
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from click.testing import CliRunner

from nomad_plugins.cli import main
from nomad_plugins.config import (
    PRIMARY_CODE_SEARCH_QUERY,
    CatalogueConfig,
    GitHubDiscoveryConfig,
)
from nomad_plugins.crawler import (
    Plugin,
    discover_repository_search_candidates,
    find_plugins,
    probe_repository_project,
)
from nomad_plugins.github import (
    GitHubClient,
    GitHubError,
    GitHubRepositorySearchResult,
    GitHubSearchDiagnostics,
)
from nomad_plugins.pyproject import parse_pyproject

NORTH_TOOLS = (
    'apmtools',
    'emtools',
    'fiji',
    'gwyddion',
    'jupyter',
    'mpes-igor',
    'nionswift',
    'pyiron',
    'vesta',
    'voila',
    'xps',
)
REPOSITORY_QUERIES = ['topic:north-tool', 'nomad-semantic in:name,description']


def _config():
    return CatalogueConfig(
        github=GitHubDiscoveryConfig(
            code_search_queries=[PRIMARY_CODE_SEARCH_QUERY],
            code_search_request_delay_seconds=0,
            repository_search_queries=REPOSITORY_QUERIES,
            repository_search_request_delay_seconds=0,
        )
    )


def _repository(name):
    return {'full_name': name, 'html_url': f'https://github.com/{name}'}


def _search_response(items):
    return httpx.Response(
        200,
        json={'total_count': len(items), 'incomplete_results': False, 'items': items},
    )


def _pyproject(name, entrypoint='parser'):
    return (
        f'[project]\nname = "{name}"\n'
        f'[project.entry-points."nomad.plugin"]\n'
        f'{entrypoint} = "example.{entrypoint}:entry_point"\n'
    )


def _run_crawl(handler):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient(
                'token',
                client=http,
                base_url='https://api.github.test',
                request_retries=0,
            ) as client:
                return await find_plugins(
                    'token', config=_config(), github_client=client
                )

    with (
        patch(
            'nomad_plugins.crawler.fetch_nomad_deployment_requirements',
            new=AsyncMock(return_value=set()),
        ),
        patch(
            'nomad_plugins.crawler.package_exists_on_pypi',
            new=AsyncMock(return_value=False),
        ),
    ):
        return asyncio.run(run())


def test_repository_and_code_overlap_reuses_roots_and_keeps_nested_projects(capsys):
    requests = Counter()
    repository_names = [
        'EXAMPLE/MONOREPO',
        'example/new',
        'example/missing',
        'example/invalid',
        'example/unrelated',
        'example/empty',
        'example/fork',
        'example/archived',
        'FAIRmat-NFDI/cookiecutter-nomad-plugin',
    ]
    contents = {
        'monorepo/pyproject.toml': _pyproject('monorepo'),
        'monorepo/packages/nested/pyproject.toml': _pyproject('nested'),
        'new/pyproject.toml': _pyproject('new'),
        'invalid/pyproject.toml': '[project',
        'unrelated/pyproject.toml': (
            '[project]\nname = "unrelated"\ndescription = "nomad.plugin nomad-lab"'
        ),
        'empty/pyproject.toml': (
            '[project]\nname = "empty"\n[project.entry-points."nomad.plugin"]'
        ),
        'fork/pyproject.toml': _pyproject('fork'),
        'archived/pyproject.toml': _pyproject('archived'),
    }

    def handler(request):
        path = request.url.path
        requests[path] += 1
        if path == '/search/code':
            return _search_response(
                [
                    {
                        'path': file_path,
                        'url': f'https://api.github.test/repos/example/monorepo/contents/{file_path}',
                        'repository': _repository('example/monorepo'),
                    }
                    for file_path in [
                        'pyproject.toml',
                        'packages/nested/pyproject.toml',
                    ]
                ]
            )
        if path == '/search/repositories':
            return _search_response([_repository(name) for name in repository_names])
        if '/contents/' in path:
            repository, file_path = path.removeprefix('/repos/example/').split(
                '/contents/'
            )
            content = contents.get(f'{repository}/{file_path}')
            return (
                httpx.Response(404)
                if content is None
                else httpx.Response(200, text=content)
            )
        repository = path.rsplit('/', 1)[-1]
        return httpx.Response(
            200,
            json={
                'owner': {'login': 'example', 'type': 'Organization'},
                'archived': repository == 'archived',
                'fork': repository == 'fork',
                'stargazers_count': 0,
                'default_branch': 'custom-branch',
            },
        )

    with patch('nomad_plugins.crawler.parse_pyproject', wraps=parse_pyproject) as parse:
        result = _run_crawl(handler)

    assert [plugin.id for plugin in result.plugins] == [
        'github.com/example/archived',
        'github.com/example/empty',
        'github.com/example/fork',
        'github.com/example/monorepo',
        'github.com/example/monorepo#packages/nested',
        'github.com/example/new',
    ]
    assert result.unique_candidate_count == len(result.plugins)
    assert all(isinstance(plugin, Plugin) for plugin in result.plugins)
    assert all(
        count == 1 for path, count in requests.items() if path.startswith('/repos/')
    )
    assert parse.call_count == len(contents)
    assert result.plugins[0].registry_visible is False
    assert result.plugins[2].registry_visible is False
    assert result.plugins[1].plugin_types is None
    assert result.plugins[1].project_kind == 'ecosystem_package'
    for diagnostics in result.repository_search_diagnostics:
        assert diagnostics.accepted_count == 4  # noqa: PLR2004
        assert diagnostics.existing_candidate_count == 1
        assert diagnostics.missing_pyproject_count == 1
        assert diagnostics.invalid_pyproject_count == 1
        assert diagnostics.no_signal_count == 1
        assert diagnostics.excluded_count == 1
    first, second = result.repository_search_diagnostics
    assert {(item.candidate, item.outcome) for item in first.candidates} >= {
        ('github.com/example/new', 'accepted_new'),
        ('github.com/example/monorepo', 'existing_code_candidate'),
        ('github.com/example/missing', 'missing'),
        ('github.com/example/invalid', 'invalid'),
        ('github.com/example/unrelated', 'no_signal'),
    }
    assert {
        item.candidate
        for item in second.candidates
        if item.outcome == 'accepted_overlap'
    } == {
        'github.com/example/new',
        'github.com/example/empty',
        'github.com/example/fork',
        'github.com/example/archived',
    }
    assert 'Invalid root pyproject.toml in example/invalid' in capsys.readouterr().err


def test_repository_search_discovers_reviewed_north_tools_and_semantic_service():
    projects = {
        f'FAIRmat-NFDI/nomad-north-{tool}': _pyproject(
            f'nomad-north-{tool}', 'north_tools'
        )
        for tool in NORTH_TOOLS
    }
    projects['FAIRmat-NFDI/nomad-semantic-web-service'] = _pyproject(
        'nomad-semantic-web-service', 'api'
    )

    def handler(request):
        path = request.url.path
        if path == '/search/code':
            return _search_response([])
        if path == '/search/repositories':
            query = request.url.params['q']
            return _search_response(
                [
                    _repository(name)
                    for name in projects
                    if ('north-' in name) == (query == 'topic:north-tool')
                ]
            )
        if '/contents/' in path:
            name = path.removeprefix('/repos/').split('/contents/')[0]
            return httpx.Response(200, text=projects[name])
        return httpx.Response(
            200,
            json={
                'owner': {'login': 'FAIRmat-NFDI', 'type': 'Organization'},
                'archived': False,
                'fork': False,
                'stargazers_count': 1,
            },
        )

    result = _run_crawl(handler)

    assert {plugin.id for plugin in result.plugins} == {
        f'github.com/{name.casefold()}' for name in projects
    }
    assert all(plugin.registry_visible for plugin in result.plugins)
    assert all(
        plugin.plugin_types == ['north_tool']
        for plugin in result.plugins
        if 'north-' in plugin.name
    )


def test_second_repository_query_failure_retains_query_and_original_exception():
    original_error = GitHubError('GitHub API request failed with HTTP 503')
    github_client = SimpleNamespace(
        search_repositories=AsyncMock(
            side_effect=[
                GitHubRepositorySearchResult(
                    items=[],
                    diagnostics=GitHubSearchDiagnostics(
                        query=REPOSITORY_QUERIES[0],
                        total_count=0,
                        fetched_count=0,
                        page_count=1,
                        incomplete_results=False,
                        result_limit_reached=False,
                        search_type='repository',
                    ),
                ),
                original_error,
            ]
        )
    )
    with pytest.raises(GitHubError) as exc_info:
        asyncio.run(discover_repository_search_candidates(github_client, _config(), []))
    assert repr(REPOSITORY_QUERIES[1]) in str(exc_info.value)
    assert exc_info.value.__cause__ is original_error


def test_root_request_failure_retains_repository_and_original_exception():
    original_error = GitHubError('GitHub API request failed with HTTP 403')
    github_client = SimpleNamespace(
        fetch_root_pyproject=AsyncMock(side_effect=original_error)
    )
    with pytest.raises(GitHubError) as exc_info:
        asyncio.run(probe_repository_project(github_client, 'example/private'))
    assert "repository 'example/private'" in str(exc_info.value)
    assert exc_info.value.__cause__ is original_error


@pytest.mark.parametrize('failure', ['http', 'transport', 'incomplete', 'probe'])
def test_repository_failures_preserve_existing_cli_output(tmp_path, failure):
    output = tmp_path / 'catalogue.json'
    output.write_text('previous snapshot', encoding='utf-8')

    def handler(request):
        if request.url.path == '/search/code':
            return _search_response([])
        if request.url.path == '/search/repositories':
            if request.url.params['q'] == 'topic:nomad-plugin':
                return _search_response([])
            if failure == 'http':
                return httpx.Response(503)
            if failure == 'transport':
                raise httpx.ReadTimeout('timed out', request=request)
            if failure == 'incomplete':
                return httpx.Response(
                    200,
                    json={'total_count': 1, 'incomplete_results': True, 'items': []},
                )
            return _search_response([_repository('example/plugin')])
        return httpx.Response(403)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = GitHubClient('token', client=http, request_retries=0)
    try:
        with (
            patch('nomad_plugins.crawler.GitHubClient', return_value=client),
            patch('nomad_plugins.github.asyncio.sleep', new=AsyncMock()),
            patch(
                'nomad_plugins.crawler.fetch_nomad_deployment_requirements',
                new=AsyncMock(return_value=set()),
            ),
        ):
            result = CliRunner().invoke(
                main, ['crawl', '--github-token', 'token', '--output', str(output)]
            )
    finally:
        asyncio.run(http.aclose())

    assert result.exit_code != 0
    context = (
        "repository 'example/plugin'"
        if failure == 'probe'
        else "query 'topic:north-tool'"
    )
    assert context in result.output
    assert output.read_text(encoding='utf-8') == 'previous snapshot'
    assert list(tmp_path.iterdir()) == [output]
