import asyncio

import httpx
import pytest

from nomad_plugins.github import (
    GITHUB_CODE_SEARCH_LIMIT,
    GitHubAuthenticationError,
    GitHubClient,
    GitHubError,
    GitHubSearchIncompleteError,
)


def _search_item(index: int) -> dict:
    return {
        'path': f'packages/plugin-{index}/pyproject.toml',
        'url': f'https://api.github.test/contents/{index}',
        'repository': {
            'full_name': f'example/plugin-{index}',
            'html_url': f'https://github.com/example/plugin-{index}',
        },
    }


def test_code_search_uses_max_page_size_without_obsolete_sorting():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params['per_page'] == '100'
        assert 'sort' not in request.url.params
        assert 'order' not in request.url.params
        return httpx.Response(
            200,
            request=request,
            json={
                'total_count': 0,
                'incomplete_results': False,
                'items': [],
            },
        )

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.search_code('query')

    assert asyncio.run(run_search()).items == []


def test_code_search_paginates_and_reports_diagnostics():
    expected_count = 2
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        page = int(request.url.params['page'])
        items = [_search_item(page)]
        return httpx.Response(
            200,
            request=request,
            json={
                'total_count': expected_count,
                'incomplete_results': False,
                'items': items,
            },
        )

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.search_code('query', per_page=1)

    result = asyncio.run(run_search())

    assert [item.path for item in result.items] == [
        'packages/plugin-1/pyproject.toml',
        'packages/plugin-2/pyproject.toml',
    ]
    assert result.diagnostics.total_count == expected_count
    assert result.diagnostics.fetched_count == expected_count
    assert result.diagnostics.page_count == expected_count
    assert result.diagnostics.incomplete_results is False
    assert result.diagnostics.result_limit_reached is False
    assert requests[0].headers['Authorization'] == 'Bearer secret'
    assert requests[0].headers['X-GitHub-Api-Version'] == '2022-11-28'


def test_code_search_follows_a_growing_live_result_count():
    final_count = 3

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params['page'])
        total_count = 2 if page == 1 else final_count
        return httpx.Response(
            200,
            request=request,
            json={
                'total_count': total_count,
                'incomplete_results': False,
                'items': [_search_item(page)],
            },
        )

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.search_code('query', per_page=1)

    result = asyncio.run(run_search())

    assert result.diagnostics.total_count == final_count
    assert result.diagnostics.fetched_count == final_count
    assert result.diagnostics.page_count == final_count


def test_code_search_rejects_an_early_empty_page():
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params['page'])
        return httpx.Response(
            200,
            request=request,
            json={
                'total_count': 2,
                'incomplete_results': False,
                'items': [_search_item(1)] if page == 1 else [],
            },
        )

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.search_code('query', per_page=1)

    with pytest.raises(GitHubSearchIncompleteError, match='fetched 1 of 2'):
        asyncio.run(run_search())


@pytest.mark.parametrize(
    ('total_count', 'incomplete_results', 'message'),
    [
        (1, True, 'incomplete_results=true'),
        (
            GITHUB_CODE_SEARCH_LIMIT + 1,
            False,
            'exceeds GitHub',
        ),
    ],
)
def test_code_search_rejects_incomplete_or_capped_results(
    total_count: int,
    incomplete_results: bool,
    message: str,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            json={
                'total_count': total_count,
                'incomplete_results': incomplete_results,
                'items': [_search_item(1)],
            },
        )

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.search_code('query')

    with pytest.raises(GitHubSearchIncompleteError, match=message) as exc_info:
        asyncio.run(run_search())

    assert exc_info.value.diagnostics.total_count == total_count


@pytest.mark.parametrize('status_code', [429, 503])
def test_transient_github_failure_retries_within_bound(status_code: int):
    expected_attempts = 2
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                status_code,
                request=request,
                json={'message': 'busy'},
            )
        return httpx.Response(
            200,
            request=request,
            json={
                'total_count': 0,
                'incomplete_results': False,
                'items': [],
            },
        )

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient(
                'secret',
                client=http,
                request_retries=1,
                retry_backoff=0,
            ) as client:
                return await client.search_code('query')

    result = asyncio.run(run_search())

    assert result.items == []
    assert attempts == expected_attempts


def test_transport_failure_exhausts_bounded_retries():
    expected_attempts = 2
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout('timed out', request=request)

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient(
                'secret',
                client=http,
                request_retries=1,
                retry_backoff=0,
            ) as client:
                return await client.search_code('query')

    with pytest.raises(GitHubError, match='after 2 attempts'):
        asyncio.run(run_search())

    assert attempts == expected_attempts


def test_authentication_failure_is_actionable_and_not_retried():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(401, request=request, json={'message': 'Bad credentials'})

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('invalid', client=http) as client:
                return await client.search_code('query')

    with pytest.raises(GitHubAuthenticationError, match='GITHUB_TOKEN'):
        asyncio.run(run_search())

    assert attempts == 1


def test_malformed_github_response_is_actionable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, json={'items': []})

    async def run_search():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.search_code('query')

    with pytest.raises(GitHubError, match='invalid response'):
        asyncio.run(run_search())


def test_repository_status_and_fork_lineage_are_parsed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            json={
                'owner': {'login': 'example', 'type': 'Organization'},
                'archived': False,
                'fork': True,
                'stargazers_count': 5,
                'created_at': '2024-01-01T00:00:00Z',
                'pushed_at': '2024-01-02T00:00:00Z',
                'default_branch': 'main',
                'parent': {'html_url': 'https://github.com/upstream/parent'},
                'source': {'html_url': 'https://github.com/upstream/source'},
            },
        )

    async def fetch_repository():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('secret', client=http) as client:
                return await client.fetch_repository('example/plugin')

    repository = asyncio.run(fetch_repository())

    assert repository.owner.login == 'example'
    assert repository.owner.type == 'Organization'
    assert repository.default_branch == 'main'
    assert str(repository.parent.html_url) == 'https://github.com/upstream/parent'
    assert str(repository.source.html_url) == 'https://github.com/upstream/source'
