import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from nomad_plugins.github import (
    GITHUB_REPOSITORY_SEARCH_LIMIT,
    GitHubAuthenticationError,
    GitHubClient,
    GitHubError,
    GitHubSearchIncompleteError,
)


def _repository(index):
    return {
        'full_name': f'example/plugin-{index}',
        'html_url': f'https://github.com/example/plugin-{index}',
    }


def _run_search(handler, **kwargs):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('token', client=http, request_retries=0) as client:
                return await client.search_repositories('query', **kwargs)

    return asyncio.run(run())


def test_repository_search_paginates_with_fixed_page_size_and_bounds_candidates():
    requests = []

    def handler(request):
        requests.append(request)
        page = int(request.url.params['page'])
        return httpx.Response(
            200,
            json={
                'total_count': 5,
                'incomplete_results': False,
                'items': [_repository(2 * page - 1), _repository(2 * page)],
            },
        )

    result = _run_search(handler, per_page=2, candidate_limit=3)

    assert [item.full_name for item in result.items] == [
        'example/plugin-1',
        'example/plugin-2',
        'example/plugin-3',
    ]
    assert [request.url.params['page'] for request in requests] == ['1', '2']
    assert all(request.url.params['per_page'] == '2' for request in requests)
    assert all(request.url.params['q'] == 'query' for request in requests)
    assert all(request.url.path == '/search/repositories' for request in requests)
    assert result.diagnostics.fetched_count == 4  # noqa: PLR2004
    assert result.diagnostics.total_count == 5  # noqa: PLR2004
    assert result.diagnostics.candidate_limit_reached is True
    assert result.diagnostics.result_limit_reached is False
    assert result.diagnostics.search_type == 'repository'


@pytest.mark.parametrize('total_count', [1, 2000])
def test_repository_window_and_local_limit_are_reported_separately(total_count):
    result = _run_search(
        lambda request: httpx.Response(
            200,
            json={
                'total_count': total_count,
                'incomplete_results': False,
                'items': [_repository(1)],
            },
        ),
        candidate_limit=1,
    )
    assert len(result.items) == 1
    assert result.diagnostics.candidate_limit_reached is (total_count > 1)
    assert result.diagnostics.result_limit_reached is (
        total_count > GITHUB_REPOSITORY_SEARCH_LIMIT
    )


@pytest.mark.parametrize('incomplete_results', [False, True])
def test_repository_search_rejects_unexpectedly_empty_or_api_incomplete_results(
    incomplete_results,
):
    with pytest.raises(GitHubSearchIncompleteError) as exc_info:
        _run_search(
            lambda request: httpx.Response(
                200,
                json={
                    'total_count': 5,
                    'incomplete_results': incomplete_results,
                    'items': [_repository(1)] if incomplete_results else [],
                },
            ),
            candidate_limit=3,
        )
    assert "repository search is incomplete for query 'query'" in str(exc_info.value)
    assert exc_info.value.diagnostics.incomplete_results is incomplete_results


def test_repository_pacing_applies_across_pages_and_queries_independently_of_code():
    async def run():
        def handler(request):
            is_repository = request.url.path == '/search/repositories'
            return httpx.Response(
                200,
                json={
                    'total_count': 2 if is_repository else 0,
                    'incomplete_results': False,
                    'items': [_repository(request.url.params['page'])]
                    if is_repository
                    else [],
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('token', client=http) as client:
                await client.search_code('code', request_delay_seconds=6.5)
                await client.search_repositories(
                    'first', candidate_limit=2, per_page=1, request_delay_seconds=2.1
                )
                await client.search_repositories(
                    'second', candidate_limit=1, request_delay_seconds=2.1
                )

    with patch('nomad_plugins.github.asyncio.sleep', new=AsyncMock()) as sleep:
        asyncio.run(run())
    assert [awaited.args for awaited in sleep.await_args_list] == [(2.1,), (2.1,)]


@pytest.mark.parametrize('status_code', [200, 404, 401, 403, 500])
def test_root_probe_treats_only_not_found_as_a_normal_exclusion(status_code):
    async def run():
        def handler(request):
            assert request.url.path == '/repos/example/plugin/contents/pyproject.toml'
            assert not request.url.params  # Default branch; no guessed branch name.
            return httpx.Response(status_code, text='[project]\nname = "plugin"')

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('token', client=http, request_retries=0) as client:
                return await client.fetch_root_pyproject('example/plugin')

    if status_code == 200:  # noqa: PLR2004
        assert asyncio.run(run()) == '[project]\nname = "plugin"'
    elif status_code == 404:  # noqa: PLR2004
        assert asyncio.run(run()) is None
    else:
        error = (
            GitHubAuthenticationError
            if status_code == httpx.codes.UNAUTHORIZED
            else GitHubError
        )
        with pytest.raises(error):
            asyncio.run(run())


def test_root_probe_does_not_suppress_transport_errors():
    async def run():
        def handler(request):
            raise httpx.ReadTimeout('timed out', request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient('token', client=http, request_retries=0) as client:
                return await client.fetch_root_pyproject('example/plugin')

    with pytest.raises(GitHubError, match='after 1 attempts') as exc_info:
        asyncio.run(run())
    assert isinstance(exc_info.value.__cause__, httpx.ReadTimeout)
