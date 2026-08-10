from __future__ import annotations

import json
import os
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request

from nomad_plugins.github import (
    GitHubClient,
    build_code_search_url,
    build_repository_search_url,
    github_token_from_environment,
    parse_code_search_response,
    parse_next_link,
    parse_repository_search_response,
    parse_repository_status_response,
    raw_url,
)


class GitHubClientTests(unittest.TestCase):
    def test_builds_code_search_url(self) -> None:
        url = build_code_search_url(
            'nomad.plugin in:file filename:pyproject.toml',
            page=2,
            per_page=50,
        )
        parsed_url = urlparse(url)
        parameters = parse_qs(parsed_url.query)

        self.assertEqual(parsed_url.scheme, 'https')
        self.assertEqual(parsed_url.netloc, 'api.github.com')
        self.assertEqual(parsed_url.path, '/search/code')
        self.assertEqual(
            parameters['q'], ['nomad.plugin in:file filename:pyproject.toml']
        )
        self.assertEqual(parameters['page'], ['2'])
        self.assertEqual(parameters['per_page'], ['50'])

    def test_builds_code_search_url_with_trailing_base_slash(self) -> None:
        url = build_code_search_url(
            'nomad.plugin',
            base_url='https://api.github.com/',
        )

        self.assertTrue(url.startswith('https://api.github.com/search/code?'))

    def test_builds_repository_search_url(self) -> None:
        url = build_repository_search_url(
            'nomad plugin in:name,description,readme',
            page=2,
            per_page=50,
        )
        parsed_url = urlparse(url)
        parameters = parse_qs(parsed_url.query)

        self.assertEqual(parsed_url.scheme, 'https')
        self.assertEqual(parsed_url.netloc, 'api.github.com')
        self.assertEqual(parsed_url.path, '/search/repositories')
        self.assertEqual(parameters['q'], ['nomad plugin in:name,description,readme'])
        self.assertEqual(parameters['page'], ['2'])
        self.assertEqual(parameters['per_page'], ['50'])

    def test_reads_plugin_registry_token_first(self) -> None:
        with temporary_environment(
            PLUGIN_REGISTRY_GITHUB_TOKEN='registry-token',
            GITHUB_TOKEN='generic-token',
        ):
            self.assertEqual(github_token_from_environment(), 'registry-token')

    def test_reads_generic_github_token_as_fallback(self) -> None:
        with temporary_environment(GITHUB_TOKEN='generic-token'):
            self.assertEqual(github_token_from_environment(), 'generic-token')

    def test_builds_auth_headers(self) -> None:
        client = GitHubClient(token='secret-token')
        request = client.build_request('https://api.github.com/search/code')

        self.assertEqual(request.headers['Authorization'], 'Bearer secret-token')
        self.assertEqual(request.headers['Accept'], 'application/vnd.github+json')
        self.assertEqual(request.headers['X-github-api-version'], '2022-11-28')

    def test_parses_code_search_response(self) -> None:
        page = parse_code_search_response(
            code_search_response(),
            link_header='<https://api.github.com/search/code?page=2>; rel="next"',
        )

        self.assertEqual(page.total_count, 1)
        self.assertFalse(page.incomplete_results)
        self.assertEqual(page.next_url, 'https://api.github.com/search/code?page=2')
        self.assertEqual(len(page.candidates), 1)
        candidate = page.candidates[0]
        self.assertEqual(candidate.repository_full_name, 'example/nomad-parser')
        self.assertEqual(
            candidate.repository_url, 'https://github.com/example/nomad-parser'
        )
        self.assertEqual(candidate.file_path, 'packages/parser/pyproject.toml')
        self.assertEqual(
            candidate.raw_url,
            'https://raw.githubusercontent.com/example/nomad-parser/main/packages/parser/pyproject.toml',
        )

    def test_rejects_malformed_code_search_response(self) -> None:
        with self.assertRaisesRegex(ValueError, 'items list'):
            parse_code_search_response({'total_count': 0, 'incomplete_results': False})

    def test_parses_repository_search_response(self) -> None:
        page = parse_repository_search_response(
            repository_search_response(),
            link_header=(
                '<https://api.github.com/search/repositories?page=2>; rel="next"'
            ),
        )

        self.assertEqual(page.total_count, 1)
        self.assertFalse(page.incomplete_results)
        self.assertEqual(
            page.next_url, 'https://api.github.com/search/repositories?page=2'
        )
        self.assertEqual(len(page.candidates), 1)
        candidate = page.candidates[0]
        self.assertEqual(candidate.full_name, 'glaidedata/nomad-measurements-afm')
        self.assertEqual(
            candidate.repository_url,
            'https://github.com/glaidedata/nomad-measurements-afm',
        )
        self.assertEqual(candidate.default_branch, 'main')
        self.assertFalse(candidate.archived)
        self.assertFalse(candidate.fork)

    def test_rejects_malformed_repository_search_response(self) -> None:
        with self.assertRaisesRegex(ValueError, 'items list'):
            parse_repository_search_response(
                {'total_count': 0, 'incomplete_results': False},
            )

    def test_search_code_uses_configured_opener(self) -> None:
        opener = FakeOpener(
            FakeResponse(
                code_search_response(),
                headers={
                    'Link': '<https://api.github.com/search/code?page=2>; rel="next"'
                },
            ),
        )
        client = GitHubClient(token='secret-token', opener=opener)

        page = client.search_code('nomad.plugin', page=3, per_page=10)

        self.assertEqual(
            page.candidates[0].repository_full_name, 'example/nomad-parser'
        )
        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0]
        parsed_url = urlparse(request.full_url)
        parameters = parse_qs(parsed_url.query)
        self.assertEqual(parameters['q'], ['nomad.plugin'])
        self.assertEqual(parameters['page'], ['3'])
        self.assertEqual(parameters['per_page'], ['10'])
        self.assertEqual(request.headers['Authorization'], 'Bearer secret-token')

    def test_open_request_uses_configured_timeout_when_supported(self) -> None:
        opener = TimeoutAwareOpener(FakeResponse(code_search_response()))
        client = GitHubClient(opener=opener, request_timeout=7)

        client.search_code('nomad.plugin')

        self.assertEqual(opener.timeouts, [7])

    def test_search_repositories_uses_configured_opener(self) -> None:
        opener = FakeOpener(
            FakeResponse(
                repository_search_response(),
                headers={
                    'Link': (
                        '<https://api.github.com/search/repositories?page=2>; '
                        'rel="next"'
                    ),
                },
            ),
        )
        client = GitHubClient(token='secret-token', opener=opener)

        page = client.search_repositories('nomad plugin', page=3, per_page=10)

        self.assertEqual(
            page.candidates[0].full_name, 'glaidedata/nomad-measurements-afm'
        )
        self.assertEqual(len(opener.requests), 1)
        request = opener.requests[0]
        parsed_url = urlparse(request.full_url)
        parameters = parse_qs(parsed_url.query)
        self.assertEqual(parameters['q'], ['nomad plugin'])
        self.assertEqual(parameters['page'], ['3'])
        self.assertEqual(parameters['per_page'], ['10'])
        self.assertEqual(request.headers['Authorization'], 'Bearer secret-token')

    def test_fetch_text_uses_raw_accept_header(self) -> None:
        opener = FakeOpener(FakeResponse('plugin metadata'))
        client = GitHubClient(opener=opener)

        content = client.fetch_text(
            'https://raw.githubusercontent.com/example/plugin/main/file.txt'
        )

        self.assertEqual(content, 'plugin metadata')
        self.assertEqual(
            opener.requests[0].headers['Accept'], 'application/vnd.github.raw'
        )

    def test_fetches_repository_status(self) -> None:
        opener = FakeOpener(FakeResponse(repository_status_response()))
        client = GitHubClient(opener=opener)

        status = client.fetch_repository_status('example/child-plugin')

        self.assertEqual(status.full_name, 'example/child-plugin')
        self.assertEqual(
            status.repository_url, 'https://github.com/example/child-plugin'
        )
        self.assertEqual(status.owner_type, 'Organization')
        self.assertTrue(status.fork)
        self.assertFalse(status.archived)
        self.assertEqual(status.stars, 12)
        self.assertEqual(status.created_at, '2025-01-01T00:00:00Z')
        self.assertEqual(status.last_pushed_at, '2026-07-01T00:00:00Z')
        self.assertEqual(
            status.parent_repository_url, 'https://github.com/example/parent-plugin'
        )
        self.assertEqual(
            status.source_repository_url, 'https://github.com/example/source-plugin'
        )
        self.assertEqual(
            opener.requests[0].full_url,
            'https://api.github.com/repos/example/child-plugin',
        )

    def test_parses_repository_status_without_lineage(self) -> None:
        response = repository_status_response(fork=False)
        response.pop('parent')
        response.pop('source')

        status = parse_repository_status_response(response)

        self.assertFalse(status.fork)
        self.assertIsNone(status.parent_repository_url)
        self.assertIsNone(status.source_repository_url)

    def test_reports_unauthorized_github_api_request(self) -> None:
        client = GitHubClient(
            opener=FailingOpener(
                HTTPError(
                    'https://api.github.com/search/code',
                    401,
                    'Unauthorized',
                    {},
                    None,
                ),
            ),
        )

        with self.assertRaisesRegex(RuntimeError, 'PLUGIN_REGISTRY_GITHUB_TOKEN'):
            client.search_code('nomad.plugin')

    def test_reports_network_github_api_request_failure(self) -> None:
        client = GitHubClient(opener=FailingOpener(URLError('network unavailable')))

        with self.assertRaisesRegex(RuntimeError, 'network unavailable'):
            client.search_code('nomad.plugin')

    def test_retries_transient_network_github_api_request_failure(self) -> None:
        opener = SequenceOpener(
            URLError('connection reset by peer'),
            FakeResponse(code_search_response()),
        )
        client = GitHubClient(opener=opener)

        page = client.search_code('nomad.plugin')

        self.assertEqual(
            page.candidates[0].repository_full_name, 'example/nomad-parser'
        )
        self.assertEqual(len(opener.requests), 2)

    def test_parses_next_link_only_when_present(self) -> None:
        link_header = (
            '<https://api.github.com/search/code?page=1>; rel="prev", '
            '<https://api.github.com/search/code?page=3>; rel="next"'
        )

        self.assertEqual(
            parse_next_link(link_header),
            'https://api.github.com/search/code?page=3',
        )
        self.assertIsNone(parse_next_link(None))

    def test_raw_url_quotes_branch_and_file_path(self) -> None:
        self.assertEqual(
            raw_url(
                'example/nomad parser', 'feature branch', 'some path/pyproject.toml'
            ),
            'https://raw.githubusercontent.com/example/nomad%20parser/feature%20branch/some%20path/pyproject.toml',
        )


def code_search_response() -> dict:
    return {
        'total_count': 1,
        'incomplete_results': False,
        'items': [
            {
                'path': 'packages/parser/pyproject.toml',
                'url': 'https://api.github.com/repositories/1/contents/packages/parser/pyproject.toml',
                'html_url': 'https://github.com/example/nomad-parser/blob/main/packages/parser/pyproject.toml',
                'repository': {
                    'full_name': 'example/nomad-parser',
                    'html_url': 'https://github.com/example/nomad-parser',
                    'default_branch': 'main',
                },
            },
        ],
    }


def repository_search_response() -> dict:
    return {
        'total_count': 1,
        'incomplete_results': False,
        'items': [
            {
                'full_name': 'glaidedata/nomad-measurements-afm',
                'html_url': 'https://github.com/glaidedata/nomad-measurements-afm',
                'default_branch': 'main',
                'fork': False,
                'archived': False,
            },
        ],
    }


def repository_status_response(*, fork: bool = True) -> dict:
    return {
        'full_name': 'example/child-plugin',
        'html_url': 'https://github.com/example/child-plugin',
        'owner': {
            'login': 'example',
            'type': 'Organization',
        },
        'fork': fork,
        'archived': False,
        'stargazers_count': 12,
        'created_at': '2025-01-01T00:00:00Z',
        'pushed_at': '2026-07-01T00:00:00Z',
        'parent': {
            'full_name': 'example/parent-plugin',
            'html_url': 'https://github.com/example/parent-plugin',
        },
        'source': {
            'full_name': 'example/source-plugin',
            'html_url': 'https://github.com/example/source-plugin',
        },
    }


class FakeResponse:
    def __init__(self, body, *, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.headers = headers or {}

    def read(self) -> bytes:
        if isinstance(self.body, str):
            return self.body.encode('utf-8')

        return json.dumps(self.body).encode('utf-8')


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> FakeResponse:
        self.requests.append(request)
        return self.response


class TimeoutAwareOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.timeouts: list[int] = []

    def __call__(self, request: Request, *, timeout: int) -> FakeResponse:
        self.timeouts.append(timeout)
        return self.response


class FailingOpener:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def __call__(self, request: Request) -> FakeResponse:
        raise self.error


class SequenceOpener:
    def __init__(self, *responses_or_errors) -> None:
        self.responses_or_errors = list(responses_or_errors)
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> FakeResponse:
        self.requests.append(request)
        response_or_error = self.responses_or_errors.pop(0)
        if isinstance(response_or_error, Exception):
            raise response_or_error

        return response_or_error


class temporary_environment:
    def __init__(self, **values: str) -> None:
        self.values = values
        self.original_values: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for key in ['PLUGIN_REGISTRY_GITHUB_TOKEN', 'GITHUB_TOKEN']:
            self.original_values[key] = os.environ.get(key)
            if key in self.values:
                os.environ[key] = self.values[key]
            else:
                os.environ.pop(key, None)

    def __exit__(self, *args) -> None:
        for key, value in self.original_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == '__main__':
    unittest.main()
