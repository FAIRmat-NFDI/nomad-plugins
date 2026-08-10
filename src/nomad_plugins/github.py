from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

GITHUB_API_BASE_URL = 'https://api.github.com'
GITHUB_API_VERSION = '2022-11-28'
DEFAULT_PER_PAGE = 100
DEFAULT_REQUEST_RETRIES = 2
DEFAULT_REQUEST_TIMEOUT = 30
HTTP_UNAUTHORIZED = 401


@dataclass(frozen=True)
class GitHubCandidateFile:
    repository_full_name: str
    repository_url: str
    file_path: str
    api_url: str
    html_url: str
    raw_url: str | None
    default_branch: str | None
    discovery_source: str = 'code_search'


@dataclass(frozen=True)
class GitHubSearchPage:
    candidates: list[GitHubCandidateFile]
    total_count: int
    incomplete_results: bool
    next_url: str | None


@dataclass(frozen=True)
class GitHubRepositoryCandidate:
    full_name: str
    repository_url: str
    default_branch: str | None
    archived: bool
    fork: bool


@dataclass(frozen=True)
class GitHubRepositorySearchPage:
    candidates: list[GitHubRepositoryCandidate]
    total_count: int
    incomplete_results: bool
    next_url: str | None


@dataclass(frozen=True)
class GitHubRepositoryStatus:
    full_name: str
    repository_url: str
    owner_type: str | None
    archived: bool
    fork: bool
    stars: int | None
    created_at: str | None
    last_pushed_at: str | None
    parent_repository_url: str | None
    source_repository_url: str | None


class GitHubClient:
    def __init__(
        self,
        *,
        token: str | None = None,
        opener: Callable[[Request], Any] = urlopen,
        base_url: str = GITHUB_API_BASE_URL,
        request_retries: int = DEFAULT_REQUEST_RETRIES,
        request_timeout: int = DEFAULT_REQUEST_TIMEOUT,
    ) -> None:
        self.token = token
        self.opener = opener
        self.base_url = base_url.rstrip('/')
        self.request_retries = request_retries
        self.request_timeout = request_timeout

    @classmethod
    def from_environment(cls) -> GitHubClient:
        return cls(token=github_token_from_environment())

    def search_code(
        self,
        query: str,
        *,
        page: int = 1,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> GitHubSearchPage:
        request = self.build_request(
            build_code_search_url(
                query,
                page=page,
                per_page=per_page,
                base_url=self.base_url,
            ),
        )
        response = self.open_request(request)
        data = json.loads(response.read().decode('utf-8'))

        return parse_code_search_response(
            data,
            link_header=response.headers.get('Link'),
        )

    def search_repositories(
        self,
        query: str,
        *,
        page: int = 1,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> GitHubRepositorySearchPage:
        request = self.build_request(
            build_repository_search_url(
                query,
                page=page,
                per_page=per_page,
                base_url=self.base_url,
            ),
        )
        response = self.open_request(request)
        data = json.loads(response.read().decode('utf-8'))

        return parse_repository_search_response(
            data,
            link_header=response.headers.get('Link'),
        )

    def fetch_text(self, url: str) -> str:
        request = self.build_request(url, accept='application/vnd.github.raw')
        response = self.open_request(request)

        return response.read().decode('utf-8')

    def fetch_repository_status(
        self, repository_full_name: str
    ) -> GitHubRepositoryStatus:
        request = self.build_request(
            f'{self.base_url}/repos/{quote(repository_full_name, safe="/")}',
        )
        response = self.open_request(request)
        data = json.loads(response.read().decode('utf-8'))

        return parse_repository_status_response(data)

    def open_request(self, request: Request) -> Any:
        attempt = 0
        while True:
            try:
                return self.open_with_timeout(request)
            except HTTPError as error:
                if error.code == HTTP_UNAUTHORIZED:
                    raise RuntimeError(
                        'GitHub API request was unauthorized. Set '
                        'PLUGIN_REGISTRY_GITHUB_TOKEN or GITHUB_TOKEN before crawling.',
                    ) from error

                if not self.should_retry_request(attempt, error.code):
                    raise RuntimeError(
                        f'GitHub API request failed with HTTP {error.code}.',
                    ) from error
            except URLError as error:
                if not self.should_retry_request(attempt):
                    raise RuntimeError(
                        f'GitHub API request failed: {error.reason}'
                    ) from error

            attempt += 1

    def open_with_timeout(self, request: Request) -> Any:
        try:
            return self.opener(request, timeout=self.request_timeout)
        except TypeError:
            return self.opener(request)

    def should_retry_request(
        self, attempt: int, http_status: int | None = None
    ) -> bool:
        if attempt >= self.request_retries:
            return False

        if http_status is None:
            return True

        return http_status in {429, 500, 502, 503, 504}

    def build_request(
        self, url: str, *, accept: str = 'application/vnd.github+json'
    ) -> Request:
        headers = {
            'Accept': accept,
            'X-GitHub-Api-Version': GITHUB_API_VERSION,
            'User-Agent': 'nomad-plugins-plugin-registry',
        }

        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'

        return Request(url, headers=headers)


def github_token_from_environment() -> str | None:
    return os.environ.get('PLUGIN_REGISTRY_GITHUB_TOKEN') or os.environ.get(
        'GITHUB_TOKEN'
    )


def build_code_search_url(
    query: str,
    *,
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
    base_url: str = GITHUB_API_BASE_URL,
) -> str:
    parameters = urlencode(
        {
            'q': query,
            'per_page': per_page,
            'page': page,
        },
    )

    return f'{base_url.rstrip("/")}/search/code?{parameters}'


def build_repository_search_url(
    query: str,
    *,
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
    base_url: str = GITHUB_API_BASE_URL,
) -> str:
    parameters = urlencode(
        {
            'q': query,
            'per_page': per_page,
            'page': page,
        },
    )

    return f'{base_url.rstrip("/")}/search/repositories?{parameters}'


def parse_code_search_response(
    data: dict[str, Any],
    *,
    link_header: str | None = None,
) -> GitHubSearchPage:
    items = data.get('items')

    if not isinstance(items, list):
        raise ValueError('GitHub code search response must contain an items list.')

    return GitHubSearchPage(
        candidates=[parse_code_search_item(item) for item in items],
        total_count=require_int(data, 'total_count', 'GitHub code search response'),
        incomplete_results=require_bool(
            data,
            'incomplete_results',
            'GitHub code search response',
        ),
        next_url=parse_next_link(link_header),
    )


def parse_repository_search_response(
    data: dict[str, Any],
    *,
    link_header: str | None = None,
) -> GitHubRepositorySearchPage:
    items = data.get('items')

    if not isinstance(items, list):
        raise ValueError(
            'GitHub repository search response must contain an items list.'
        )

    return GitHubRepositorySearchPage(
        candidates=[parse_repository_search_item(item) for item in items],
        total_count=require_int(
            data, 'total_count', 'GitHub repository search response'
        ),
        incomplete_results=require_bool(
            data,
            'incomplete_results',
            'GitHub repository search response',
        ),
        next_url=parse_next_link(link_header),
    )


def parse_code_search_item(item: Any) -> GitHubCandidateFile:
    if not isinstance(item, dict):
        raise ValueError('GitHub code search item must be an object.')

    repository = item.get('repository')
    if not isinstance(repository, dict):
        raise ValueError('GitHub code search item must contain a repository object.')

    repository_full_name = require_string(repository, 'full_name', 'repository')
    repository_url = require_string(repository, 'html_url', 'repository')
    file_path = require_string(item, 'path', 'GitHub code search item')
    api_url = require_string(item, 'url', 'GitHub code search item')
    html_url = require_string(item, 'html_url', 'GitHub code search item')
    default_branch = optional_string(repository, 'default_branch', 'repository')

    return GitHubCandidateFile(
        repository_full_name=repository_full_name,
        repository_url=repository_url,
        file_path=file_path,
        api_url=api_url,
        html_url=html_url,
        raw_url=raw_url(repository_full_name, default_branch, file_path),
        default_branch=default_branch,
    )


def parse_repository_search_item(item: Any) -> GitHubRepositoryCandidate:
    if not isinstance(item, dict):
        raise ValueError('GitHub repository search item must be an object.')

    return GitHubRepositoryCandidate(
        full_name=require_string(item, 'full_name', 'GitHub repository search item'),
        repository_url=require_string(
            item, 'html_url', 'GitHub repository search item'
        ),
        default_branch=optional_string(
            item,
            'default_branch',
            'GitHub repository search item',
        ),
        archived=require_bool(item, 'archived', 'GitHub repository search item'),
        fork=require_bool(item, 'fork', 'GitHub repository search item'),
    )


def parse_repository_status_response(data: dict[str, Any]) -> GitHubRepositoryStatus:
    parent = optional_mapping(data, 'parent', 'GitHub repository')
    source = optional_mapping(data, 'source', 'GitHub repository')
    owner = optional_mapping(data, 'owner', 'GitHub repository')

    return GitHubRepositoryStatus(
        full_name=require_string(data, 'full_name', 'GitHub repository'),
        repository_url=require_string(data, 'html_url', 'GitHub repository'),
        owner_type=optional_string(owner, 'type', 'GitHub repository owner')
        if owner is not None
        else None,
        archived=require_bool(data, 'archived', 'GitHub repository'),
        fork=require_bool(data, 'fork', 'GitHub repository'),
        stars=optional_int(data, 'stargazers_count', 'GitHub repository'),
        created_at=optional_string(data, 'created_at', 'GitHub repository'),
        last_pushed_at=optional_string(data, 'pushed_at', 'GitHub repository'),
        parent_repository_url=optional_repository_url(parent),
        source_repository_url=optional_repository_url(source),
    )


def optional_repository_url(data: dict[str, Any] | None) -> str | None:
    if data is None:
        return None

    return optional_string(data, 'html_url', 'GitHub repository lineage')


def raw_url(
    repository_full_name: str,
    default_branch: str | None,
    file_path: str,
) -> str | None:
    if default_branch is None:
        return None

    return (
        'https://raw.githubusercontent.com/'
        f'{quote(repository_full_name, safe="/")}/'
        f'{quote(default_branch, safe="")}/'
        f'{quote(file_path, safe="/")}'
    )


def parse_next_link(link_header: str | None) -> str | None:
    if link_header is None:
        return None

    for link_value in link_header.split(','):
        link_url, *parameters = link_value.split(';')
        relations = [
            parameter.strip()
            for parameter in parameters
            if parameter.strip() == 'rel="next"'
        ]

        if relations:
            return link_url.strip()[1:-1]

    return None


def require_string(data: dict[str, Any], key: str, context: str) -> str:
    value = data.get(key)

    if not isinstance(value, str) or value.strip() == '':
        raise ValueError(f'{context}.{key} must be a non-empty string.')

    return value


def optional_string(data: dict[str, Any], key: str, context: str) -> str | None:
    value = data.get(key)

    if value is None:
        return None

    if not isinstance(value, str) or value.strip() == '':
        raise ValueError(f'{context}.{key} must be a non-empty string when present.')

    return value


def optional_mapping(
    data: dict[str, Any], key: str, context: str
) -> dict[str, Any] | None:
    value = data.get(key)

    if value is None:
        return None

    if not isinstance(value, dict):
        raise ValueError(f'{context}.{key} must be an object when present.')

    return value


def require_int(data: dict[str, Any], key: str, context: str) -> int:
    value = data.get(key)

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f'{context}.{key} must be a non-negative integer.')

    return value


def optional_int(data: dict[str, Any], key: str, context: str) -> int | None:
    value = data.get(key)

    if value is None:
        return None

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(
            f'{context}.{key} must be a non-negative integer when present.'
        )

    return value


def require_bool(data: dict[str, Any], key: str, context: str) -> bool:
    value = data.get(key)

    if not isinstance(value, bool):
        raise ValueError(f'{context}.{key} must be a boolean.')

    return value
