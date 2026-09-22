from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field, HttpUrl, ValidationError

GITHUB_API_BASE_URL = 'https://api.github.com'
GITHUB_API_VERSION = '2022-11-28'
GITHUB_CODE_SEARCH_LIMIT = 1000
DEFAULT_PER_PAGE = 30
DEFAULT_REQUEST_RETRIES = 2
DEFAULT_REQUEST_TIMEOUT = 30.0
DEFAULT_RETRY_BACKOFF = 0.25
MAX_RETRY_DELAY = 30.0
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class GitHubError(RuntimeError):
    """Base error for actionable GitHub API failures."""


class GitHubAuthenticationError(GitHubError):
    """Raised when GitHub rejects the configured credentials."""


class GitHubSearchIncompleteError(GitHubError):
    """Raised when GitHub cannot provide a complete code-search result."""

    def __init__(self, diagnostics: GitHubSearchDiagnostics) -> None:
        self.diagnostics = diagnostics
        reasons = []
        if diagnostics.incomplete_results:
            reasons.append('GitHub reported incomplete_results=true')
        if diagnostics.result_limit_reached:
            reasons.append(
                f"total_count exceeds GitHub's {GITHUB_CODE_SEARCH_LIMIT}-result "
                'search window'
            )
        if diagnostics.fetched_count != min(
            diagnostics.total_count,
            GITHUB_CODE_SEARCH_LIMIT,
        ):
            reasons.append(
                f'fetched {diagnostics.fetched_count} of '
                f'{diagnostics.total_count} reported results'
            )
        reason = '; '.join(reasons) or 'search completeness could not be verified'
        super().__init__(f'GitHub code search is incomplete: {reason}.')


class GitHubOwner(BaseModel):
    login: str
    type: str | None = None


class GitHubRepositorySummary(BaseModel):
    full_name: str
    html_url: HttpUrl


class GitHubSearchResultItem(BaseModel):
    path: str
    url: HttpUrl
    repository: GitHubRepositorySummary


class GitHubCodeSearchPage(BaseModel):
    total_count: int = Field(ge=0)
    incomplete_results: bool
    items: list[GitHubSearchResultItem]


class GitHubRepositoryLink(BaseModel):
    html_url: HttpUrl


class GitHubRepositoryDetails(BaseModel):
    owner: GitHubOwner
    archived: bool
    fork: bool
    stargazers_count: int
    created_at: datetime | None = None
    pushed_at: datetime | None = None
    default_branch: str | None = None
    parent: GitHubRepositoryLink | None = None
    source: GitHubRepositoryLink | None = None


@dataclass(frozen=True)
class GitHubSearchDiagnostics:
    query: str
    total_count: int
    fetched_count: int
    page_count: int
    incomplete_results: bool
    result_limit_reached: bool


@dataclass(frozen=True)
class GitHubSearchResult:
    items: list[GitHubSearchResultItem]
    diagnostics: GitHubSearchDiagnostics


class GitHubClient:
    def __init__(  # noqa: PLR0913
        self,
        token: str,
        *,
        client: httpx.AsyncClient | None = None,
        request_retries: int = DEFAULT_REQUEST_RETRIES,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        base_url: str = GITHUB_API_BASE_URL,
    ) -> None:
        if not token.strip():
            raise ValueError('A non-empty GitHub token is required.')
        self.token = token
        self.request_retries = request_retries
        self.request_timeout = request_timeout
        self.retry_backoff = retry_backoff
        self.base_url = base_url.rstrip('/')
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> GitHubClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.request_timeout)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search_code(
        self,
        query: str,
        *,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> GitHubSearchResult:
        if per_page < 1 or per_page > 100:  # noqa: PLR2004
            raise ValueError('GitHub search per_page must be between 1 and 100.')

        items: list[GitHubSearchResultItem] = []
        total_count = 0
        page_count = 0
        incomplete_results = False
        result_limit_reached = False
        expected_count = 0

        while page_count == 0 or len(items) < expected_count:
            page_count += 1
            response = await self._request(
                'GET',
                f'{self.base_url}/search/code',
                params={
                    'q': query,
                    'sort': 'stars',
                    'order': 'desc',
                    'per_page': per_page,
                    'page': page_count,
                },
            )
            page = self._validate_response(GitHubCodeSearchPage, response)

            if page_count == 1:
                total_count = page.total_count
                result_limit_reached = total_count > GITHUB_CODE_SEARCH_LIMIT
                expected_count = min(total_count, GITHUB_CODE_SEARCH_LIMIT)

            incomplete_results = incomplete_results or page.incomplete_results
            items.extend(page.items)

            if page.incomplete_results or result_limit_reached or not page.items:
                break

            expected_pages = math.ceil(expected_count / per_page)
            if page_count >= expected_pages:
                break

        diagnostics = GitHubSearchDiagnostics(
            query=query,
            total_count=total_count,
            fetched_count=len(items),
            page_count=page_count,
            incomplete_results=incomplete_results,
            result_limit_reached=result_limit_reached,
        )
        if incomplete_results or result_limit_reached or len(items) != expected_count:
            raise GitHubSearchIncompleteError(diagnostics)

        return GitHubSearchResult(items=items, diagnostics=diagnostics)

    async def fetch_text(self, url: str) -> str:
        response = await self._request(
            'GET',
            url,
            headers={'Accept': 'application/vnd.github.raw'},
        )
        return response.text

    async def fetch_repository(
        self,
        repository_full_name: str,
    ) -> GitHubRepositoryDetails:
        response = await self._request(
            'GET',
            f'{self.base_url}/repos/{repository_full_name}',
        )
        return self._validate_response(GitHubRepositoryDetails, response)

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        if self._client is None:
            raise RuntimeError('GitHubClient must be used as an async context manager.')

        request_headers = {
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {self.token}',
            'User-Agent': 'nomad-plugin-catalogue',
            'X-GitHub-Api-Version': GITHUB_API_VERSION,
        }
        request_headers.update(kwargs.pop('headers', {}))

        for attempt in range(self.request_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=request_headers,
                    timeout=self.request_timeout,
                    **kwargs,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt >= self.request_retries:
                    raise GitHubError(
                        f'GitHub API request failed after '
                        f'{self.request_retries + 1} attempts: {exc}'
                    ) from exc
                await self._wait_before_retry(attempt)
                continue

            if response.status_code == httpx.codes.UNAUTHORIZED:
                raise GitHubAuthenticationError(
                    'GitHub API authentication failed. Check GITHUB_TOKEN.'
                )

            if response.is_success:
                return response

            if self._is_retryable(response) and attempt < self.request_retries:
                await self._wait_before_retry(attempt, response)
                continue

            detail = self._response_error_detail(response)
            raise GitHubError(
                f'GitHub API request failed with HTTP {response.status_code}'
                f'{detail}: {method} {url}'
            )

        raise AssertionError('GitHub request retry loop ended unexpectedly.')

    def _is_retryable(self, response: httpx.Response) -> bool:
        if response.status_code in RETRYABLE_STATUS_CODES:
            return True
        return response.status_code == httpx.codes.FORBIDDEN and (
            response.headers.get('X-RateLimit-Remaining') == '0'
            or 'Retry-After' in response.headers
        )

    async def _wait_before_retry(
        self,
        attempt: int,
        response: httpx.Response | None = None,
    ) -> None:
        retry_after = response.headers.get('Retry-After') if response else None
        try:
            delay = float(retry_after) if retry_after is not None else None
        except ValueError:
            delay = None
        if delay is None:
            delay = self.retry_backoff * (2**attempt)
        await asyncio.sleep(min(delay, MAX_RETRY_DELAY))

    @staticmethod
    def _validate_response(model: type[BaseModel], response: httpx.Response) -> Any:
        try:
            return model.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise GitHubError(
                f'GitHub API returned an invalid response for {response.request.url}: '
                f'{exc}'
            ) from exc

    @staticmethod
    def _response_error_detail(response: httpx.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            data = None
        message = data.get('message') if isinstance(data, dict) else None
        return f' ({message})' if isinstance(message, str) and message else ''
