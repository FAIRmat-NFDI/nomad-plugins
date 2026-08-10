from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

from .github import (
    DEFAULT_PER_PAGE,
    GitHubCandidateFile,
    GitHubClient,
    GitHubRepositoryCandidate,
    GitHubRepositoryStatus,
    raw_url,
)
from .pyproject import parse_pyproject_candidate, project_path_from_candidate
from .transform import (
    PROJECT_KIND_OFFICIAL_SOFTWARE,
    PROJECT_KIND_OFFICIAL_TEMPLATE,
    DiscoveredDeployment,
    DiscoveredPlugin,
    DiscoveredStatus,
    build_registry_snapshot,
    discovered_plugins_to_legacy_plugin_data,
    stable_plugin_id,
)

# TODO: Add a metadata-file discovery path here once nomad_plugin_metadata.yaml is
# present in live plugins. Keep pyproject discovery as the fallback source.
DISCOVERY_LABEL = 'github-code-search-pyproject'
PYPROJECT_FILENAME = 'pyproject.toml'
DEFAULT_FAIRMAT_OWNERS = ('fairmat-nfdi',)
REPOSITORY_SEARCH_SOURCE = 'repository_search'
REPOSITORY_SEARCH_REQUIRED_TEXT = ('nomad.plugin', 'nomad-lab')
CONFIGURED_REPOSITORY_METADATA_SOURCE = 'crawler-config'
GITHUB_REPOSITORY_PATH_PARTS = 2
ProgressReporter = Callable[[str], None]


@dataclass(frozen=True)
class CrawlReport:
    snapshot: dict[str, Any]
    legacy_plugin_data: list[dict[str, Any]]
    searched_queries: list[str]
    fetched_count: int
    parsed_count: int
    skipped: list[str]


@dataclass(frozen=True)
class OfficialTemplateRepository:
    repository: str
    name: str
    description: str


ConfiguredRepository = OfficialTemplateRepository


def crawl_pyproject_registry(  # noqa: PLR0913
    config: dict[str, Any],
    *,
    client: GitHubClient | None = None,
    data_updated_at: str | None = None,
    per_page: int = DEFAULT_PER_PAGE,
    include_repository_search: bool = True,
    repository_candidate_limit: int | None = None,
    progress: ProgressReporter | None = None,
) -> CrawlReport:
    github_client = client or GitHubClient.from_environment()
    search_queries = pyproject_search_queries(config)
    repository_queries = (
        repository_search_queries(config) if include_repository_search else []
    )
    excluded_candidates = candidate_exclusions(config)
    excluded_documentation_urls = documentation_url_exclusions(config)
    excluded_pypi_urls = pypi_url_exclusions(config)
    should_exclude_forks = exclude_forks(config)
    request_delay_seconds = search_request_delay_seconds(config)
    progress_message(progress, 'Discovering pyproject.toml files from code search.')
    discovered_candidates = discover_pyproject_candidates(
        github_client,
        search_queries,
        excluded_candidates=excluded_candidates,
        per_page=per_page,
        request_delay_seconds=request_delay_seconds,
        progress=progress,
    )
    progress_message(
        progress,
        f'Found {len(discovered_candidates)} code-search pyproject candidates.',
    )
    repository_candidates: list[GitHubCandidateFile] = []
    if include_repository_search:
        progress_message(
            progress, 'Discovering root pyprojects from repository search.'
        )
        repository_candidates = discover_repository_pyproject_candidates(
            github_client,
            repository_queries,
            exclude_forks=should_exclude_forks,
            excluded_candidates=excluded_candidates,
            max_candidates=repository_candidate_limit
            if repository_candidate_limit is not None
            else max_repository_candidates(config),
            per_page=per_page,
            request_delay_seconds=request_delay_seconds,
            progress=progress,
        )
        progress_message(
            progress,
            'Found '
            f'{len(repository_candidates)} repository-search pyproject candidates.',
        )
    candidates = merge_pyproject_candidates(
        discovered_candidates,
        repository_candidates,
        excluded_candidates=excluded_candidates,
    )
    progress_message(progress, f'Fetching and parsing {len(candidates)} candidates.')
    plugins, skipped, fetched_count = parse_pyproject_candidates(
        github_client,
        candidates,
        exclude_forks=should_exclude_forks,
        fairmat_owners=fairmat_owners(config),
        progress=progress,
    )
    progress_message(progress, 'Fetching configured official repositories.')
    configured_templates, configured_template_skips = fetch_official_template_plugins(
        github_client,
        official_template_repositories(config),
        exclude_forks=should_exclude_forks,
        fairmat_owner_names=fairmat_owners(config),
    )
    configured_software, configured_software_skips = fetch_official_software_plugins(
        github_client,
        official_software_repositories(config),
        exclude_forks=should_exclude_forks,
        fairmat_owner_names=fairmat_owners(config),
    )
    plugins = merge_discovered_plugins(
        plugins,
        [*configured_templates, *configured_software],
    )
    plugins = exclude_documentation_urls(
        plugins,
        excluded_documentation_urls=excluded_documentation_urls,
    )
    plugins = exclude_pypi_urls(
        plugins,
        excluded_pypi_urls=excluded_pypi_urls,
    )
    progress_message(progress, 'Fetching deployment and PyPI compatibility metadata.')
    plugins = enrich_legacy_metadata(
        github_client,
        plugins,
        config=config,
    )
    skipped = [*skipped, *configured_template_skips, *configured_software_skips]
    snapshot = build_registry_snapshot(
        plugins,
        data_updated_at=data_updated_at or current_utc_timestamp(),
        discovery=DISCOVERY_LABEL,
    )
    progress_message(
        progress,
        f'Built snapshot with {len(plugins)} records; {len(skipped)} skipped.',
    )

    return CrawlReport(
        snapshot=snapshot,
        legacy_plugin_data=discovered_plugins_to_legacy_plugin_data(plugins),
        searched_queries=[*search_queries, *repository_queries],
        fetched_count=fetched_count,
        parsed_count=len(plugins),
        skipped=skipped,
    )


def pyproject_search_queries(config: dict[str, Any]) -> list[str]:
    queries = config.get('github', {}).get('searchQueries', [])
    if not isinstance(queries, list):
        raise ValueError('github.searchQueries must be a list.')

    pyproject_queries = [
        query
        for query in queries
        if isinstance(query, str) and PYPROJECT_FILENAME in query
    ]

    if len(pyproject_queries) == 0:
        raise ValueError('github.searchQueries must contain a pyproject.toml query.')

    return pyproject_queries


def repository_search_queries(config: dict[str, Any]) -> list[str]:
    queries = config.get('github', {}).get('repositorySearchQueries', [])
    if not isinstance(queries, list):
        raise ValueError('github.repositorySearchQueries must be a list.')

    repository_queries = [
        query for query in queries if isinstance(query, str) and query.strip() != ''
    ]

    if len(repository_queries) != len(queries):
        raise ValueError(
            'github.repositorySearchQueries must contain only non-empty strings.'
        )

    return repository_queries


def max_repository_candidates(config: dict[str, Any]) -> int | None:
    value = config.get('github', {}).get('maxRepositoryCandidates')
    if value is None:
        return None

    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError('github.maxRepositoryCandidates must be a positive integer.')

    return value


def search_request_delay_seconds(config: dict[str, Any]) -> float:
    value = config.get('github', {}).get('searchRequestDelaySeconds', 0)
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise ValueError(
            'github.searchRequestDelaySeconds must be a non-negative number.',
        )

    return float(value)


def official_template_repositories(
    config: dict[str, Any],
) -> list[OfficialTemplateRepository]:
    return configured_repositories(config, 'officialTemplateRepositories')


def official_software_repositories(
    config: dict[str, Any],
) -> list[ConfiguredRepository]:
    return configured_repositories(config, 'officialSoftwareRepositories')


def configured_repositories(
    config: dict[str, Any], key: str
) -> list[ConfiguredRepository]:
    values = config.get('github', {}).get(key, [])
    if not isinstance(values, list):
        raise ValueError(f'github.{key} must be a list.')

    repositories: list[ConfiguredRepository] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise ValueError(f'github.{key}[{index}] must be an object.')

        repository = value.get('repository')
        name = value.get('name')
        description = value.get('description')
        if not isinstance(repository, str) or repository.strip() == '':
            raise ValueError(
                f'github.{key}[{index}].repository must be a non-empty string.',
            )
        if not isinstance(name, str) or name.strip() == '':
            raise ValueError(
                f'github.{key}[{index}].name must be a non-empty string.',
            )
        if not isinstance(description, str):
            raise ValueError(
                f'github.{key}[{index}].description must be a string.',
            )

        repositories.append(
            ConfiguredRepository(
                repository=repository.strip(),
                name=name.strip(),
                description=description.strip(),
            ),
        )

    return repositories


def documentation_url_exclusions(config: dict[str, Any]) -> set[str]:
    values = config.get('github', {}).get('excludeDocumentationUrls', [])
    if not isinstance(values, list):
        raise ValueError('github.excludeDocumentationUrls must be a list.')

    normalized_urls = {
        normalize_url_exclusion(value)
        for value in values
        if isinstance(value, str) and value.strip() != ''
    }
    if len(normalized_urls) != len(values):
        raise ValueError(
            'github.excludeDocumentationUrls must contain only non-empty strings.'
        )

    return normalized_urls


def pypi_url_exclusions(config: dict[str, Any]) -> set[str]:
    values = config.get('github', {}).get('excludePypiUrls', [])
    if not isinstance(values, list):
        raise ValueError('github.excludePypiUrls must be a list.')

    normalized_urls = {
        normalize_url_exclusion(value)
        for value in values
        if isinstance(value, str) and value.strip() != ''
    }
    if len(normalized_urls) != len(values):
        raise ValueError('github.excludePypiUrls must contain only non-empty strings.')

    return normalized_urls


def discover_pyproject_candidates(  # noqa: PLR0913
    client: GitHubClient,
    search_queries: list[str],
    *,
    excluded_candidates: set[str] | None = None,
    per_page: int = DEFAULT_PER_PAGE,
    request_delay_seconds: float = 0,
    progress: ProgressReporter | None = None,
) -> list[GitHubCandidateFile]:
    candidates_by_key: dict[str, GitHubCandidateFile] = {}
    exclusions = excluded_candidates or set()

    for query in search_queries:
        page_number = 1
        while True:
            progress_message(
                progress,
                f'Code search: {query!r}, page {page_number}.',
            )
            page = client.search_code(query, page=page_number, per_page=per_page)
            delay_after_search_request(request_delay_seconds)
            for candidate in page.candidates:
                if not is_pyproject_candidate(candidate):
                    continue

                key = candidate_key(candidate)
                if key in exclusions:
                    continue

                candidates_by_key.setdefault(key, candidate)

            if page.next_url is None:
                break

            page_number += 1

    return [
        candidates_by_key[key] for key in sorted(candidates_by_key, key=str.casefold)
    ]


def discover_repository_pyproject_candidates(  # noqa: PLR0913
    client: GitHubClient,
    search_queries: list[str],
    *,
    exclude_forks: bool,
    excluded_candidates: set[str] | None = None,
    max_candidates: int | None = None,
    per_page: int = DEFAULT_PER_PAGE,
    request_delay_seconds: float = 0,
    progress: ProgressReporter | None = None,
) -> list[GitHubCandidateFile]:
    candidates_by_key: dict[str, GitHubCandidateFile] = {}
    exclusions = excluded_candidates or set()

    for query in search_queries:
        page_number = 1
        query_candidate_count = 0
        while True:
            progress_message(
                progress,
                f'Repository search: {query!r}, page {page_number}.',
            )
            page = client.search_repositories(
                query, page=page_number, per_page=per_page
            )
            delay_after_search_request(request_delay_seconds)
            for repository in page.candidates:
                if repository.archived or (exclude_forks and repository.fork):
                    continue

                candidate = root_pyproject_candidate(repository)
                key = candidate_key(candidate)
                if key in exclusions:
                    continue

                candidates_by_key.setdefault(key, candidate)
                query_candidate_count += 1
                if (
                    max_candidates is not None
                    and query_candidate_count >= max_candidates
                ):
                    break

            if max_candidates is not None and query_candidate_count >= max_candidates:
                break

            if page.next_url is None:
                break

            page_number += 1

    return sorted_candidates(candidates_by_key)


def delay_after_search_request(delay_seconds: float) -> None:
    if delay_seconds > 0:
        time.sleep(delay_seconds)


def sorted_candidates(
    candidates_by_key: dict[str, GitHubCandidateFile],
) -> list[GitHubCandidateFile]:
    return [
        candidates_by_key[key] for key in sorted(candidates_by_key, key=str.casefold)
    ]


def parse_pyproject_candidates(
    client: GitHubClient,
    candidates: list[GitHubCandidateFile],
    *,
    exclude_forks: bool = False,
    fairmat_owners: set[str] | None = None,
    progress: ProgressReporter | None = None,
) -> tuple[list[DiscoveredPlugin], list[str], int]:
    plugins_by_id: dict[str, DiscoveredPlugin] = {}
    status_by_repository: dict[str, GitHubRepositoryStatus] = {}
    fairmat_owner_names = (
        fairmat_owners if fairmat_owners is not None else set(DEFAULT_FAIRMAT_OWNERS)
    )
    skipped: list[str] = []
    fetched_count = 0

    for index, candidate in enumerate(candidates, start=1):
        if index == 1 or index % 25 == 0 or index == len(candidates):
            progress_message(
                progress,
                f'Fetching candidate {index}/{len(candidates)}: '
                f'{candidate_label(candidate)}.',
            )
        label = candidate_label(candidate)
        fetch_url = candidate.raw_url or candidate.api_url
        if fetch_url == '':
            skipped.append(f'{label}: missing fetchable file URL')
            continue

        try:
            pyproject_text = client.fetch_text(fetch_url)
            if (
                candidate.discovery_source == REPOSITORY_SEARCH_SOURCE
                and not has_nomad_ecosystem_signal(
                    pyproject_text,
                )
            ):
                continue

            fetched_count += 1
            plugin = parse_pyproject_candidate(candidate, pyproject_text)
            status = status_by_repository.get(candidate.repository_full_name)
            if status is None:
                status = client.fetch_repository_status(candidate.repository_full_name)
                status_by_repository[candidate.repository_full_name] = status
            if exclude_forks and status.fork:
                skipped.append(f'{label}: skipped fork repository')
                continue

            plugin = replace(
                plugin,
                owner=status.full_name.split('/', 1)[0],
                owner_type=status.owner_type,
                owner_group=owner_group(plugin, fairmat_owner_names),
                status=discovered_status(status),
                registry_visible=plugin.registry_visible and not status.archived,
            )
        except Exception as error:
            if (
                candidate.discovery_source == REPOSITORY_SEARCH_SOURCE
                and 'HTTP 404' in str(error)
            ):
                continue

            skipped.append(f'{label}: {error}')
            continue

        plugin_id = stable_plugin_id(plugin.repository_url, plugin.project_path)
        existing_plugin = plugins_by_id.get(plugin_id)
        if existing_plugin is not None:
            plugins_by_id[plugin_id] = replace(
                existing_plugin,
                discovery_warnings=[
                    *existing_plugin.discovery_warnings,
                    f'Duplicate pyproject candidate skipped: {candidate.file_path}',
                ],
            )
            continue

        plugins_by_id[plugin_id] = plugin

    return (
        [
            plugins_by_id[plugin_id]
            for plugin_id in sorted(plugins_by_id, key=str.casefold)
        ],
        skipped,
        fetched_count,
    )


def enrich_legacy_metadata(
    client: GitHubClient,
    plugins: list[DiscoveredPlugin],
    *,
    config: dict[str, Any],
) -> list[DiscoveredPlugin]:
    central_plugins = deployment_requirement_names(
        client,
        config,
        'centralRequirementsUrl',
    )
    example_oasis_plugins = deployment_requirement_names(
        client,
        config,
        'exampleOasisRequirementsUrl',
    )
    pypi_status_by_name: dict[str, bool] = {}
    enriched_plugins: list[DiscoveredPlugin] = []

    for plugin in plugins:
        normalized_name = normalize_package_name(plugin.name)
        on_pypi = pypi_status_by_name.get(normalized_name)
        if on_pypi is None:
            on_pypi = package_exists_on_pypi(client, plugin.name)
            pypi_status_by_name[normalized_name] = on_pypi

        enriched_plugins.append(
            replace(
                plugin,
                deployment=DiscoveredDeployment(
                    on_central=normalized_name in central_plugins,
                    on_example_oasis=normalized_name in example_oasis_plugins,
                ),
                on_pypi=on_pypi,
            ),
        )

    return enriched_plugins


def deployment_requirement_names(
    client: GitHubClient,
    config: dict[str, Any],
    key: str,
) -> set[str]:
    url = config.get('deploymentSources', {}).get(key)
    if not isinstance(url, str) or url.strip() == '':
        return set()

    try:
        requirements_text = client.fetch_text(url)
    except Exception:
        return set()

    return {
        normalize_package_name(requirement)
        for requirement in requirement_names(requirements_text)
    }


def requirement_names(requirements_text: str) -> list[str]:
    names: list[str] = []
    for line in requirements_text.splitlines():
        cleaned_line = line.split('#', 1)[0].split(';', 1)[0].strip()
        if cleaned_line == '' or cleaned_line.startswith(('-', '--')):
            continue

        match = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)', cleaned_line)
        if match is not None:
            names.append(match.group(1))

    return names


def package_exists_on_pypi(client: GitHubClient, package_name: str) -> bool:
    try:
        client.fetch_text(
            f'https://pypi.org/pypi/{quote(package_name, safe="")}/json',
        )
    except Exception:
        return False

    return True


def normalize_package_name(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name.strip().lower())


def fetch_official_template_plugins(
    client: GitHubClient,
    repositories: list[ConfiguredRepository],
    *,
    exclude_forks: bool,
    fairmat_owner_names: set[str],
) -> tuple[list[DiscoveredPlugin], list[str]]:
    return fetch_configured_repository_plugins(
        client,
        repositories,
        exclude_forks=exclude_forks,
        fairmat_owner_names=fairmat_owner_names,
        project_kind=PROJECT_KIND_OFFICIAL_TEMPLATE,
    )


def fetch_official_software_plugins(
    client: GitHubClient,
    repositories: list[ConfiguredRepository],
    *,
    exclude_forks: bool,
    fairmat_owner_names: set[str],
) -> tuple[list[DiscoveredPlugin], list[str]]:
    return fetch_configured_repository_plugins(
        client,
        repositories,
        exclude_forks=exclude_forks,
        fairmat_owner_names=fairmat_owner_names,
        project_kind=PROJECT_KIND_OFFICIAL_SOFTWARE,
    )


def fetch_configured_repository_plugins(
    client: GitHubClient,
    repositories: list[ConfiguredRepository],
    *,
    exclude_forks: bool,
    fairmat_owner_names: set[str],
    project_kind: str,
) -> tuple[list[DiscoveredPlugin], list[str]]:
    plugins: list[DiscoveredPlugin] = []
    skipped: list[str] = []

    for repository in repositories:
        repository_full_name = normalize_repository_full_name(repository.repository)
        try:
            status = client.fetch_repository_status(repository_full_name)
            if exclude_forks and status.fork:
                skipped.append(f'{repository_full_name}: skipped fork repository')
                continue

            plugin = DiscoveredPlugin(
                name=repository.name,
                description=repository.description,
                repository_url=status.repository_url,
                owner=status.full_name.split('/', 1)[0],
                owner_type=status.owner_type,
                owner_group='fairmat'
                if status.full_name.split('/', 1)[0].lower() in fairmat_owner_names
                else 'community',
                dependencies=[],
                status=discovered_status(status),
                deployment=DiscoveredDeployment(),
                metadata_source=CONFIGURED_REPOSITORY_METADATA_SOURCE,
                project_kind=project_kind,
                registry_visible=not status.archived,
            )
            plugins.append(plugin)
        except Exception as error:
            skipped.append(f'{repository_full_name}: {error}')

    return plugins, skipped


def merge_discovered_plugins(
    discovered_plugins: list[DiscoveredPlugin],
    configured_plugins: list[DiscoveredPlugin],
) -> list[DiscoveredPlugin]:
    plugins_by_id = {
        stable_plugin_id(plugin.repository_url, plugin.project_path): plugin
        for plugin in discovered_plugins
    }

    for plugin in configured_plugins:
        plugins_by_id[stable_plugin_id(plugin.repository_url, plugin.project_path)] = (
            plugin
        )

    return [
        plugins_by_id[plugin_id]
        for plugin_id in sorted(plugins_by_id, key=str.casefold)
    ]


def exclude_documentation_urls(
    plugins: list[DiscoveredPlugin],
    *,
    excluded_documentation_urls: set[str],
) -> list[DiscoveredPlugin]:
    if len(excluded_documentation_urls) == 0:
        return plugins

    return [
        replace(plugin, documentation_url=None)
        if (
            plugin.documentation_url is not None
            and normalize_url_exclusion(plugin.documentation_url)
            in excluded_documentation_urls
        )
        else plugin
        for plugin in plugins
    ]


def exclude_pypi_urls(
    plugins: list[DiscoveredPlugin],
    *,
    excluded_pypi_urls: set[str],
) -> list[DiscoveredPlugin]:
    if len(excluded_pypi_urls) == 0:
        return plugins

    return [
        replace(plugin, pypi_url=None)
        if (
            plugin.pypi_url is not None
            and normalize_url_exclusion(plugin.pypi_url) in excluded_pypi_urls
        )
        else plugin
        for plugin in plugins
    ]


def merge_pyproject_candidates(
    discovered_candidates: list[GitHubCandidateFile],
    repository_candidates: list[GitHubCandidateFile],
    *,
    excluded_candidates: set[str] | None = None,
) -> list[GitHubCandidateFile]:
    candidates_by_key = {
        candidate_key(candidate): candidate for candidate in discovered_candidates
    }
    exclusions = excluded_candidates or set()

    for candidate in repository_candidates:
        key = candidate_key(candidate)
        if key in exclusions:
            continue

        candidates_by_key.setdefault(key, candidate)

    return [
        candidates_by_key[key] for key in sorted(candidates_by_key, key=str.casefold)
    ]


def is_pyproject_candidate(candidate: GitHubCandidateFile) -> bool:
    return candidate.file_path.replace('\\', '/').endswith(
        f'/{PYPROJECT_FILENAME}'
    ) or (candidate.file_path == PYPROJECT_FILENAME)


def candidate_key(candidate: GitHubCandidateFile) -> str:
    return stable_plugin_id(
        candidate.repository_url, project_path_from_candidate(candidate)
    )


def normalize_repository_full_name(repository: str) -> str:
    cleaned_repository = repository.strip()
    if cleaned_repository == '':
        raise ValueError('Repository full name must not be empty.')

    if '://' in cleaned_repository:
        parsed_url = urlparse(cleaned_repository)
        repository_path = parsed_url.path.strip('/')
    else:
        repository_path = cleaned_repository

    if repository_path.endswith('.git'):
        repository_path = repository_path[:-4]

    repository_parts = [part for part in repository_path.split('/') if part]
    if len(repository_parts) != GITHUB_REPOSITORY_PATH_PARTS:
        raise ValueError(
            'Repository must be configured as "owner/name" or a GitHub repository URL.',
        )

    return '/'.join(repository_parts).lower()


def root_pyproject_candidate(
    repository: GitHubRepositoryCandidate,
) -> GitHubCandidateFile:
    file_path = PYPROJECT_FILENAME
    repository_url = repository.repository_url

    return GitHubCandidateFile(
        repository_full_name=repository.full_name,
        repository_url=repository_url,
        file_path=file_path,
        api_url=(
            f'https://api.github.com/repos/{repository.full_name}/contents/{file_path}'
        ),
        html_url=(
            f'{repository_url}/blob/{repository.default_branch or "HEAD"}/{file_path}'
        ),
        raw_url=raw_url(repository.full_name, repository.default_branch, file_path),
        default_branch=repository.default_branch,
        discovery_source=REPOSITORY_SEARCH_SOURCE,
    )


def has_nomad_ecosystem_signal(pyproject_text: str) -> bool:
    normalized_text = pyproject_text.lower()

    return any(signal in normalized_text for signal in REPOSITORY_SEARCH_REQUIRED_TEXT)


def candidate_exclusions(config: dict[str, Any]) -> set[str]:
    exclusions = config.get('github', {}).get('excludeCandidates', [])
    if not isinstance(exclusions, list):
        raise ValueError('github.excludeCandidates must be a list.')

    normalized_exclusions: set[str] = set()
    for exclusion in exclusions:
        if not isinstance(exclusion, str) or exclusion.strip() == '':
            raise ValueError(
                'github.excludeCandidates must contain only non-empty strings.'
            )

        normalized_exclusions.add(normalize_candidate_exclusion(exclusion))

    return normalized_exclusions


def exclude_forks(config: dict[str, Any]) -> bool:
    value = config.get('github', {}).get('excludeForks', False)
    if not isinstance(value, bool):
        raise ValueError('github.excludeForks must be a boolean.')

    return value


def fairmat_owners(config: dict[str, Any]) -> set[str]:
    owner_groups = config.get('ownerGroups', {})
    if owner_groups is None:
        return set(DEFAULT_FAIRMAT_OWNERS)
    if not isinstance(owner_groups, dict):
        raise ValueError('ownerGroups must be an object.')

    fairmat = owner_groups.get('fairmat', list(DEFAULT_FAIRMAT_OWNERS))
    if not isinstance(fairmat, list):
        raise ValueError('ownerGroups.fairmat must be a list.')

    normalized_owners = {
        owner.strip().lower()
        for owner in fairmat
        if isinstance(owner, str) and owner.strip() != ''
    }
    if len(normalized_owners) != len(fairmat):
        raise ValueError('ownerGroups.fairmat must contain only non-empty strings.')

    return normalized_owners


def owner_group(plugin: DiscoveredPlugin, fairmat_owner_names: set[str]) -> str:
    if plugin.owner is not None and plugin.owner.strip().lower() in fairmat_owner_names:
        return 'fairmat'

    return 'community'


def normalize_candidate_exclusion(exclusion: str) -> str:
    repository_url, separator, project_path = exclusion.strip().partition('#')

    if '://' not in repository_url:
        repository_url = f'https://{repository_url}'

    return stable_plugin_id(repository_url, project_path if separator else None)


def normalize_url_exclusion(url: str) -> str:
    return url.strip().rstrip('/').lower()


def discovered_status(status: GitHubRepositoryStatus) -> DiscoveredStatus:
    return DiscoveredStatus(
        archived=status.archived,
        fork=status.fork,
        stars=status.stars,
        created_at=status.created_at,
        last_pushed_at=status.last_pushed_at,
        parent_repository_url=status.parent_repository_url,
        source_repository_url=status.source_repository_url,
    )


def candidate_label(candidate: GitHubCandidateFile) -> str:
    return f'{candidate.repository_full_name}:{candidate.file_path}'


def current_utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace('+00:00', 'Z')
    )


def progress_message(progress: ProgressReporter | None, message: str) -> None:
    if progress is not None:
        progress(message)
