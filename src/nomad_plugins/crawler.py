import asyncio
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import click
import httpx
from dotenv import load_dotenv
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    model_serializer,
)
from pydantic.json_schema import SkipJsonSchema

from nomad_plugins.config import CatalogueConfig, load_catalogue_config
from nomad_plugins.github import (
    GitHubClient,
    GitHubError,
    GitHubRepositoryDetails,
    GitHubSearchDiagnostics,
    GitHubSearchIncompleteError,
    GitHubSearchResultItem,
)
from nomad_plugins.pyproject import (
    Author,
    PluginEntryPoint,
    PyProjectError,
    PyProjectTOML,
    has_nomad_ecosystem_signal,
    parse_pyproject,
    parse_requirement_name,
    project_path_from_pyproject_path,
)
from nomad_plugins.transform import (
    PluginType,
    ProjectKind,
    classify_project,
    derive_plugin_types,
    is_registry_visible,
    normalize_dependencies,
    sorted_unique,
    stable_plugin_id,
)

# Load .env file if it exists
env_path = Path('.env')
if env_path.exists():
    load_dotenv(env_path)


class RepositoryStatus(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    archived: bool
    fork: bool
    stars: int
    created_at: datetime | None = Field(default=None, alias='createdAt')
    last_pushed_at: datetime | None = Field(default=None, alias='lastPushedAt')
    default_branch: str | None = Field(default=None, alias='defaultBranch')
    parent_repository_url: HttpUrl | None = Field(
        default=None,
        alias='parentRepositoryUrl',
    )
    source_repository_url: HttpUrl | None = Field(
        default=None,
        alias='sourceRepositoryUrl',
    )


class DeploymentInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    on_central: bool = Field(alias='onCentral')
    on_example_oasis: bool = Field(alias='onExampleOasis')


class Plugin(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str = ''
    repository_url: HttpUrl = Field(alias='repositoryUrl')
    documentation_url: HttpUrl | None = Field(default=None, alias='documentationUrl')
    pypi_url: HttpUrl | None = Field(default=None, alias='pypiUrl')
    owner: str
    owner_type: str | None = Field(default=None, alias='ownerType')
    entrypoints: list[PluginEntryPoint] = Field(default_factory=list)
    plugin_types: list[PluginType] | None = Field(default=None, alias='pluginTypes')
    dependencies: list[str] = Field(default_factory=list)
    status: RepositoryStatus
    deployment: DeploymentInfo
    project_kind: ProjectKind = Field(alias='projectKind')
    registry_visible: bool = Field(alias='registryVisible')
    metadata_source: Literal['pyproject.toml'] = Field(alias='metadataSource')
    discovery_warnings: list[str] = Field(
        default_factory=list,
        alias='discoveryWarnings',
    )
    project_path: SkipJsonSchema[str | None] = Field(default=None, exclude=True)
    declared_repository_url: SkipJsonSchema[HttpUrl | None] = Field(
        default=None,
        exclude=True,
    )
    homepage_url: SkipJsonSchema[HttpUrl | None] = Field(default=None, exclude=True)
    issues_url: SkipJsonSchema[HttpUrl | None] = Field(default=None, exclude=True)
    authors: SkipJsonSchema[list[Author]] = Field(default_factory=list, exclude=True)
    maintainers: SkipJsonSchema[list[Author]] = Field(
        default_factory=list, exclude=True
    )

    @model_serializer(mode='wrap')
    def serialize_model(
        self,
        handler: SerializerFunctionWrapHandler,
        info: SerializationInfo,
    ) -> dict[str, Any]:
        data = handler(self)
        if self.plugin_types is None:
            data['pluginTypes' if info.by_alias else 'plugin_types'] = None
        return data


@dataclass(frozen=True)
class CrawlResult:
    plugins: list[Plugin]
    search_diagnostics: list['CodeQueryDiagnostics']
    unique_candidate_count: int
    repository_search_diagnostics: list['RepositoryQueryDiagnostics'] = field(
        default_factory=list
    )


@dataclass(frozen=True)
class SearchCandidateAudit:
    candidate: str
    outcome: Literal[
        'new_candidate',
        'overlap',
        'excluded',
        'invalid_path',
        'existing_code_candidate',
        'accepted_new',
        'accepted_overlap',
        'missing',
        'invalid',
        'no_signal',
    ]


@dataclass(frozen=True)
class CodeQueryDiagnostics:
    search: GitHubSearchDiagnostics
    candidates: tuple[SearchCandidateAudit, ...] = ()


@dataclass(frozen=True)
class RepositoryQueryDiagnostics:
    search: GitHubSearchDiagnostics
    considered_count: int
    accepted_count: int
    existing_candidate_count: int
    excluded_count: int
    missing_pyproject_count: int
    invalid_pyproject_count: int
    no_signal_count: int
    candidates: tuple[SearchCandidateAudit, ...] = ()


@dataclass(frozen=True)
class RepositoryDiscoveryResult:
    candidates: list[GitHubSearchResultItem]
    projects: dict[tuple[str, str], PyProjectTOML]
    diagnostics: list[RepositoryQueryDiagnostics]


class OasisURLs(Enum):
    CENTRAL = (
        'https://gitlab.mpcdf.mpg.de/nomad-lab/nomad-distro/-/raw/main/requirements.txt'
    )
    EXAMPLE = (
        'https://gitlab.mpcdf.mpg.de/nomad-lab/nomad-distro/-/raw/'
        'test-oasis/requirements.txt'
    )


# The following repositories are not actual plugins.
EXCLUDED_REPOS = {
    'nomad-coe/nomad',
    'FAIRmat-NFDI/cookiecutter-nomad-plugin',
    'FAIRmat-NFDI/pynxtools-plugin-template',
}


async def fetch_nomad_deployment_requirements(
    requirements_url: str,
) -> set[str]:
    """Fetch package names from a NOMAD deployment requirements file."""
    response = await fetch_page_async(requirements_url)
    if response:
        return {
            dependency_name
            for line in response.text.splitlines()[2:]
            if line.strip() and not line.lstrip().startswith('#')
            if (dependency_name := parse_requirement_name(line)) is not None
        }
    return set()


async def get_toml_project(
    search_result: GitHubSearchResultItem,
    github_client: GitHubClient,
) -> PyProjectTOML | None:
    """Fetch and parse a pyproject found by GitHub code search."""
    try:
        project_path_from_pyproject_path(search_result.path)
    except PyProjectError:
        return None

    content = await github_client.fetch_text(str(search_result.url))
    try:
        return parse_pyproject(content, pyproject_path=search_result.path)
    except PyProjectError as exc:
        click.echo(f'Failed to parse pyproject.toml from {search_result.url}: {exc}')
        return None


async def package_exists_on_pypi(package_name: str) -> bool:
    """Return whether PyPI currently has a project with this name."""
    async with httpx.AsyncClient() as client:
        try:
            url = f'https://pypi.org/pypi/{package_name}/json'
            response = await client.head(url)
            return response.status_code == 200  # noqa: PLR2004
        except httpx.RequestError:
            return False


async def get_plugin(  # noqa: PLR0913
    *,
    item: GitHubSearchResultItem,
    github_client: GitHubClient,
    repository: GitHubRepositoryDetails,
    central_plugins: set[str],
    example_oasis_plugins: set[str],
    project: PyProjectTOML | None = None,
) -> Plugin | None:
    """Build one public plugin record from a discovered pyproject."""
    if project is None:
        project = await get_toml_project(item, github_client)
    if project is None:
        return None

    name = project.name
    on_pypi = await package_exists_on_pypi(name)
    entrypoints = project.entry_points.nomad_plugin if project.entry_points else []
    dependencies = normalize_dependencies(project.all_dependencies or set())
    repository_url = str(item.repository.html_url)
    project_kind = classify_project(
        name=name,
        description=project.description or '',
        repository_url=repository_url,
        project_path=project.project_path,
        dependencies=dependencies,
        has_entrypoints=bool(entrypoints),
    )

    return Plugin(
        id=stable_plugin_id(repository_url, project.project_path),
        name=name,
        description=project.description or '',
        repository_url=item.repository.html_url,
        documentation_url=project.urls.documentation,
        pypi_url=f'https://pypi.org/project/{name}/' if on_pypi else None,
        owner=repository.owner.login,
        owner_type=repository.owner.type,
        entrypoints=entrypoints,
        plugin_types=derive_plugin_types(entrypoint.type for entrypoint in entrypoints),
        dependencies=dependencies,
        status=RepositoryStatus(
            archived=repository.archived,
            fork=repository.fork,
            stars=repository.stargazers_count,
            created_at=repository.created_at,
            last_pushed_at=repository.pushed_at,
            default_branch=repository.default_branch,
            parent_repository_url=(
                repository.parent.html_url if repository.parent else None
            ),
            source_repository_url=(
                repository.source.html_url if repository.source else None
            ),
        ),
        deployment=DeploymentInfo(
            on_central=name in central_plugins,
            on_example_oasis=name in example_oasis_plugins,
        ),
        project_kind=project_kind,
        registry_visible=is_registry_visible(
            project_kind,
            archived=repository.archived,
            fork=repository.fork,
        ),
        metadata_source='pyproject.toml',
        discovery_warnings=sorted_unique(project.parsing_warnings),
        project_path=project.project_path,
        declared_repository_url=project.urls.repository,
        homepage_url=project.urls.homepage,
        issues_url=project.urls.issues,
        authors=project.authors or [],
        maintainers=project.maintainers or [],
    )


async def fetch_page_async(
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
) -> httpx.Response | None:
    """Fetch a non-GitHub page used by the current enrichment logic."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response
        except (httpx.HTTPStatusError, httpx.RequestError):
            return None


async def find_plugins(
    token: str,
    *,
    config: CatalogueConfig | None = None,
    github_client: GitHubClient | None = None,
) -> CrawlResult:
    """Find NOMAD projects with the configured code and repository searches."""
    catalogue_config = config or load_catalogue_config()
    if github_client is not None:
        return await _find_plugins(github_client, catalogue_config)

    async with GitHubClient(token) as client:
        return await _find_plugins(client, catalogue_config)


async def discover_code_search_candidates(
    github_client: GitHubClient,
    config: CatalogueConfig,
) -> tuple[list[GitHubSearchResultItem], list[CodeQueryDiagnostics]]:
    candidates: dict[tuple[str, str], GitHubSearchResultItem] = {}
    diagnostics: list[CodeQueryDiagnostics] = []
    excluded_repositories = {repository.casefold() for repository in EXCLUDED_REPOS}

    for query in config.github.code_search_queries:
        try:
            result = await github_client.search_code(
                query,
                request_delay_seconds=config.github.code_search_request_delay_seconds,
            )
        except GitHubSearchIncompleteError:
            raise
        except GitHubError as exc:
            raise GitHubError(
                f'GitHub code search failed for query {query!r}: {exc}'
            ) from exc
        candidate_audit: list[SearchCandidateAudit] = []
        for item in result.items:
            if item.repository.full_name.casefold() in excluded_repositories:
                candidate_audit.append(
                    SearchCandidateAudit(
                        candidate=stable_plugin_id(str(item.repository.html_url)),
                        outcome='excluded',
                    )
                )
                continue
            try:
                key = code_search_candidate_key(item)
            except PyProjectError:
                candidate_audit.append(
                    SearchCandidateAudit(
                        candidate=str(item.url), outcome='invalid_path'
                    )
                )
                continue
            candidate_id = stable_plugin_id(str(item.repository.html_url), key[1])
            candidate_audit.append(
                SearchCandidateAudit(
                    candidate=candidate_id,
                    outcome='overlap' if key in candidates else 'new_candidate',
                )
            )
            candidates.setdefault(key, item)
        diagnostics.append(
            CodeQueryDiagnostics(
                search=result.diagnostics,
                candidates=tuple(candidate_audit),
            )
        )

    return (
        [candidates[key] for key in sorted(candidates)],
        diagnostics,
    )


def code_search_candidate_key(item: GitHubSearchResultItem) -> tuple[str, str]:
    project_path = project_path_from_pyproject_path(item.path)
    return (item.repository.full_name.casefold(), project_path or '')


async def probe_repository_project(
    github_client: GitHubClient,
    repository_name: str,
) -> tuple[PyProjectTOML | None, str]:
    try:
        content = await github_client.fetch_root_pyproject(repository_name)
    except GitHubError as exc:
        raise GitHubError(
            f'Root pyproject probe failed for repository {repository_name!r}: {exc}'
        ) from exc
    if content is None:
        return None, 'missing'
    try:
        project = parse_pyproject(content)
    except PyProjectError as exc:
        click.echo(f'Invalid root pyproject.toml in {repository_name}: {exc}', err=True)
        return None, 'invalid'
    if not has_nomad_ecosystem_signal(project):
        return None, 'no_signal'
    return project, 'accepted'


async def discover_repository_search_candidates(
    github_client: GitHubClient,
    config: CatalogueConfig,
    code_candidates: list[GitHubSearchResultItem],
) -> RepositoryDiscoveryResult:
    """Probe new roots once and report outcomes for each overlapping query."""
    existing_keys = {code_search_candidate_key(item) for item in code_candidates}
    excluded = {name.casefold() for name in EXCLUDED_REPOS}
    candidates: dict[tuple[str, str], GitHubSearchResultItem] = {}
    projects: dict[tuple[str, str], PyProjectTOML] = {}
    probes: dict[str, tuple[PyProjectTOML | None, str]] = {}
    diagnostics: list[RepositoryQueryDiagnostics] = []

    for query in config.github.repository_search_queries:
        try:
            result = await github_client.search_repositories(
                query,
                candidate_limit=config.github.repository_search_candidate_limit,
                request_delay_seconds=(
                    config.github.repository_search_request_delay_seconds
                ),
            )
        except GitHubSearchIncompleteError:
            raise
        except GitHubError as exc:
            raise GitHubError(
                f'GitHub repository search failed for query {query!r}: {exc}'
            ) from exc

        outcomes: Counter[str] = Counter()
        candidate_audit: list[SearchCandidateAudit] = []
        for repository in result.items:
            name = repository.full_name.casefold()
            key = (name, '')
            candidate_id = stable_plugin_id(str(repository.html_url))
            if name in excluded:
                outcomes['excluded'] += 1
                candidate_audit.append(SearchCandidateAudit(candidate_id, 'excluded'))
                continue
            if key in existing_keys:
                outcomes['existing'] += 1
                candidate_audit.append(
                    SearchCandidateAudit(candidate_id, 'existing_code_candidate')
                )
                continue
            if name not in probes:
                probes[name] = await probe_repository_project(
                    github_client, repository.full_name
                )
            project, outcome = probes[name]
            outcomes[outcome] += 1
            if project is not None:
                candidate_audit.append(
                    SearchCandidateAudit(
                        candidate_id,
                        'accepted_overlap' if key in candidates else 'accepted_new',
                    )
                )
                candidates.setdefault(
                    key,
                    GitHubSearchResultItem(
                        path='pyproject.toml',
                        url=(
                            f'{github_client.base_url}/repos/{repository.full_name}'
                            '/contents/pyproject.toml'
                        ),
                        repository=repository,
                    ),
                )
                projects[key] = project
            else:
                candidate_audit.append(SearchCandidateAudit(candidate_id, outcome))

        diagnostics.append(
            RepositoryQueryDiagnostics(
                search=result.diagnostics,
                considered_count=len(result.items),
                accepted_count=outcomes['accepted'],
                existing_candidate_count=outcomes['existing'],
                excluded_count=outcomes['excluded'],
                missing_pyproject_count=outcomes['missing'],
                invalid_pyproject_count=outcomes['invalid'],
                no_signal_count=outcomes['no_signal'],
                candidates=tuple(candidate_audit),
            )
        )

    return RepositoryDiscoveryResult(
        candidates=[candidates[key] for key in sorted(candidates)],
        projects=projects,
        diagnostics=diagnostics,
    )


async def _find_plugins(
    github_client: GitHubClient,
    config: CatalogueConfig,
) -> CrawlResult:
    example_task = fetch_nomad_deployment_requirements(OasisURLs.EXAMPLE.value)
    central_task = fetch_nomad_deployment_requirements(OasisURLs.CENTRAL.value)
    search_task = discover_code_search_candidates(github_client, config)
    example_oasis_plugins, central_plugins, search_data = await asyncio.gather(
        example_task,
        central_task,
        search_task,
    )
    search_items, search_diagnostics = search_data
    repository_discovery = await discover_repository_search_candidates(
        github_client, config, search_items
    )
    candidates = {
        code_search_candidate_key(item): item
        for item in [*search_items, *repository_discovery.candidates]
    }
    search_items = [candidates[key] for key in sorted(candidates)]
    repository_names = {
        item.repository.full_name.casefold(): item.repository.full_name
        for item in search_items
    }
    repository_details = await asyncio.gather(
        *(
            github_client.fetch_repository(repository_names[key])
            for key in sorted(repository_names)
        )
    )
    repositories = dict(zip(sorted(repository_names), repository_details, strict=True))

    tasks = [
        get_plugin(
            item=item,
            github_client=github_client,
            repository=repositories[item.repository.full_name.casefold()],
            central_plugins=central_plugins,
            example_oasis_plugins=example_oasis_plugins,
            project=repository_discovery.projects.get(code_search_candidate_key(item)),
        )
        for item in search_items
    ]

    plugins: dict[str, Plugin] = {}
    with click.progressbar(
        length=len(tasks),
        label='Fetching individual plugin data',
    ) as bar:
        for future in asyncio.as_completed(tasks):
            plugin = await future
            if plugin:
                plugins[plugin.id] = plugin
            bar.update(1)

    return CrawlResult(
        plugins=[plugins[plugin_id] for plugin_id in sorted(plugins)],
        search_diagnostics=search_diagnostics,
        unique_candidate_count=len(search_items),
        repository_search_diagnostics=repository_discovery.diagnostics,
    )
