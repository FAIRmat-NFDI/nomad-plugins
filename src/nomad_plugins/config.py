import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from nomad_plugins.transform import normalize_project_path

PRIMARY_CODE_SEARCH_QUERY = 'nomad.plugin in:file filename:pyproject.toml'
DEFAULT_CONFIG_RESOURCE = 'plugin_catalogue_config.json'
DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS = 6.5
DEFAULT_REPOSITORY_SEARCH_REQUEST_DELAY_SECONDS = 2.1
DEFAULT_REPOSITORY_SEARCH_CANDIDATE_LIMIT = 120
OWNER_LOGIN_PATTERN = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z')
REPOSITORY_PATTERN = re.compile(
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]+\Z'
)


def _repository_name(value: str) -> str:
    if not REPOSITORY_PATTERN.fullmatch(value.strip()):
        raise ValueError('Expected a GitHub repository in owner/name form.')
    return value.strip()


class ConfiguredRepository(BaseModel):
    model_config = ConfigDict(extra='forbid')

    repository: str
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)

    @field_validator('repository')
    @classmethod
    def validate_repository(cls, value: str) -> str:
        return _repository_name(value)

    @field_validator('name', 'description')
    @classmethod
    def validate_public_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Official repository text must be non-empty.')
        return value.strip()


class ManualProjectSeed(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    repository: str
    project_path: str | None = Field(default=None, alias='projectPath')

    @field_validator('repository')
    @classmethod
    def validate_repository(cls, value: str) -> str:
        return _repository_name(value)

    @field_validator('project_path')
    @classmethod
    def validate_project_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value.startswith('/') or '\\' in value:
            raise ValueError('Manual project paths must be relative POSIX paths.')
        normalized = normalize_project_path(value)
        if not normalized or '..' in normalized.split('/'):
            raise ValueError('Manual project paths must be non-empty relative paths.')
        return normalized


class CatalogueCurationConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    official_template_repositories: list[ConfiguredRepository] = Field(
        default_factory=list, alias='officialTemplateRepositories'
    )
    official_software_repositories: list[ConfiguredRepository] = Field(
        default_factory=list, alias='officialSoftwareRepositories'
    )
    manual_project_seeds: list[ManualProjectSeed] = Field(
        default_factory=list, alias='manualProjectSeeds'
    )
    exclude_candidates: list[str] = Field(
        default_factory=list, alias='excludeCandidates'
    )
    exclude_documentation_urls: list[HttpUrl] = Field(
        default_factory=list, alias='excludeDocumentationUrls'
    )
    exclude_pypi_urls: list[HttpUrl] = Field(
        default_factory=list, alias='excludePypiUrls'
    )

    @field_validator('exclude_candidates')
    @classmethod
    def validate_exclusions(cls, values: list[str]) -> list[str]:
        normalized = [value.strip().lower() for value in values]
        for value in normalized:
            root, separator, project_path = value.partition('#')
            repository = root.removeprefix('github.com/')
            if not root.startswith('github.com/'):
                raise ValueError('excludeCandidates must contain GitHub catalogue IDs.')
            _repository_name(repository)
            if separator and (
                not project_path
                or project_path.startswith('/')
                or '..' in project_path.split('/')
            ):
                raise ValueError('excludeCandidates contains an invalid project path.')
        if len(set(normalized)) != len(normalized):
            raise ValueError('excludeCandidates must not contain duplicates.')
        return normalized

    @model_validator(mode='after')
    def validate_unique_rows(self) -> 'CatalogueCurationConfig':
        official = [
            row.repository.casefold()
            for row in [
                *self.official_template_repositories,
                *self.official_software_repositories,
            ]
        ]
        if len(set(official)) != len(official):
            raise ValueError('Official repositories must be unique.')
        seeds = [
            (seed.repository.casefold(), (seed.project_path or '').casefold())
            for seed in self.manual_project_seeds
        ]
        if len(set(seeds)) != len(seeds):
            raise ValueError('Manual project seeds must be unique.')
        for repository, project_path in seeds:
            root_id = f'github.com/{repository}'
            seed_id = f'{root_id}#{project_path}' if project_path else root_id
            if seed_id in self.exclude_candidates or root_id in self.exclude_candidates:
                raise ValueError('A manual project seed cannot also be excluded.')
            if not project_path and repository in official:
                raise ValueError('An official root cannot also be a manual seed.')
        for field_name in ('exclude_documentation_urls', 'exclude_pypi_urls'):
            urls = [
                str(url).rstrip('/').casefold() for url in getattr(self, field_name)
            ]
            if len(set(urls)) != len(urls):
                raise ValueError(f'{field_name} must not contain duplicates.')
        return self


class DeploymentSourcesConfig(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True, extra='forbid', validate_default=True
    )

    central_info_url: HttpUrl = Field(
        default='https://nomad-lab.eu/backend/api/v1/info',
        alias='centralInfoUrl',
    )
    example_oasis_info_url: HttpUrl = Field(
        default='https://nomad-lab.eu/prod/v1/oasis/api/v1/info',
        alias='exampleOasisInfoUrl',
    )


class GitHubOwnerSearch(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    login: str
    owner_type: Literal['Organization', 'User'] = Field(alias='ownerType')

    @field_validator('login', mode='before')
    @classmethod
    def validate_login(cls, value: object) -> str:
        if not isinstance(value, str) or not OWNER_LOGIN_PATTERN.fullmatch(
            value.strip()
        ):
            raise ValueError('github.ownerSearches contains an invalid GitHub login.')
        return value.strip()

    @property
    def query(self) -> str:
        qualifier = 'org' if self.owner_type == 'Organization' else 'user'
        return f'{qualifier}:{self.login} nomad in:name,description'


class GitHubDiscoveryConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    code_search_queries: list[str] = Field(alias='codeSearchQueries', min_length=1)
    code_search_request_delay_seconds: float = Field(
        default=DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS,
        alias='codeSearchRequestDelaySeconds',
        ge=0,
    )
    repository_search_queries: list[str] = Field(
        default_factory=list, alias='repositorySearchQueries'
    )
    owner_searches: list[GitHubOwnerSearch] = Field(
        default_factory=list, alias='ownerSearches'
    )
    repository_search_candidate_limit: int = Field(
        default=DEFAULT_REPOSITORY_SEARCH_CANDIDATE_LIMIT,
        alias='repositorySearchCandidateLimit',
        strict=True,
        ge=1,
        le=1000,
    )
    repository_search_request_delay_seconds: float = Field(
        default=DEFAULT_REPOSITORY_SEARCH_REQUEST_DELAY_SECONDS,
        alias='repositorySearchRequestDelaySeconds',
        ge=0,
        allow_inf_nan=False,
    )

    @field_validator('repository_search_queries', mode='before')
    @classmethod
    def validate_repository_queries(cls, value: object) -> object:
        if not isinstance(value, list):
            return value
        if any(not isinstance(query, str) or not query.strip() for query in value):
            raise ValueError(
                'github.repositorySearchQueries must contain only non-empty strings.'
            )
        queries = [query.strip() for query in value]
        if len({query.casefold() for query in queries}) != len(queries):
            raise ValueError(
                'github.repositorySearchQueries must not contain duplicates.'
            )
        return queries

    @field_validator('code_search_queries', mode='before')
    @classmethod
    def validate_queries(cls, value: object) -> object:
        if not isinstance(value, list):
            return value

        queries: list[str] = []
        for query in value:
            if not isinstance(query, str) or not query.strip():
                raise ValueError(
                    'github.codeSearchQueries must contain only non-empty strings.'
                )
            normalized_query = query.strip()
            if 'filename:pyproject.toml' not in normalized_query.casefold():
                raise ValueError(
                    'github.codeSearchQueries supports only pyproject.toml queries.'
                )
            queries.append(normalized_query)

        if len({query.casefold() for query in queries}) != len(queries):
            raise ValueError('github.codeSearchQueries must not contain duplicates.')
        return queries

    @field_validator(
        'code_search_request_delay_seconds',
        'repository_search_request_delay_seconds',
        mode='before',
    )
    @classmethod
    def validate_request_delay(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(
                'GitHub search request delays must be non-negative numbers.'
            )
        return value

    @model_validator(mode='after')
    def require_primary_query_first(self) -> 'GitHubDiscoveryConfig':
        if self.code_search_queries[0] != PRIMARY_CODE_SEARCH_QUERY:
            raise ValueError(
                'github.codeSearchQueries must begin with the primary nomad.plugin '
                'query.'
            )
        owner_logins = [owner.login.casefold() for owner in self.owner_searches]
        if len(set(owner_logins)) != len(owner_logins):
            raise ValueError('github.ownerSearches must not contain duplicate logins.')
        all_queries = [
            *self.repository_search_queries,
            *(owner.query for owner in self.owner_searches),
        ]
        if len({query.casefold() for query in all_queries}) != len(all_queries):
            raise ValueError(
                'github.ownerSearches must not duplicate repositorySearchQueries.'
            )
        return self


class CatalogueConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    github: GitHubDiscoveryConfig
    curation: CatalogueCurationConfig = Field(default_factory=CatalogueCurationConfig)
    deployment_sources: DeploymentSourcesConfig = Field(
        default_factory=DeploymentSourcesConfig, alias='deploymentSources'
    )


def load_catalogue_config(path: Path | None = None) -> CatalogueConfig:
    if path is None:
        content = (
            files('nomad_plugins')
            .joinpath(DEFAULT_CONFIG_RESOURCE)
            .read_text(encoding='utf-8')
        )
    else:
        content = path.read_text(encoding='utf-8')

    return CatalogueConfig.model_validate(json.loads(content))
