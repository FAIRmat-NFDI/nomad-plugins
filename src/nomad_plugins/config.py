import json
from importlib.resources import files
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PRIMARY_CODE_SEARCH_QUERY = 'nomad.plugin in:file filename:pyproject.toml'
DEFAULT_CONFIG_RESOURCE = 'plugin_catalogue_config.json'
DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS = 6.5


class GitHubDiscoveryConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    code_search_queries: list[str] = Field(alias='codeSearchQueries', min_length=1)
    code_search_request_delay_seconds: float = Field(
        default=DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS,
        alias='codeSearchRequestDelaySeconds',
        ge=0,
    )

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

    @field_validator('code_search_request_delay_seconds', mode='before')
    @classmethod
    def validate_request_delay(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(
                'github.codeSearchRequestDelaySeconds must be a non-negative number.'
            )
        return value

    @model_validator(mode='after')
    def require_primary_query_first(self) -> 'GitHubDiscoveryConfig':
        if self.code_search_queries[0] != PRIMARY_CODE_SEARCH_QUERY:
            raise ValueError(
                'github.codeSearchQueries must begin with the primary nomad.plugin '
                'query.'
            )
        return self


class CatalogueConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra='forbid')

    github: GitHubDiscoveryConfig


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
