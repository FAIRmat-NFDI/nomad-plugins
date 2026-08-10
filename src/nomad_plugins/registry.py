from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SNAPSHOT_PATH = REPOSITORY_ROOT / 'plugin-registry.json'
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / 'plugin_registry_config.json'
SCHEMA_VERSION = 2


@dataclass(frozen=True)
class RegistrySnapshot:
    schema_version: int
    data_updated_at: str | None
    plugins: list[RegistryPlugin]


@dataclass(frozen=True)
class RegistryPlugin:
    id: str
    name: str
    project_kind: str
    registry_visible: bool
    discovery_warnings: list[str]


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    with path.open() as config_file:
        config = json.load(config_file)

    github = require_mapping(config, 'github', 'config')
    search_queries = require_string_list(github, 'searchQueries', 'github')
    repository_search_queries = optional_string_list(
        github,
        'repositorySearchQueries',
        'github',
    )
    exclude_candidates = require_string_list(github, 'excludeCandidates', 'github')
    exclude_documentation_urls = optional_string_list(
        github,
        'excludeDocumentationUrls',
        'github',
    )
    exclude_pypi_urls = optional_string_list(
        github,
        'excludePypiUrls',
        'github',
    )
    official_template_repositories = optional_mapping_list(
        github,
        'officialTemplateRepositories',
        'github',
    )
    official_software_repositories = optional_mapping_list(
        github,
        'officialSoftwareRepositories',
        'github',
    )
    exclude_forks = github.get('excludeForks', False)
    max_repository_candidates = github.get('maxRepositoryCandidates')

    if len(search_queries) == 0:
        raise ValueError('github.searchQueries must contain at least one query.')

    if any(query.strip() == '' for query in repository_search_queries):
        raise ValueError(
            'github.repositorySearchQueries must not contain empty values.'
        )

    if any(candidate.strip() == '' for candidate in exclude_candidates):
        raise ValueError('github.excludeCandidates must not contain empty values.')

    if any(url.strip() == '' for url in exclude_documentation_urls):
        raise ValueError(
            'github.excludeDocumentationUrls must not contain empty values.'
        )

    if any(url.strip() == '' for url in exclude_pypi_urls):
        raise ValueError('github.excludePypiUrls must not contain empty values.')

    for index, repository in enumerate(official_template_repositories):
        context = f'github.officialTemplateRepositories[{index}]'
        require_string(repository, 'repository', context, allow_empty=False)
        require_string(repository, 'name', context, allow_empty=False)
        require_string(repository, 'description', context)

    for index, repository in enumerate(official_software_repositories):
        context = f'github.officialSoftwareRepositories[{index}]'
        require_string(repository, 'repository', context, allow_empty=False)
        require_string(repository, 'name', context, allow_empty=False)
        require_string(repository, 'description', context)

    if not isinstance(exclude_forks, bool):
        raise ValueError('github.excludeForks must be a boolean.')

    if max_repository_candidates is not None and (
        not isinstance(max_repository_candidates, int)
        or isinstance(max_repository_candidates, bool)
        or max_repository_candidates <= 0
    ):
        raise ValueError('github.maxRepositoryCandidates must be a positive integer.')

    quality = require_mapping(config, 'quality', 'config')
    minimum_plugin_count = require_int(quality, 'minimumPluginCount', 'quality')

    if minimum_plugin_count < 0:
        raise ValueError('quality.minimumPluginCount must be non-negative.')

    return config


def load_snapshot(path: Path = DEFAULT_SNAPSHOT_PATH) -> RegistrySnapshot:
    return validate_snapshot_data(load_snapshot_data(path))


def load_snapshot_data(path: Path = DEFAULT_SNAPSHOT_PATH) -> dict[str, Any]:
    with path.open() as snapshot_file:
        data = json.load(snapshot_file)

    return require_mapping(data, 'snapshot')


def validate_snapshot_data(snapshot: dict[str, Any]) -> RegistrySnapshot:
    schema_version = require_int(snapshot, 'schemaVersion', 'snapshot')

    if schema_version != SCHEMA_VERSION:
        raise ValueError(f'Unsupported schema version {schema_version}.')

    data_updated_at = optional_string(snapshot, 'dataUpdatedAt', 'snapshot')
    if data_updated_at is not None:
        require_iso_date(data_updated_at, 'snapshot.dataUpdatedAt')

    source_summary = require_mapping(snapshot, 'sourceSummary', 'snapshot')
    require_string(source_summary, 'discovery', 'sourceSummary', allow_empty=False)
    expected_plugin_count = require_int(source_summary, 'pluginCount', 'sourceSummary')
    expected_registry_visible_count = require_int(
        source_summary,
        'registryVisibleCount',
        'sourceSummary',
    )
    project_kind_counts = require_int_mapping(
        source_summary,
        'projectKindCounts',
        'sourceSummary',
    )
    expected_warning_count = require_int(
        source_summary, 'warningCount', 'sourceSummary'
    )

    plugins_data = require_list(snapshot, 'plugins', 'snapshot')
    plugins = [
        validate_plugin(plugin_data, f'plugins[{index}]')
        for index, plugin_data in enumerate(plugins_data)
    ]

    if expected_plugin_count != len(plugins):
        raise ValueError(
            f'sourceSummary.pluginCount is {expected_plugin_count}, '
            f'but {len(plugins)} plugins were found.',
        )

    registry_visible_count = sum(1 for plugin in plugins if plugin.registry_visible)
    if expected_registry_visible_count != registry_visible_count:
        raise ValueError(
            f'sourceSummary.registryVisibleCount is {expected_registry_visible_count}, '
            f'but {registry_visible_count} registry-visible plugins were found.',
        )

    actual_project_kind_counts: dict[str, int] = {}
    for plugin in plugins:
        actual_project_kind_counts[plugin.project_kind] = (
            actual_project_kind_counts.get(plugin.project_kind, 0) + 1
        )
    if project_kind_counts != actual_project_kind_counts:
        raise ValueError(
            'sourceSummary.projectKindCounts does not match plugin projectKind values.'
        )

    warning_count = sum(len(plugin.discovery_warnings) for plugin in plugins)
    if expected_warning_count != warning_count:
        raise ValueError(
            f'sourceSummary.warningCount is {expected_warning_count}, '
            f'but {warning_count} warnings were found.',
        )

    ensure_unique([plugin.id for plugin in plugins], 'plugin id')

    return RegistrySnapshot(
        schema_version=schema_version,
        data_updated_at=data_updated_at,
        plugins=plugins,
    )


def write_snapshot(
    snapshot: dict[str, Any], output_path: Path = DEFAULT_SNAPSHOT_PATH
) -> RegistrySnapshot:
    validated_snapshot = validate_snapshot_data(snapshot)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            'w',
            delete=False,
            dir=output_path.parent,
            encoding='utf-8',
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(snapshot, temporary_file, indent=2)
            temporary_file.write('\n')

        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return validated_snapshot


def validate_plugin(plugin_data: Any, context: str) -> RegistryPlugin:
    plugin = require_mapping(plugin_data, context)

    plugin_id = require_string(plugin, 'id', context, allow_empty=False)
    name = require_string(plugin, 'name', context, allow_empty=False)
    require_string(plugin, 'description', context)
    require_http_url(plugin, 'repositoryUrl', context)
    optional_http_url(plugin, 'documentationUrl', context)
    optional_http_url(plugin, 'pypiUrl', context)
    require_string(plugin, 'owner', context, allow_empty=False)
    optional_string(plugin, 'ownerType', context)
    optional_string(plugin, 'ownerGroup', context)

    entrypoints = require_list(plugin, 'entrypoints', context)
    for index, entrypoint in enumerate(entrypoints):
        validate_entrypoint(entrypoint, f'{context}.entrypoints[{index}]')

    nullable_string_list(plugin, 'pluginTypes', context)
    require_string_list(plugin, 'dependencies', context)
    validate_status(require_mapping(plugin, 'status', context), f'{context}.status')
    validate_deployment(
        require_mapping(plugin, 'deployment', context), f'{context}.deployment'
    )
    project_kind = require_string(plugin, 'projectKind', context, allow_empty=False)
    registry_visible = require_bool(plugin, 'registryVisible', context)
    require_string(plugin, 'metadataSource', context, allow_empty=False)
    discovery_warnings = require_string_list(plugin, 'discoveryWarnings', context)

    return RegistryPlugin(
        id=plugin_id,
        name=name,
        project_kind=project_kind,
        registry_visible=registry_visible,
        discovery_warnings=discovery_warnings,
    )


def validate_entrypoint(entrypoint_data: Any, context: str) -> None:
    entrypoint = require_mapping(entrypoint_data, context)
    require_string(entrypoint, 'name', context, allow_empty=False)
    require_string(entrypoint, 'module', context, allow_empty=False)
    require_string(entrypoint, 'type', context, allow_empty=False)


def validate_status(status: dict[str, Any], context: str) -> None:
    require_bool(status, 'archived', context)
    require_bool(status, 'fork', context)
    optional_int(status, 'stars', context)
    optional_iso_date(status, 'createdAt', context)
    optional_iso_date(status, 'lastPushedAt', context)
    optional_http_url(status, 'parentRepositoryUrl', context)
    optional_http_url(status, 'sourceRepositoryUrl', context)


def validate_deployment(deployment: dict[str, Any], context: str) -> None:
    require_bool(deployment, 'onCentral', context)
    require_bool(deployment, 'onExampleOasis', context)


def require_mapping(data: Any, key: str, context: str | None = None) -> dict[str, Any]:
    value = data if context is None else data.get(key)
    label = key if context is None else f'{context}.{key}'

    if not isinstance(value, dict):
        raise ValueError(f'{label} must be an object.')

    return value


def require_list(data: dict[str, Any], key: str, context: str) -> list[Any]:
    value = data.get(key)

    if not isinstance(value, list):
        raise ValueError(f'{context}.{key} must be a list.')

    return value


def require_string(
    data: dict[str, Any],
    key: str,
    context: str,
    *,
    allow_empty: bool = True,
) -> str:
    value = data.get(key)

    if not isinstance(value, str):
        raise ValueError(f'{context}.{key} must be a string.')

    if not allow_empty and len(value.strip()) == 0:
        raise ValueError(f'{context}.{key} must not be empty.')

    return value


def optional_string(data: dict[str, Any], key: str, context: str) -> str | None:
    value = data.get(key)

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f'{context}.{key} must be a string when present.')

    return value


def require_string_list(data: dict[str, Any], key: str, context: str) -> list[str]:
    values = require_list(data, key, context)

    if not all(isinstance(value, str) for value in values):
        raise ValueError(f'{context}.{key} must contain only strings.')

    return values


def require_int_mapping(data: dict[str, Any], key: str, context: str) -> dict[str, int]:
    value = require_mapping(data, key, context)
    int_mapping: dict[str, int] = {}

    for item_key, item_value in value.items():
        if not isinstance(item_key, str) or item_key.strip() == '':
            raise ValueError(f'{context}.{key} keys must be non-empty strings.')
        if (
            not isinstance(item_value, int)
            or isinstance(item_value, bool)
            or item_value < 0
        ):
            raise ValueError(
                f'{context}.{key}.{item_key} must be a non-negative integer.'
            )

        int_mapping[item_key] = item_value

    return int_mapping


def optional_string_list(data: dict[str, Any], key: str, context: str) -> list[str]:
    value = data.get(key, [])

    if not isinstance(value, list):
        raise ValueError(f'{context}.{key} must be a list when present.')

    if not all(isinstance(item, str) for item in value):
        raise ValueError(f'{context}.{key} must contain only strings.')

    return value


def nullable_string_list(
    data: dict[str, Any], key: str, context: str
) -> list[str] | None:
    value = data.get(key)

    if value is None:
        return None

    if not isinstance(value, list):
        raise ValueError(f'{context}.{key} must be a list or null.')

    if not all(isinstance(item, str) for item in value):
        raise ValueError(f'{context}.{key} must contain only strings.')

    return value


def optional_mapping_list(
    data: dict[str, Any], key: str, context: str
) -> list[dict[str, Any]]:
    values = data.get(key, [])

    if not isinstance(values, list):
        raise ValueError(f'{context}.{key} must be a list when present.')

    result: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise ValueError(f'{context}.{key}[{index}] must be an object.')

        result.append(value)

    return result


def require_bool(data: dict[str, Any], key: str, context: str) -> bool:
    value = data.get(key)

    if not isinstance(value, bool):
        raise ValueError(f'{context}.{key} must be a boolean.')

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


def require_http_url(data: dict[str, Any], key: str, context: str) -> str:
    value = require_string(data, key, context, allow_empty=False)
    validate_http_url(value, f'{context}.{key}')
    return value


def optional_http_url(data: dict[str, Any], key: str, context: str) -> str | None:
    value = optional_string(data, key, context)

    if value is not None:
        validate_http_url(value, f'{context}.{key}')

    return value


def validate_http_url(value: str, context: str) -> None:
    parsed_url = urlparse(value)

    if parsed_url.scheme not in {'http', 'https'} or not parsed_url.netloc:
        raise ValueError(f'{context} must be an http(s) URL.')


def require_iso_date(value: str, context: str) -> None:
    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise ValueError(f'{context} must be an ISO 8601 date.') from error


def optional_iso_date(data: dict[str, Any], key: str, context: str) -> str | None:
    value = optional_string(data, key, context)

    if value is not None:
        require_iso_date(value, f'{context}.{key}')

    return value


def ensure_unique(values: list[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)

    if duplicates:
        duplicate_list = ', '.join(sorted(duplicates))
        raise ValueError(f'Duplicate {label} values found: {duplicate_list}.')
