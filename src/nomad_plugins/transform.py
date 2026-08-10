from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .capabilities import normalize_plugin_type
from .registry import SCHEMA_VERSION, validate_snapshot_data

PROJECT_KIND_PLUGIN = 'plugin'
PROJECT_KIND_ECOSYSTEM_PACKAGE = 'ecosystem_package'
PROJECT_KIND_NOMAD_DEPENDENT_PACKAGE = 'nomad_dependent_package'
PROJECT_KIND_DISTRIBUTION = 'distribution'
PROJECT_KIND_OFFICIAL_SOFTWARE = 'official_software'
PROJECT_KIND_OFFICIAL_TEMPLATE = 'official_template'
PROJECT_KIND_TEMPLATE_OR_EXAMPLE = 'template_or_example'
LEGACY_PLUGIN_TYPE_NAMES = {
    'app': 'App',
    'schema': 'Schema package',
    'normalizer': 'Normalizer',
    'parser': 'Parser',
    'example_upload': 'Example upload',
    'api': 'API',
}


@dataclass(frozen=True)
class DiscoveredEntrypoint:
    name: str
    module: str
    type: str


@dataclass(frozen=True)
class DiscoveredStatus:
    archived: bool = False
    fork: bool = False
    stars: int | None = None
    created_at: str | None = None
    last_pushed_at: str | None = None
    parent_repository_url: str | None = None
    source_repository_url: str | None = None


@dataclass(frozen=True)
class DiscoveredDeployment:
    on_central: bool = False
    on_example_oasis: bool = False


@dataclass(frozen=True)
class DiscoveredAuthor:
    name: str | None = None
    email: str | None = None


@dataclass(frozen=True)
class DiscoveredPlugin:
    name: str
    repository_url: str
    metadata_source: str
    description: str = ''
    project_path: str | None = None
    documentation_url: str | None = None
    pypi_url: str | None = None
    owner: str | None = None
    owner_type: str | None = None
    owner_group: str | None = None
    entrypoints: list[DiscoveredEntrypoint] = field(default_factory=list)
    plugin_types: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    authors: list[DiscoveredAuthor] = field(default_factory=list)
    maintainers: list[DiscoveredAuthor] = field(default_factory=list)
    on_pypi: bool = False
    status: DiscoveredStatus = field(default_factory=DiscoveredStatus)
    deployment: DiscoveredDeployment = field(default_factory=DiscoveredDeployment)
    project_kind: str = PROJECT_KIND_PLUGIN
    registry_visible: bool = True
    discovery_warnings: list[str] = field(default_factory=list)


def build_registry_snapshot(
    discovered_plugins: list[DiscoveredPlugin],
    *,
    data_updated_at: str,
    discovery: str,
) -> dict[str, Any]:
    plugins = [plugin_to_registry_data(plugin) for plugin in discovered_plugins]
    plugins.sort(key=lambda plugin: (plugin['name'].casefold(), plugin['id']))
    warning_count = sum(len(plugin['discoveryWarnings']) for plugin in plugins)
    registry_visible_count = sum(1 for plugin in plugins if plugin['registryVisible'])

    snapshot = {
        'schemaVersion': SCHEMA_VERSION,
        'dataUpdatedAt': data_updated_at,
        'sourceSummary': {
            'discovery': discovery,
            'pluginCount': len(plugins),
            'registryVisibleCount': registry_visible_count,
            'projectKindCounts': project_kind_counts(plugins),
            'warningCount': warning_count,
        },
        'plugins': plugins,
    }
    validate_snapshot_data(snapshot)

    return snapshot


def plugin_to_registry_data(plugin: DiscoveredPlugin) -> dict[str, Any]:
    data = {
        'id': stable_plugin_id(plugin.repository_url, plugin.project_path),
        'name': plugin.name.strip(),
        'description': plugin.description.strip(),
        'repositoryUrl': plugin.repository_url.strip(),
        'owner': owner_from_plugin(plugin),
        'entrypoints': [
            {
                'name': entrypoint.name.strip(),
                'module': entrypoint.module.strip(),
                'type': entrypoint.type.strip(),
            }
            for entrypoint in sorted(
                plugin.entrypoints,
                key=lambda entrypoint: (
                    entrypoint.type.casefold(),
                    entrypoint.name.casefold(),
                    entrypoint.module.casefold(),
                ),
            )
        ],
        'pluginTypes': plugin_types(plugin),
        'dependencies': normalize_dependencies(plugin.dependencies),
        'status': status_data(plugin.status),
        'deployment': {
            'onCentral': plugin.deployment.on_central,
            'onExampleOasis': plugin.deployment.on_example_oasis,
        },
        'projectKind': plugin.project_kind,
        'registryVisible': plugin.registry_visible,
        'metadataSource': plugin.metadata_source.strip(),
        'discoveryWarnings': sorted_unique(plugin.discovery_warnings),
    }

    optional_fields = {
        'documentationUrl': plugin.documentation_url,
        'pypiUrl': plugin.pypi_url,
        'ownerType': plugin.owner_type,
        'ownerGroup': plugin.owner_group,
    }
    for key, value in optional_fields.items():
        cleaned_value = clean_optional_string(value)
        if cleaned_value is not None:
            data[key] = cleaned_value

    return data


def stable_plugin_id(repository_url: str, project_path: str | None = None) -> str:
    parsed_url = urlparse(repository_url.strip())
    repository_path = parsed_url.path.strip('/')

    if repository_path.endswith('.git'):
        repository_path = repository_path[:-4]

    base_id = f'{parsed_url.netloc.lower()}/{repository_path}'.lower()
    normalized_project_path = normalize_project_path(project_path)

    if normalized_project_path is None:
        return base_id

    return f'{base_id}#{normalized_project_path}'


def owner_from_plugin(plugin: DiscoveredPlugin) -> str:
    owner = clean_optional_string(plugin.owner)

    if owner is not None:
        return owner

    parsed_url = urlparse(plugin.repository_url.strip())
    repository_parts = [part for part in parsed_url.path.split('/') if part]

    if repository_parts:
        return repository_parts[0]

    return parsed_url.netloc


def plugin_types(plugin: DiscoveredPlugin) -> list[str] | None:
    explicit_types = plugin.plugin_types
    entrypoint_types = [entrypoint.type for entrypoint in plugin.entrypoints]
    if len(explicit_types) == 0 and len(entrypoint_types) == 0:
        return None

    return sorted_unique(
        [
            normalize_plugin_type(plugin_type)
            for plugin_type in [*explicit_types, *entrypoint_types]
            if normalize_plugin_type(plugin_type) is not None
        ],
    )


def normalize_dependencies(dependencies: list[str]) -> list[str]:
    normalized_dependencies = [
        re.sub(r'[-_.]+', '-', dependency.strip().lower())
        for dependency in dependencies
        if dependency.strip() != ''
    ]

    return sorted_unique(normalized_dependencies)


def status_data(status: DiscoveredStatus) -> dict[str, Any]:
    data: dict[str, Any] = {
        'archived': status.archived,
        'fork': status.fork,
    }

    optional_fields = {
        'stars': status.stars,
        'createdAt': status.created_at,
        'lastPushedAt': status.last_pushed_at,
        'parentRepositoryUrl': status.parent_repository_url,
        'sourceRepositoryUrl': status.source_repository_url,
    }
    for key, value in optional_fields.items():
        if value is not None:
            data[key] = value

    return data


def project_kind_counts(plugins: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}

    for plugin in plugins:
        project_kind = plugin['projectKind']
        counts[project_kind] = counts.get(project_kind, 0) + 1

    return {
        project_kind: counts[project_kind]
        for project_kind in sorted(counts, key=str.casefold)
    }


def normalize_project_path(project_path: str | None) -> str | None:
    cleaned_path = clean_optional_string(project_path)

    if cleaned_path is None:
        return None

    path_parts = [
        part
        for part in cleaned_path.replace('\\', '/').split('/')
        if part not in {'', '.'}
    ]

    if not path_parts:
        return None

    return '/'.join(path_parts)


def clean_optional_string(value: str | None) -> str | None:
    if value is None:
        return None

    cleaned_value = value.strip()

    if cleaned_value == '':
        return None

    return cleaned_value


def sorted_unique(values: list[str]) -> list[str]:
    return sorted(set(values), key=str.casefold)


def snapshot_to_legacy_plugin_data(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    plugins = snapshot.get('plugins', [])
    if not isinstance(plugins, list):
        raise ValueError('snapshot.plugins must be a list.')

    return [
        {'data': legacy_plugin_data(plugin)}
        for plugin in plugins
        if isinstance(plugin, dict) and should_include_legacy_plugin(plugin)
    ]


def discovered_plugins_to_legacy_plugin_data(
    plugins: list[DiscoveredPlugin],
) -> list[dict[str, Any]]:
    plugins_by_name = {
        normalize_dependency_name(plugin.name): plugin
        for plugin in plugins
        if len(plugin.entrypoints) > 0
    }

    return [
        {'data': discovered_plugin_to_legacy_plugin_data(plugin, plugins_by_name)}
        for plugin in plugins
        if len(plugin.entrypoints) > 0
    ]


def discovered_plugin_to_legacy_plugin_data(
    plugin: DiscoveredPlugin,
    plugins_by_name: dict[str, DiscoveredPlugin],
) -> dict[str, Any]:
    return {
        'm_def': 'nomad_plugins.schema_packages.plugin.Plugin',
        'repository': plugin.repository_url,
        'toml_directory': normalize_project_path(plugin.project_path) or '',
        'created': plugin.status.created_at,
        'last_updated': plugin.status.last_pushed_at,
        'stars': plugin.status.stars or 0,
        'owner': owner_from_plugin(plugin),
        'name': plugin.name,
        'description': plugin.description,
        'authors': legacy_authors(plugin.authors),
        'maintainers': legacy_authors(plugin.maintainers),
        'on_central': plugin.deployment.on_central,
        'on_example_oasis': plugin.deployment.on_example_oasis,
        'on_pypi': plugin.on_pypi,
        'plugin_entry_points': legacy_discovered_entrypoints(plugin.entrypoints),
        'plugin_dependencies': legacy_discovered_plugin_dependencies(
            plugin.dependencies,
            plugins_by_name,
        ),
    }


def should_include_legacy_plugin(plugin: dict[str, Any]) -> bool:
    entrypoints = plugin.get('entrypoints')
    return isinstance(entrypoints, list) and len(entrypoints) > 0


def legacy_plugin_data(plugin: dict[str, Any]) -> dict[str, Any]:
    status = plugin.get('status')
    deployment = plugin.get('deployment')
    if not isinstance(status, dict):
        status = {}
    if not isinstance(deployment, dict):
        deployment = {}

    return {
        'm_def': 'nomad_plugins.schema_packages.plugin.Plugin',
        'repository': plugin['repositoryUrl'],
        'toml_directory': legacy_toml_directory(plugin),
        'created': status.get('createdAt'),
        'last_updated': status.get('lastPushedAt'),
        'stars': status.get('stars') or 0,
        'owner': plugin['owner'],
        'name': plugin['name'],
        'description': plugin.get('description'),
        'on_central': deployment.get('onCentral', False),
        'on_example_oasis': deployment.get('onExampleOasis', False),
        'on_pypi': bool(plugin.get('pypiUrl')),
        'plugin_entry_points': legacy_entrypoints(plugin.get('entrypoints', [])),
        'plugin_dependencies': legacy_plugin_dependencies(
            plugin.get('dependencies', []),
        ),
    }


def legacy_authors(authors: list[DiscoveredAuthor]) -> list[dict[str, Any]]:
    return [
        {
            key: value
            for key, value in {'name': author.name, 'email': author.email}.items()
            if value is not None
        }
        for author in authors
        if author.name is not None or author.email is not None
    ]


def legacy_discovered_entrypoints(
    entrypoints: list[DiscoveredEntrypoint],
) -> list[dict[str, Any]]:
    legacy_data: list[dict[str, Any]] = []
    for entrypoint in entrypoints:
        legacy_type = LEGACY_PLUGIN_TYPE_NAMES.get(entrypoint.type)
        data = {
            'm_def': 'nomad_plugins.schema_packages.plugin.PluginEntryPoint',
            'name': entrypoint.name,
            'module': entrypoint.module,
        }
        if legacy_type is not None:
            data['type'] = legacy_type

        legacy_data.append(data)

    return legacy_data


def legacy_entrypoints(entrypoints: list[Any]) -> list[dict[str, Any]]:
    legacy_data: list[dict[str, Any]] = []
    for entrypoint in entrypoints:
        if not isinstance(entrypoint, dict):
            continue

        legacy_type = LEGACY_PLUGIN_TYPE_NAMES.get(str(entrypoint.get('type', '')))
        data = {
            'm_def': 'nomad_plugins.schema_packages.plugin.PluginEntryPoint',
            'name': entrypoint.get('name'),
            'module': entrypoint.get('module'),
        }
        if legacy_type is not None:
            data['type'] = legacy_type

        legacy_data.append(data)

    return legacy_data


def legacy_toml_directory(plugin: dict[str, Any]) -> str:
    plugin_id = plugin.get('id')
    if not isinstance(plugin_id, str):
        return ''

    _, separator, project_path = plugin_id.partition('#')
    return project_path if separator else ''


def legacy_plugin_dependencies(dependencies: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            'm_def': 'nomad_plugins.schema_packages.plugin.PluginReference',
            'name': dependency,
            'location': f'https://pypi.org/project/{dependency}/',
        }
        for dependency in dependencies
        if isinstance(dependency, str) and dependency != 'nomad-lab'
    ]


def legacy_discovered_plugin_dependencies(
    dependencies: list[str],
    plugins_by_name: dict[str, DiscoveredPlugin],
) -> list[dict[str, Any]]:
    legacy_dependencies: list[dict[str, Any]] = []
    for dependency in normalize_dependencies(dependencies):
        if dependency == 'nomad-lab' or dependency not in plugins_by_name:
            continue

        plugin = plugins_by_name[dependency]
        legacy_dependencies.append(
            {
                'm_def': 'nomad_plugins.schema_packages.plugin.PluginReference',
                'name': dependency,
                'location': plugin.repository_url,
                'toml_directory': normalize_project_path(plugin.project_path) or '',
            },
        )

    return legacy_dependencies


def normalize_dependency_name(name: str) -> str:
    return re.sub(r'[-_.\s]+', '-', name.strip().lower())
