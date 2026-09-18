from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal
from urllib.parse import urlparse

PluginType = Literal[
    'schema',
    'parser',
    'normalizer',
    'app',
    'example_upload',
    'api',
    'north_tool',
    'action',
    'dashboard',
    'unknown',
]

ProjectKind = Literal[
    'plugin',
    'nomad_dependent_package',
    'distribution',
    'official_template',
    'official_software',
    'template_or_example',
    'ecosystem_package',
]

VISIBLE_PROJECT_KINDS: frozenset[ProjectKind] = frozenset(
    {
        'plugin',
        'nomad_dependent_package',
        'official_template',
        'official_software',
    }
)

PLUGIN_TYPE_ALIASES: dict[str, PluginType] = {
    'action': 'action',
    'actions': 'action',
    'app': 'app',
    'apps': 'app',
    'application': 'app',
    'api': 'api',
    'apis': 'api',
    'dashboard': 'dashboard',
    'dashboards': 'dashboard',
    'example': 'example_upload',
    'example_upload': 'example_upload',
    'example_uploads': 'example_upload',
    'normalizer': 'normalizer',
    'normalizers': 'normalizer',
    'north_tool': 'north_tool',
    'north_tools': 'north_tool',
    'parser': 'parser',
    'parsers': 'parser',
    'schema': 'schema',
    'schema_package': 'schema',
    'schemas': 'schema',
    'tool': 'action',
    'tools': 'action',
    'unknown': 'unknown',
}

ENTRYPOINT_TYPE_HINTS: tuple[tuple[PluginType, tuple[str, ...]], ...] = (
    ('example_upload', ('example_upload', 'exampleupload')),
    ('north_tool', ('north_tool', 'northtool')),
    ('normalizer', ('normalizer',)),
    ('parser', ('parser',)),
    ('schema', ('schema_package', 'schema')),
    ('dashboard', ('dashboard',)),
    ('action', ('action', 'tool')),
    ('app', ('app',)),
    ('api', ('api',)),
)


def normalize_plugin_type(value: str) -> PluginType:
    normalized = normalize_hint_text(value)
    return PLUGIN_TYPE_ALIASES.get(normalized, 'unknown')


def infer_entrypoint_type(name: str, module: str) -> PluginType:
    normalized_name = normalize_hint_text(name)
    if normalized_name.endswith('_example'):
        return 'example_upload'

    for searchable_text in (normalized_name, normalize_hint_text(module)):
        for plugin_type, hints in ENTRYPOINT_TYPE_HINTS:
            if any(hint in searchable_text for hint in hints):
                return plugin_type

    return 'unknown'


def derive_plugin_types(entrypoint_types: Iterable[str]) -> list[PluginType] | None:
    normalized_types = {
        normalize_plugin_type(entrypoint_type) for entrypoint_type in entrypoint_types
    }
    if not normalized_types:
        return None
    return sorted(normalized_types)


def stable_plugin_id(repository_url: str, project_path: str | None = None) -> str:
    parsed_url = urlparse(repository_url.strip())
    repository_path = parsed_url.path.strip('/').removesuffix('.git')
    base_id = f'{parsed_url.netloc.lower()}/{repository_path}'.lower()
    normalized_project_path = normalize_project_path(project_path)
    if normalized_project_path is None:
        return base_id
    return f'{base_id}#{normalized_project_path}'


def normalize_project_path(project_path: str | None) -> str | None:
    if project_path is None:
        return None
    parts = [
        part
        for part in project_path.strip().replace('\\', '/').split('/')
        if part not in {'', '.'}
    ]
    return '/'.join(parts) or None


def normalize_dependency_name(dependency: str) -> str:
    return re.sub(r'[-_.]+', '-', dependency.strip().lower())


def normalize_dependencies(dependencies: Iterable[str]) -> list[str]:
    return sorted(
        {
            normalize_dependency_name(dependency)
            for dependency in dependencies
            if dependency.strip()
        }
    )


def classify_project(  # noqa: PLR0913
    *,
    name: str,
    description: str,
    repository_url: str,
    project_path: str | None,
    dependencies: Iterable[str],
    has_entrypoints: bool,
    explicit_kind: ProjectKind | None = None,
) -> ProjectKind:
    if explicit_kind is not None:
        return explicit_kind
    if _is_template_or_example(name, description, repository_url, project_path):
        return 'template_or_example'
    if has_entrypoints:
        return 'plugin'
    if _is_distribution(name, description, repository_url):
        return 'distribution'
    if 'nomad-lab' in normalize_dependencies(dependencies):
        return 'nomad_dependent_package'
    return 'ecosystem_package'


def is_registry_visible(project_kind: ProjectKind) -> bool:
    return project_kind in VISIBLE_PROJECT_KINDS


def sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted(
        {value.strip() for value in values if value.strip()}, key=str.casefold
    )


def normalize_hint_text(value: str) -> str:
    return re.sub(r'[-.\s]+', '_', value.strip().lower())


def _is_template_or_example(
    name: str,
    description: str,
    repository_url: str,
    project_path: str | None,
) -> bool:
    normalized_name = normalize_hint_text(name)
    normalized_description = description.strip().casefold()
    normalized_repository = repository_url.strip().casefold()
    normalized_path = normalize_project_path(project_path)
    path_parts = (normalized_path or '').casefold().split('/')

    return (
        '{{' in name
        or '{{' in (project_path or '')
        or 'examples' in path_parts
        or normalized_description == 'nomad example template'
        or 'cookiecutter' in normalized_repository
        or 'plugin_template' in normalize_hint_text(normalized_repository)
        or normalized_name.endswith('_template')
    )


def _is_distribution(name: str, description: str, repository_url: str) -> bool:
    normalized_name = normalize_dependency_name(name)
    searchable_text = normalize_hint_text(' '.join((name, description, repository_url)))
    if normalized_name == 'nomad-distribution':
        return True
    if 'distro' in searchable_text or 'distribution' in searchable_text:
        return True
    if 'oasis' in searchable_text and any(
        term in searchable_text for term in ('deployment', 'image')
    ):
        return True
    return normalized_name.endswith('-image') or '_image' in normalize_hint_text(
        repository_url
    )
