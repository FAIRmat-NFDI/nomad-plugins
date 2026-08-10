from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.9/3.10
    try:
        import tomli as tomllib
    except ModuleNotFoundError:  # pragma: no cover - environment dependent
        tomllib = None

try:
    from packaging.requirements import InvalidRequirement, Requirement
except ModuleNotFoundError:  # pragma: no cover - dependency-light local fallback
    InvalidRequirement = ValueError
    Requirement = None

from .capabilities import (
    infer_entrypoint_type,
    normalize_hint_text,
    normalize_plugin_type,
)
from .github import GitHubCandidateFile
from .transform import (
    PROJECT_KIND_DISTRIBUTION,
    PROJECT_KIND_ECOSYSTEM_PACKAGE,
    PROJECT_KIND_NOMAD_DEPENDENT_PACKAGE,
    PROJECT_KIND_OFFICIAL_TEMPLATE,
    PROJECT_KIND_PLUGIN,
    PROJECT_KIND_TEMPLATE_OR_EXAMPLE,
    DiscoveredAuthor,
    DiscoveredEntrypoint,
    DiscoveredPlugin,
)

NOMAD_ENTRYPOINT_GROUP = 'nomad.plugin'
METADATA_SOURCE = 'pyproject.toml'
PYPROJECT_FILENAME = 'pyproject.toml'
OFFICIAL_TEMPLATE_REPOSITORIES = {
    'github.com/fairmat-nfdi/cookiecutter-nomad-plugin',
    'github.com/fairmat-nfdi/nomad-distro-dev',
    'github.com/fairmat-nfdi/nomad-distro-template',
    'github.com/fairmat-nfdi/nomad-plugin-example',
    'github.com/fairmat-nfdi/nomad-plugin-template',
    'github.com/fairmat-nfdi/pynxtools-plugin-template',
}
EXAMPLE_PROJECT_PATH_WARNING = (
    'Project path is under examples/ and hidden from public registry.'
)


def parse_pyproject_candidate(
    candidate: GitHubCandidateFile,
    pyproject_text: str,
) -> DiscoveredPlugin:
    warnings: list[str] = []
    pyproject = parse_toml(pyproject_text)
    project = optional_mapping(pyproject, 'project', 'pyproject')
    tool = optional_mapping(pyproject, 'tool', 'pyproject')
    poetry = optional_mapping(tool, 'poetry', 'pyproject.tool')

    if project is None and poetry is None:
        raise ValueError('pyproject.toml must contain project or tool.poetry metadata.')

    name = first_string(
        [
            mapping_string(project, 'name') if project is not None else None,
            mapping_string(poetry, 'name') if poetry is not None else None,
            repository_name(candidate.repository_url),
        ],
    )
    description = first_string(
        [
            mapping_string(project, 'description') if project is not None else None,
            mapping_string(poetry, 'description') if poetry is not None else None,
        ],
        default='',
    )
    project_urls = project_url_mapping(project)
    poetry_urls = poetry_url_mapping(poetry)
    documentation_url = documentation_url_from(project_urls, poetry_urls)
    declared_repository_url = repository_url_from(project_urls, poetry_urls)
    if declared_repository_url is not None and not same_url(
        declared_repository_url,
        candidate.repository_url,
    ):
        warnings.append(
            f'Declared repository URL differs from discovered GitHub repository: '
            f'{declared_repository_url}',
        )

    entrypoints = parse_nomad_entrypoints(pyproject, warnings)
    dependencies = parse_dependencies(project, poetry, warnings)
    authors = parse_project_people(
        project.get('authors') if project is not None else None,
        warnings,
    )
    maintainers = parse_project_people(
        project.get('maintainers') if project is not None else None,
        warnings,
    )
    if len(authors) == 0:
        authors = parse_poetry_people(
            poetry.get('authors') if poetry is not None else None,
            warnings,
        )
    if len(maintainers) == 0:
        maintainers = parse_poetry_people(
            poetry.get('maintainers') if poetry is not None else None,
            warnings,
        )
    project_path = project_path_from_candidate(candidate)
    plugin_types = [
        entrypoint_type
        for entrypoint_type in [
            normalize_plugin_type(entrypoint.type) for entrypoint in entrypoints
        ]
        if entrypoint_type is not None
    ]

    project_kind = classify_project(
        name=name,
        description=description,
        project_path=project_path,
        repository_url=candidate.repository_url,
        entrypoints=entrypoints,
        dependencies=dependencies,
    )
    if is_example_project_path(project_path):
        warnings.append(EXAMPLE_PROJECT_PATH_WARNING)

    registry_visible = project_kind in {
        PROJECT_KIND_PLUGIN,
        PROJECT_KIND_NOMAD_DEPENDENT_PACKAGE,
        PROJECT_KIND_OFFICIAL_TEMPLATE,
    }

    if len(entrypoints) == 0:
        warnings.append('No nomad.plugin entry points found in pyproject.toml.')

    return DiscoveredPlugin(
        name=name,
        description=description,
        repository_url=candidate.repository_url,
        project_path=project_path,
        documentation_url=documentation_url,
        pypi_url=pypi_url_from_name(name),
        owner=repository_owner(candidate.repository_url),
        entrypoints=entrypoints,
        plugin_types=plugin_types,
        dependencies=dependencies,
        authors=authors,
        maintainers=maintainers,
        metadata_source=METADATA_SOURCE,
        project_kind=project_kind,
        registry_visible=registry_visible,
        discovery_warnings=warnings,
    )


def classify_project(  # noqa: PLR0911, PLR0913
    *,
    name: str,
    description: str,
    project_path: str | None,
    repository_url: str,
    entrypoints: list[DiscoveredEntrypoint],
    dependencies: list[str],
) -> str:
    if is_official_template_repository(repository_url):
        return PROJECT_KIND_OFFICIAL_TEMPLATE

    if is_unmodified_nomad_example_template_description(description):
        return PROJECT_KIND_TEMPLATE_OR_EXAMPLE

    if is_example_project_path(project_path):
        return PROJECT_KIND_TEMPLATE_OR_EXAMPLE

    if len(entrypoints) > 0:
        return PROJECT_KIND_PLUGIN

    normalized_repository_url = repository_url.lower()
    normalized_project_path = (project_path or '').lower()

    if is_distribution_project(
        name=name,
        description=description,
        repository_url=repository_url,
    ):
        return PROJECT_KIND_DISTRIBUTION

    if (
        '{{' in name
        or '{{' in normalized_project_path
        or 'cookiecutter' in normalized_repository_url
        or 'plugin-template' in normalized_repository_url
    ):
        return PROJECT_KIND_TEMPLATE_OR_EXAMPLE

    if has_nomad_lab_dependency(dependencies):
        return PROJECT_KIND_NOMAD_DEPENDENT_PACKAGE

    return PROJECT_KIND_ECOSYSTEM_PACKAGE


def normalize_project_name(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name.strip().lower())


def is_distribution_project(
    *,
    name: str,
    description: str,
    repository_url: str,
) -> bool:
    normalized_name = normalize_project_name(name)
    normalized_description = normalize_hint_text(description)
    normalized_repository_url = normalize_hint_text(repository_url)
    searchable_text = ' '.join(
        [normalized_name, normalized_description, normalized_repository_url],
    )

    if normalized_name == 'nomad-distribution':
        return True

    if any(term in searchable_text for term in ['distro', 'distribution']):
        return True

    if 'oasis' in searchable_text and any(
        term in searchable_text
        for term in ['deployment', 'image', 'distribution', 'distro']
    ):
        return True

    return normalized_name.endswith('-image') or '_image' in normalized_repository_url


def is_official_template_repository(repository_url: str) -> bool:
    parsed_url = urlparse(repository_url.strip())
    repository_path = parsed_url.path.strip('/')

    if repository_path.endswith('.git'):
        repository_path = repository_path[:-4]

    return (
        f'{parsed_url.netloc.lower()}/{repository_path}'.lower()
        in OFFICIAL_TEMPLATE_REPOSITORIES
    )


def has_nomad_lab_dependency(dependencies: list[str]) -> bool:
    return any(
        normalize_project_name(dependency) == 'nomad-lab' for dependency in dependencies
    )


def is_unmodified_nomad_example_template_description(description: str) -> bool:
    return description.strip().casefold() == 'nomad example template'


def is_example_project_path(project_path: str | None) -> bool:
    if project_path is None:
        return False

    return 'examples' in [
        segment.strip().casefold()
        for segment in project_path.replace('\\', '/').split('/')
    ]


def parse_toml(pyproject_text: str) -> dict[str, Any]:
    if tomllib is None:
        raise RuntimeError(
            'Parsing pyproject.toml requires Python 3.11+ or the tomli package.',
        )

    try:
        data = tomllib.loads(pyproject_text)
    except tomllib.TOMLDecodeError as error:  # type: ignore[union-attr]
        raise ValueError(f'Unable to parse pyproject.toml: {error}') from error

    if not isinstance(data, dict):
        raise ValueError('pyproject.toml must be a TOML table.')

    return data


def parse_nomad_entrypoints(
    pyproject: dict[str, Any],
    warnings: list[str],
) -> list[DiscoveredEntrypoint]:
    entrypoints = optional_mapping(
        optional_mapping(pyproject, 'project', 'pyproject'),
        'entry-points',
        'pyproject.project',
    )
    nomad_entrypoints = optional_mapping(
        entrypoints,
        NOMAD_ENTRYPOINT_GROUP,
        'pyproject.project.entry-points',
    )

    if nomad_entrypoints is None:
        poetry_plugins = optional_mapping(
            optional_mapping(
                optional_mapping(pyproject, 'tool', 'pyproject'),
                'poetry',
                'pyproject.tool',
            ),
            'plugins',
            'pyproject.tool.poetry',
        )
        nomad_entrypoints = optional_mapping(
            poetry_plugins,
            NOMAD_ENTRYPOINT_GROUP,
            'pyproject.tool.poetry.plugins',
        )

    if nomad_entrypoints is None:
        return []

    discovered_entrypoints: list[DiscoveredEntrypoint] = []
    for name, module in sorted(nomad_entrypoints.items()):
        if not isinstance(name, str) or not isinstance(module, str):
            warnings.append('Skipped malformed nomad.plugin entry point.')
            continue

        cleaned_name = name.strip()
        cleaned_module = module.strip()
        if cleaned_name == '' or cleaned_module == '':
            warnings.append('Skipped empty nomad.plugin entry point.')
            continue

        discovered_entrypoints.append(
            DiscoveredEntrypoint(
                name=cleaned_name,
                module=cleaned_module,
                type=infer_entrypoint_type(cleaned_name, cleaned_module),
            ),
        )

    return discovered_entrypoints


def parse_dependencies(
    project: dict[str, Any] | None,
    poetry: dict[str, Any] | None,
    warnings: list[str],
) -> list[str]:
    dependencies: list[str] = []

    if project is not None:
        dependencies.extend(
            parse_dependency_list(project.get('dependencies'), warnings)
        )
        optional_dependencies = project.get('optional-dependencies')
        if isinstance(optional_dependencies, dict):
            for values in optional_dependencies.values():
                dependencies.extend(parse_dependency_list(values, warnings))
        elif optional_dependencies is not None:
            warnings.append('Skipped malformed project.optional-dependencies.')

    if poetry is not None:
        dependencies.extend(
            parse_poetry_dependencies(poetry.get('dependencies'), warnings)
        )
        dependency_groups = poetry.get('group')
        if isinstance(dependency_groups, dict):
            for group in dependency_groups.values():
                if isinstance(group, dict):
                    dependencies.extend(
                        parse_poetry_dependencies(group.get('dependencies'), warnings),
                    )
        elif dependency_groups is not None:
            warnings.append('Skipped malformed tool.poetry.group dependencies.')

    return dependencies


def parse_project_people(value: Any, warnings: list[str]) -> list[DiscoveredAuthor]:
    if value is None:
        return []

    if not isinstance(value, list):
        warnings.append('Skipped malformed project person list.')
        return []

    people: list[DiscoveredAuthor] = []
    for person in value:
        if not isinstance(person, dict):
            warnings.append('Skipped malformed project person.')
            continue

        name = person.get('name')
        email = person.get('email')
        people.append(
            DiscoveredAuthor(
                name=name.strip() if isinstance(name, str) and name.strip() else None,
                email=email.strip()
                if isinstance(email, str) and email.strip()
                else None,
            ),
        )

    return people


def parse_poetry_people(value: Any, warnings: list[str]) -> list[DiscoveredAuthor]:
    if value is None:
        return []

    if not isinstance(value, list):
        warnings.append('Skipped malformed Poetry person list.')
        return []

    people: list[DiscoveredAuthor] = []
    for person in value:
        if not isinstance(person, str):
            warnings.append('Skipped malformed Poetry person.')
            continue

        match = re.match(r'\s*(?P<name>[^<]+?)(?:\s*<(?P<email>[^>]+)>)?\s*$', person)
        if match is None:
            people.append(DiscoveredAuthor(name=person.strip() or None))
            continue

        name = match.group('name').strip()
        email = match.group('email')
        people.append(
            DiscoveredAuthor(
                name=name or None,
                email=email.strip() if email is not None and email.strip() else None,
            ),
        )

    return people


def parse_dependency_list(value: Any, warnings: list[str]) -> list[str]:
    if value is None:
        return []

    if not isinstance(value, list):
        warnings.append('Skipped malformed project dependency list.')
        return []

    dependencies: list[str] = []
    for dependency in value:
        if not isinstance(dependency, str):
            warnings.append('Skipped malformed project dependency.')
            continue

        dependencies.append(parse_dependency_name(dependency, warnings))

    return dependencies


def parse_poetry_dependencies(value: Any, warnings: list[str]) -> list[str]:
    if value is None:
        return []

    if not isinstance(value, dict):
        warnings.append('Skipped malformed Poetry dependency table.')
        return []

    return [
        dependency
        for dependency in value.keys()
        if isinstance(dependency, str) and dependency.lower() != 'python'
    ]


def parse_dependency_name(dependency: str, warnings: list[str]) -> str:
    if Requirement is not None:
        try:
            return Requirement(dependency).name
        except InvalidRequirement:
            warnings.append(f'Could not parse dependency requirement: {dependency}')

    fallback_match = re.match(r'\s*([A-Za-z0-9][A-Za-z0-9._-]*)', dependency)
    if fallback_match is not None:
        return fallback_match.group(1)

    return dependency


def project_url_mapping(project: dict[str, Any] | None) -> dict[str, str]:
    if project is None:
        return {}

    return string_mapping(project.get('urls'))


def poetry_url_mapping(poetry: dict[str, Any] | None) -> dict[str, str]:
    if poetry is None:
        return {}

    urls = {
        'repository': mapping_string(poetry, 'repository'),
        'documentation': mapping_string(poetry, 'documentation'),
        'homepage': mapping_string(poetry, 'homepage'),
    }

    return {key: value for key, value in urls.items() if value is not None}


def documentation_url_from(
    project_urls: dict[str, str],
    poetry_urls: dict[str, str],
) -> str | None:
    return first_valid_url(
        [
            project_urls.get('Documentation'),
            project_urls.get('documentation'),
            project_urls.get('Docs'),
            project_urls.get('docs'),
            project_urls.get('Homepage'),
            project_urls.get('homepage'),
            poetry_urls.get('documentation'),
            poetry_urls.get('homepage'),
        ],
    )


def repository_url_from(
    project_urls: dict[str, str],
    poetry_urls: dict[str, str],
    default: str | None = None,
) -> str | None:
    return first_valid_url(
        [
            project_urls.get('Repository'),
            project_urls.get('repository'),
            project_urls.get('Source'),
            project_urls.get('source'),
            project_urls.get('Source Code'),
            project_urls.get('source code'),
            poetry_urls.get('repository'),
        ],
        default=default,
    )


def first_valid_url(
    values: list[str | None], *, default: str | None = None
) -> str | None:
    for value in values:
        if value is not None and is_http_url(value):
            return value.strip()

    return default


def project_path_from_candidate(candidate: GitHubCandidateFile) -> str | None:
    normalized_path = candidate.file_path.replace('\\', '/')

    if normalized_path == PYPROJECT_FILENAME:
        return None

    if normalized_path.endswith(f'/{PYPROJECT_FILENAME}'):
        project_path = normalized_path[: -len(f'/{PYPROJECT_FILENAME}')]

        return project_path or None

    return None


def repository_owner(repository_url: str) -> str | None:
    parsed_url = urlparse(repository_url)
    path_parts = [part for part in parsed_url.path.split('/') if part]

    if parsed_url.netloc.endswith('github.com') and path_parts:
        return path_parts[0]

    return None


def repository_name(repository_url: str) -> str:
    parsed_url = urlparse(repository_url)
    path_parts = [part for part in parsed_url.path.split('/') if part]

    if path_parts:
        return path_parts[-1].removesuffix('.git')

    return parsed_url.netloc or 'Unknown plugin'


def pypi_url_from_name(name: str) -> str:
    return f'https://pypi.org/project/{name.strip()}/'


def optional_mapping(
    data: dict[str, Any] | None,
    key: str,
    context: str,
) -> dict[str, Any] | None:
    if data is None:
        return None

    value = data.get(key)

    if value is None:
        return None

    if not isinstance(value, dict):
        raise ValueError(f'{context}.{key} must be a table when present.')

    return value


def string_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}

    return {
        key: item
        for key, item in value.items()
        if isinstance(key, str) and isinstance(item, str) and item.strip() != ''
    }


def mapping_string(data: dict[str, Any] | None, key: str) -> str | None:
    if data is None:
        return None

    value = data.get(key)
    if isinstance(value, str) and value.strip() != '':
        return value.strip()

    return None


def first_string(values: list[str | None], *, default: str | None = None) -> str:
    for value in values:
        if value is not None and value.strip() != '':
            return value.strip()

    if default is not None:
        return default

    raise ValueError('Expected at least one non-empty string value.')


def is_http_url(value: str) -> bool:
    parsed_url = urlparse(value.strip())

    return parsed_url.scheme in {'http', 'https'} and parsed_url.netloc != ''


def same_url(first_url: str, second_url: str) -> bool:
    first = urlparse(first_url.strip())
    second = urlparse(second_url.strip())

    return (
        first.scheme.lower(),
        first.netloc.lower(),
        first.path.rstrip('/').removesuffix('.git').lower(),
    ) == (
        second.scheme.lower(),
        second.netloc.lower(),
        second.path.rstrip('/').removesuffix('.git').lower(),
    )
