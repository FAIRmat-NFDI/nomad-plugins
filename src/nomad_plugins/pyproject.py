from __future__ import annotations

import warnings
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from packaging.requirements import InvalidRequirement, Requirement
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError

PYPROJECT_FILENAME = 'pyproject.toml'
NOMAD_ENTRY_POINT_GROUP = 'nomad.plugin'


class PyProjectError(ValueError):
    """Raised when standards-based pyproject metadata cannot be parsed."""


class PyProjectWarning(UserWarning):
    """Warning emitted for recoverable pyproject metadata problems."""


class Author(BaseModel):
    name: str | None = None
    email: str | None = None


class LicenseInfo(BaseModel):
    file: str | None = None
    text: str | None = None


class ProjectURLs(BaseModel):
    repository: HttpUrl | None = None
    documentation: HttpUrl | None = None
    homepage: HttpUrl | None = None
    issues: HttpUrl | None = None


class NomadPlugin(BaseModel):
    name: str
    module: str
    type: str | None = None


class EntryPoints(BaseModel):
    nomad_plugin: list[NomadPlugin] = Field(default_factory=list)


class PyProjectTOML(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    dynamic: list[str] | None = None
    authors: list[Author] | None = None
    maintainers: list[Author] | None = None
    description: str | None = None
    readme: str | dict[str, str] | None = None
    license: str | LicenseInfo | None = None
    requires_python: str | None = Field(None, alias='requires-python')
    dependencies: list[str] | None = None
    urls: ProjectURLs = Field(default_factory=ProjectURLs)
    optional_dependencies: dict[str, list[str]] | None = Field(
        None,
        alias='optional-dependencies',
    )
    all_dependencies: set[str] = Field(default_factory=set)
    entry_points: EntryPoints = Field(default_factory=EntryPoints, alias='entry-points')
    project_path: str | None = None
    parsing_warnings: list[str] = Field(default_factory=list)


def parse_pyproject(
    pyproject_text: str,
    *,
    pyproject_path: str = PYPROJECT_FILENAME,
) -> PyProjectTOML:
    """Parse the PEP 621 project metadata from a pyproject file."""
    try:
        pyproject = tomllib.loads(pyproject_text)
    except tomllib.TOMLDecodeError as error:
        raise PyProjectError(f'Unable to parse pyproject.toml: {error}') from error

    project = pyproject.get('project')
    if not isinstance(project, dict):
        raise PyProjectError('pyproject.toml must contain a [project] table.')

    diagnostics: list[str] = []
    parsed_project = {
        **project,
        'all_dependencies': _parse_dependencies(project, diagnostics),
        'entry-points': _parse_entry_points(project, diagnostics),
        'urls': _parse_project_urls(project.get('urls'), diagnostics),
        'project_path': project_path_from_pyproject_path(pyproject_path),
        'parsing_warnings': diagnostics,
    }

    try:
        return PyProjectTOML.model_validate(parsed_project)
    except ValidationError as error:
        raise PyProjectError(f'Invalid PEP 621 project metadata: {error}') from error


def parse_requirement_name(
    requirement: str,
    diagnostics: list[str] | None = None,
) -> str | None:
    """Return the distribution name from a valid PEP 508 requirement."""
    try:
        return Requirement(requirement.strip()).name
    except InvalidRequirement:
        _record_warning(
            diagnostics,
            f'Skipped invalid dependency requirement: {requirement}',
        )
        return None


def project_path_from_pyproject_path(pyproject_path: str) -> str | None:
    """Return the containing project path for a repository pyproject path."""
    normalized_path = pyproject_path.replace('\\', '/').strip('/')
    parts = [part for part in PurePosixPath(normalized_path).parts if part != '.']
    if not parts or parts[-1] != PYPROJECT_FILENAME:
        raise PyProjectError(f'Expected a path ending in {PYPROJECT_FILENAME}.')

    project_path = '/'.join(parts[:-1])
    return project_path or None


def _parse_dependencies(
    project: dict[str, Any],
    diagnostics: list[str],
) -> set[str]:
    requirements: list[Any] = []

    dependencies = project.get('dependencies', [])
    if isinstance(dependencies, list):
        requirements.extend(dependencies)
    elif dependencies is not None:
        _record_warning(diagnostics, 'Skipped malformed project dependency list.')

    optional_dependencies = project.get('optional-dependencies', {})
    if isinstance(optional_dependencies, dict):
        for group_requirements in optional_dependencies.values():
            if isinstance(group_requirements, list):
                requirements.extend(group_requirements)
            else:
                _record_warning(
                    diagnostics,
                    'Skipped malformed optional dependency group.',
                )
    elif optional_dependencies is not None:
        _record_warning(diagnostics, 'Skipped malformed optional dependency table.')

    dependency_names: set[str] = set()
    for requirement in requirements:
        if not isinstance(requirement, str):
            _record_warning(diagnostics, 'Skipped non-string dependency requirement.')
            continue
        if dependency_name := parse_requirement_name(requirement, diagnostics):
            dependency_names.add(dependency_name)

    return dependency_names


def _parse_entry_points(
    project: dict[str, Any],
    diagnostics: list[str],
) -> EntryPoints:
    entry_point_groups = project.get('entry-points')
    if entry_point_groups is None:
        return EntryPoints()
    if not isinstance(entry_point_groups, dict):
        _record_warning(diagnostics, 'Skipped malformed project entry-point table.')
        return EntryPoints()

    nomad_entry_points = entry_point_groups.get(NOMAD_ENTRY_POINT_GROUP)
    if nomad_entry_points is None:
        return EntryPoints()
    if not isinstance(nomad_entry_points, dict):
        _record_warning(
            diagnostics,
            'Skipped malformed nomad.plugin entry-point group.',
        )
        return EntryPoints()

    plugins: list[NomadPlugin] = []
    for name, module in sorted(nomad_entry_points.items()):
        if not isinstance(name, str) or not isinstance(module, str):
            _record_warning(diagnostics, 'Skipped malformed nomad.plugin entry point.')
            continue

        cleaned_name = name.strip()
        cleaned_module = module.strip()
        if not cleaned_name or not cleaned_module:
            _record_warning(diagnostics, 'Skipped empty nomad.plugin entry point.')
            continue

        plugin_type = _infer_legacy_plugin_type(cleaned_name, cleaned_module)
        if plugin_type is None:
            _record_warning(
                diagnostics,
                f'Retained unclassified nomad.plugin entry point: {cleaned_name}',
            )
        plugins.append(
            NomadPlugin(
                name=cleaned_name,
                module=cleaned_module,
                type=plugin_type,
            )
        )

    return EntryPoints(nomad_plugin=plugins)


def _infer_legacy_plugin_type(name: str, module: str) -> str | None:
    searchable_text = f'{name} {module}'.casefold()
    type_hints = (
        ('schema', 'Schema package'),
        ('parser', 'Parser'),
        ('normalizer', 'Normalizer'),
        ('app', 'App'),
        ('example', 'Example upload'),
        ('api', 'API'),
    )
    for hint, plugin_type in type_hints:
        if hint in searchable_text:
            return plugin_type
    return None


def _parse_project_urls(
    value: Any,
    diagnostics: list[str],
) -> ProjectURLs:
    if value is None:
        return ProjectURLs()
    if not isinstance(value, dict):
        _record_warning(diagnostics, 'Skipped malformed project.urls table.')
        return ProjectURLs()

    entries = [(str(label).casefold(), url) for label, url in value.items()]
    return ProjectURLs(
        repository=_first_url(
            entries,
            ('repository', 'source', 'source code'),
            diagnostics,
        ),
        documentation=_first_url(
            entries,
            ('documentation', 'docs', 'homepage'),
            diagnostics,
        ),
        homepage=_first_url(entries, ('homepage',), diagnostics),
        issues=_first_url(
            entries,
            ('issues', 'bug tracker', 'bug reports'),
            diagnostics,
        ),
    )


def _first_url(
    entries: list[tuple[str, Any]],
    labels: tuple[str, ...],
    diagnostics: list[str],
) -> str | None:
    for label in labels:
        for actual_label, value in entries:
            if actual_label != label:
                continue
            if not isinstance(value, str) or not _is_http_url(value):
                _record_warning(
                    diagnostics,
                    f'Skipped invalid project URL for {actual_label}: {value}',
                )
                continue
            return value.strip()
    return None


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme in {'http', 'https'} and bool(parsed.netloc)


def _record_warning(diagnostics: list[str] | None, message: str) -> None:
    if diagnostics is not None:
        diagnostics.append(message)
    warnings.warn(message, PyProjectWarning, stacklevel=3)
