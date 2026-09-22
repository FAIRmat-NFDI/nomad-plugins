import asyncio
import warnings
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from nomad_plugins.crawler import get_plugin, get_toml_project
from nomad_plugins.github import (
    GitHubOwner,
    GitHubRepositoryDetails,
    GitHubRepositoryLink,
    GitHubRepositorySummary,
    GitHubSearchResultItem,
)
from nomad_plugins.pyproject import PyProjectError, PyProjectWarning, parse_pyproject


def test_parse_complete_nested_pep621_project():
    content = """
[project]
name = "example-plugin"
description = "An example plugin"
requires-python = ">=3.10"
authors = [{name = "Ada", email = "ada@example.com"}]
maintainers = [{name = "Grace"}]
dependencies = [
    "nomad-lab[parsing]>=1.2; python_version >= '3.10'",
    "helper @ git+https://example.com/helper.git#subdirectory=python",
]

[project.optional-dependencies]
dev = ["pytest>=8", "nomad-lab"]

[project.urls]
source = "https://github.com/example/declared"
docs = "https://docs.example.com/plugin"
homepage = "https://example.com/plugin"
"Bug Tracker" = "https://github.com/example/declared/issues"

[project.entry-points."nomad.plugin"]
"example.parser" = "example.parsers:parser_entry_point"
"special.extension" = "custom.extension:entry_point"
"""

    with pytest.warns(PyProjectWarning, match='Retained unclassified'):
        project = parse_pyproject(
            content,
            pyproject_path='packages/example/pyproject.toml',
        )

    assert project.name == 'example-plugin'
    assert project.description == 'An example plugin'
    assert project.requires_python == '>=3.10'
    assert project.authors is not None
    assert project.authors[0].name == 'Ada'
    assert project.maintainers is not None
    assert project.maintainers[0].name == 'Grace'
    assert project.project_path == 'packages/example'
    assert project.all_dependencies == {'nomad-lab', 'helper', 'pytest'}
    assert str(project.urls.repository) == 'https://github.com/example/declared'
    assert str(project.urls.documentation) == 'https://docs.example.com/plugin'
    assert str(project.urls.homepage) == 'https://example.com/plugin'
    assert str(project.urls.issues) == ('https://github.com/example/declared/issues')
    assert [entry.name for entry in project.entry_points.nomad_plugin] == [
        'example.parser',
        'special.extension',
    ]
    assert project.entry_points.nomad_plugin[0].type == 'parser'
    assert project.entry_points.nomad_plugin[1].type == 'unknown'
    assert project.parsing_warnings == [
        'Retained unclassified nomad.plugin entry point: special.extension'
    ]


def test_empty_entry_point_group_produces_no_entries_or_unknown_type():
    content = """
[project]
name = "example-plugin"

[project.entry-points."nomad.plugin"]
"""

    with warnings.catch_warnings():
        warnings.simplefilter('error')
        project = parse_pyproject(content)

    assert project.entry_points.nomad_plugin == []
    assert project.parsing_warnings == []
    assert project.project_path is None


def test_malformed_metadata_is_skipped_with_warnings_where_possible():
    content = """
[project]
name = "example-plugin"
dependencies = ["valid>=1", "not a valid requirement ???"]

[project.entry-points."nomad.plugin"]
broken = 42
valid = "custom.extension:entry_point"
"""

    with pytest.warns(PyProjectWarning) as emitted_warnings:
        project = parse_pyproject(content)

    assert project.all_dependencies == {'valid'}
    assert [entry.name for entry in project.entry_points.nomad_plugin] == ['valid']
    assert project.entry_points.nomad_plugin[0].type == 'unknown'
    assert [str(warning.message) for warning in emitted_warnings] == [
        'Skipped invalid dependency requirement: not a valid requirement ???',
        'Skipped malformed nomad.plugin entry point.',
        'Retained unclassified nomad.plugin entry point: valid',
    ]
    assert project.parsing_warnings == [
        'Skipped invalid dependency requirement: not a valid requirement ???',
        'Skipped malformed nomad.plugin entry point.',
        'Retained unclassified nomad.plugin entry point: valid',
    ]


def test_project_url_precedence_is_case_insensitive():
    project = parse_pyproject(
        """
[project]
name = "example-plugin"

[project.urls]
REPOSITORY = "https://example.com/repository"
Source = "https://example.com/source"
DOCUMENTATION = "https://example.com/documentation"
Docs = "https://example.com/docs"
Homepage = "https://example.com/homepage"
ISSUES = "https://example.com/issues"
"Bug Tracker" = "https://example.com/bugs"
"""
    )

    assert str(project.urls.repository) == 'https://example.com/repository'
    assert str(project.urls.documentation) == 'https://example.com/documentation'
    assert str(project.urls.homepage) == 'https://example.com/homepage'
    assert str(project.urls.issues) == 'https://example.com/issues'


def test_poetry_only_metadata_is_not_parsed():
    with pytest.raises(PyProjectError, match=r'\[project\] table'):
        parse_pyproject(
            """
[tool.poetry]
name = "poetry-plugin"
"""
        )


def test_crawler_fetches_and_parses_nested_pyproject():
    search_result = GitHubSearchResultItem(
        path='packages/example/pyproject.toml',
        url='https://api.github.test/contents/pyproject.toml?ref=abc123',
        repository=GitHubRepositorySummary(
            full_name='example/repository',
            html_url='https://github.com/example/repository',
        ),
    )
    github_client = SimpleNamespace(
        fetch_text=AsyncMock(
            return_value="""
[project]
name = "example-plugin"
"""
        )
    )

    project = asyncio.run(get_toml_project(search_result, github_client))

    github_client.fetch_text.assert_awaited_once_with(
        'https://api.github.test/contents/pyproject.toml?ref=abc123'
    )
    assert project is not None
    assert project.name == 'example-plugin'
    assert project.project_path == 'packages/example'


def test_crawler_builds_public_contract_and_retains_internal_source_metadata():
    with pytest.warns(PyProjectWarning, match='Retained unclassified'):
        project = parse_pyproject(
            """
[project]
name = "example-parser"
description = "Example parser"
dependencies = ["NOMAD_lab>=1", "Helper_Plugin"]

[project.urls]
Repository = "https://github.com/example/declared"
Documentation = "https://docs.example.com/parser"
Homepage = "https://example.com/parser"
Issues = "https://github.com/example/declared/issues"

[project.entry-points."nomad.plugin"]
example_parser = "example.parsers:parser_entry_point"
"special.extension" = "custom.extension:entry_point"
""",
            pyproject_path='packages/parser/pyproject.toml',
        )
    item = GitHubSearchResultItem(
        path='packages/parser/pyproject.toml',
        url='https://api.github.test/contents/pyproject.toml?ref=abc123',
        repository=GitHubRepositorySummary(
            full_name='example/discovered',
            html_url='https://github.com/example/discovered',
        ),
    )
    repository_details = GitHubRepositoryDetails(
        owner=GitHubOwner(login='example', type='Organization'),
        stargazers_count=5,
        created_at='2024-01-01T00:00:00Z',
        pushed_at='2024-01-03T00:00:00Z',
        archived=False,
        fork=False,
        default_branch='main',
        parent=GitHubRepositoryLink(html_url='https://github.com/upstream/parent'),
        source=GitHubRepositoryLink(html_url='https://github.com/upstream/source'),
    )
    github_client = SimpleNamespace()

    with (
        patch(
            'nomad_plugins.crawler.get_toml_project',
            new=AsyncMock(return_value=project),
        ),
        patch(
            'nomad_plugins.crawler.package_exists_on_pypi',
            new=AsyncMock(return_value=True),
        ),
    ):
        plugin = asyncio.run(
            get_plugin(
                item=item,
                github_client=github_client,
                repository=repository_details,
                central_plugins=set(),
                example_oasis_plugins=set(),
            )
        )

    assert plugin is not None
    assert plugin.id == 'github.com/example/discovered#packages/parser'
    assert str(plugin.repository_url) == 'https://github.com/example/discovered'
    assert plugin.project_path == 'packages/parser'
    assert str(plugin.declared_repository_url) == (
        'https://github.com/example/declared'
    )
    assert str(plugin.documentation_url) == 'https://docs.example.com/parser'
    assert str(plugin.homepage_url) == 'https://example.com/parser'
    assert str(plugin.issues_url) == 'https://github.com/example/declared/issues'
    assert plugin.plugin_types == ['parser', 'unknown']
    assert plugin.dependencies == ['helper-plugin', 'nomad-lab']
    assert plugin.project_kind == 'plugin'
    assert plugin.registry_visible is True
    assert plugin.owner_type == 'Organization'
    assert plugin.status.default_branch == 'main'
    assert str(plugin.status.parent_repository_url) == (
        'https://github.com/upstream/parent'
    )
    assert str(plugin.status.source_repository_url) == (
        'https://github.com/upstream/source'
    )
    assert plugin.status.last_pushed_at == datetime.fromisoformat(
        '2024-01-03T00:00:00+00:00'
    )

    public_data = plugin.model_dump(mode='json', by_alias=True, exclude_none=True)
    assert public_data['repositoryUrl'] == 'https://github.com/example/discovered'
    assert public_data['ownerType'] == 'Organization'
    assert public_data['status']['defaultBranch'] == 'main'
    assert public_data['status']['parentRepositoryUrl'] == (
        'https://github.com/upstream/parent'
    )
    assert public_data['status']['sourceRepositoryUrl'] == (
        'https://github.com/upstream/source'
    )
    assert public_data['documentationUrl'] == 'https://docs.example.com/parser'
    assert public_data['pypiUrl'] == 'https://pypi.org/project/example-parser/'
    assert public_data['pluginTypes'] == ['parser', 'unknown']
    assert public_data['discoveryWarnings'] == [
        'Retained unclassified nomad.plugin entry point: special.extension'
    ]
    assert {
        'project_path',
        'declared_repository_url',
        'homepage_url',
        'issues_url',
        'authors',
        'maintainers',
    }.isdisjoint(public_data)
