import asyncio
import warnings
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from nomad_plugins.crawler import get_plugin, get_toml_project
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
    assert project.entry_points.nomad_plugin[0].type == 'Parser'
    assert project.entry_points.nomad_plugin[1].type is None
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
    assert project.entry_points.nomad_plugin[0].type is None
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
    search_result = SimpleNamespace(
        path='packages/example/pyproject.toml',
        url='https://api.github.test/code?ref=abc123',
        repository=SimpleNamespace(full_name='example/repository'),
    )
    response = SimpleNamespace(
        text="""
[project]
name = "example-plugin"
"""
    )

    with patch(
        'nomad_plugins.crawler.fetch_page_async',
        new=AsyncMock(return_value=response),
    ) as fetch_page:
        project = asyncio.run(get_toml_project(search_result))

    fetch_page.assert_awaited_once_with(
        url=(
            'https://raw.githubusercontent.com/example/repository/abc123/'
            'packages/example/pyproject.toml'
        )
    )
    assert project is not None
    assert project.name == 'example-plugin'
    assert project.project_path == 'packages/example'


def test_crawler_retains_source_metadata_without_changing_public_output():
    project = parse_pyproject(
        """
[project]
name = "example-parser"

[project.urls]
Repository = "https://github.com/example/declared"
Documentation = "https://docs.example.com/parser"
Homepage = "https://example.com/parser"
Issues = "https://github.com/example/declared/issues"
""",
        pyproject_path='packages/parser/pyproject.toml',
    )
    item = SimpleNamespace(
        repository=SimpleNamespace(
            url='https://api.github.test/repos/example/discovered',
            html_url='https://github.com/example/discovered',
            owner=SimpleNamespace(login='example'),
        )
    )
    repository_response = SimpleNamespace(json=lambda: {})
    repository_details = SimpleNamespace(
        stargazers_count=5,
        created_at='2024-01-01T00:00:00Z',
        updated_at='2024-01-02T00:00:00Z',
    )

    with (
        patch(
            'nomad_plugins.crawler.fetch_page_async',
            new=AsyncMock(return_value=repository_response),
        ),
        patch(
            'nomad_plugins.crawler.get_toml_project',
            new=AsyncMock(return_value=project),
        ),
        patch(
            'nomad_plugins.crawler.package_exists_on_pypi',
            new=AsyncMock(return_value=True),
        ),
        patch(
            'nomad_plugins.crawler.GitHubRepositoryDetailed.model_validate',
            return_value=repository_details,
        ),
    ):
        plugin = asyncio.run(
            get_plugin(
                item=item,
                headers={},
                central_plugins=set(),
                example_oasis_plugins=set(),
            )
        )

    assert plugin is not None
    assert str(plugin.repository) == 'https://github.com/example/discovered'
    assert plugin.project_path == 'packages/parser'
    assert str(plugin.declared_repository_url) == (
        'https://github.com/example/declared'
    )
    assert str(plugin.documentation_url) == 'https://docs.example.com/parser'
    assert str(plugin.homepage_url) == 'https://example.com/parser'
    assert str(plugin.issues_url) == 'https://github.com/example/declared/issues'

    public_data = plugin.model_dump(mode='json', exclude_none=True)
    assert {
        'project_path',
        'declared_repository_url',
        'documentation_url',
        'homepage_url',
        'issues_url',
        'parsing_warnings',
    }.isdisjoint(public_data)
