from __future__ import annotations

import unittest

from nomad_plugins.github import GitHubCandidateFile
from nomad_plugins.pyproject import (
    infer_entrypoint_type,
    parse_dependency_name,
    parse_pyproject_candidate,
    project_path_from_candidate,
    same_url,
)


class PyprojectParserTests(unittest.TestCase):
    def test_parses_pep_621_nomad_plugin_metadata(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(),
            """
[project]
name = "nomad-parser-example"
description = "An example NOMAD parser."
authors = [{ name = "Ada", email = "ada@example.org" }]
maintainers = [{ name = "Grace" }]
dependencies = [
  "nomad-lab>=1.3",
  "pydantic[email]>=2",
  "example_dep @ git+https://github.com/example/example-dep.git",
]

[project.optional-dependencies]
dev = ["pytest>=8", 7]

[project.urls]
Documentation = "https://example.github.io/nomad-parser-example/"
Repository = "https://github.com/example/nomad-parser-example"

[project.entry-points."nomad.plugin"]
example_parser = "nomad_parser_example.parsers:parser_entrypoint"
example_schema = "nomad_parser_example.schema:schema_package_entrypoint"
""",
        )

        self.assertEqual(plugin.name, 'nomad-parser-example')
        self.assertEqual(plugin.description, 'An example NOMAD parser.')
        self.assertEqual(
            plugin.repository_url, 'https://github.com/example/nomad-parser-example'
        )
        self.assertEqual(
            plugin.documentation_url,
            'https://example.github.io/nomad-parser-example/',
        )
        self.assertEqual(
            plugin.pypi_url, 'https://pypi.org/project/nomad-parser-example/'
        )
        self.assertEqual(plugin.owner, 'example')
        self.assertEqual(plugin.project_path, 'packages/parser')
        self.assertEqual(plugin.metadata_source, 'pyproject.toml')
        entrypoint_data = [
            (entrypoint.name, entrypoint.module, entrypoint.type)
            for entrypoint in plugin.entrypoints
        ]
        self.assertEqual(
            entrypoint_data,
            [
                (
                    'example_parser',
                    'nomad_parser_example.parsers:parser_entrypoint',
                    'parser',
                ),
                (
                    'example_schema',
                    'nomad_parser_example.schema:schema_package_entrypoint',
                    'schema',
                ),
            ],
        )
        self.assertEqual(
            plugin.dependencies,
            ['nomad-lab', 'pydantic', 'example_dep', 'pytest'],
        )
        self.assertEqual(plugin.authors[0].name, 'Ada')
        self.assertEqual(plugin.authors[0].email, 'ada@example.org')
        self.assertEqual(plugin.maintainers[0].name, 'Grace')
        self.assertEqual(plugin.plugin_types, ['parser', 'schema'])
        self.assertEqual(
            plugin.discovery_warnings, ['Skipped malformed project dependency.']
        )

    def test_keeps_discovered_repository_when_declared_repository_differs(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(
                repository_url='https://github.com/actual-owner/actual-plugin',
            ),
            """
[project]
name = "nomad-parser-example"

[project.urls]
Repository = "https://github.com/foo/template-plugin"

[project.entry-points."nomad.plugin"]
example_parser = "nomad_parser_example.parsers:parser_entrypoint"
""",
        )

        self.assertEqual(
            plugin.repository_url, 'https://github.com/actual-owner/actual-plugin'
        )
        self.assertEqual(plugin.owner, 'actual-owner')
        self.assertEqual(
            plugin.discovery_warnings,
            [
                'Declared repository URL differs from discovered GitHub repository: '
                'https://github.com/foo/template-plugin',
            ],
        )

    def test_parses_poetry_metadata_as_fallback(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(file_path='pyproject.toml'),
            """
[tool.poetry]
name = "nomad-schema-example"
description = "A Poetry based schema plugin."
authors = ["Ada Lovelace <ada@example.org>"]
maintainers = ["Grace Hopper"]
repository = "https://github.com/example/nomad-schema-example"
documentation = "https://example.github.io/nomad-schema-example/"

[tool.poetry.dependencies]
python = ">=3.10"
nomad-lab = "^1.3"
numpy = "*"

[tool.poetry.plugins."nomad.plugin"]
example_schema_package = "nomad_schema_example:schema_package_entrypoint"
""",
        )

        self.assertEqual(plugin.name, 'nomad-schema-example')
        self.assertEqual(plugin.project_path, None)
        self.assertEqual(plugin.dependencies, ['nomad-lab', 'numpy'])
        self.assertEqual(plugin.authors[0].name, 'Ada Lovelace')
        self.assertEqual(plugin.authors[0].email, 'ada@example.org')
        self.assertEqual(plugin.maintainers[0].name, 'Grace Hopper')
        self.assertEqual(plugin.entrypoints[0].type, 'schema')

    def test_warns_when_nomad_entrypoints_are_missing(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(),
            """
[project]
name = "plain-package"
description = "This package was discovered but declares no NOMAD entry points."
dependencies = ["nomad-lab>=1.3"]
""",
        )

        self.assertEqual(plugin.entrypoints, [])
        self.assertEqual(plugin.plugin_types, [])
        self.assertIn(
            'No nomad.plugin entry points found in pyproject.toml.',
            plugin.discovery_warnings,
        )

    def test_marks_example_project_paths_hidden_from_registry(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(
                file_path='examples/data/cow_tutorial/nomad-countries/pyproject.toml',
                repository_url='https://github.com/example/test-distro',
            ),
            """
[project]
name = "nomad-countries"
description = "Countries of the world plugin"
dependencies = ["nomad-lab>=1.3"]

[project.entry-points."nomad.plugin"]
countryparser = "nomad_countries.parsers:country"
""",
        )

        self.assertEqual(
            plugin.project_path, 'examples/data/cow_tutorial/nomad-countries'
        )
        self.assertEqual(plugin.project_kind, 'template_or_example')
        self.assertFalse(plugin.registry_visible)
        self.assertEqual(
            plugin.discovery_warnings,
            ['Project path is under examples/ and hidden from public registry.'],
        )

    def test_marks_oasis_deployment_packages_hidden_from_registry(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(repository_url='https://github.com/example/example-oasis'),
            """
[project]
name = "example-oasis"
description = "NOMAD Oasis deployment for an institute."
dependencies = ["nomad-lab>=1.3"]
""",
        )

        self.assertEqual(plugin.project_kind, 'distribution')
        self.assertFalse(plugin.registry_visible)

    def test_marks_image_packages_hidden_from_registry(self) -> None:
        plugin = parse_pyproject_candidate(
            candidate_file(repository_url='https://github.com/example/perotf-image'),
            """
[project]
name = "perotf-image"
description = "NOMAD distribution image."
dependencies = ["nomad-lab>=1.3"]
""",
        )

        self.assertEqual(plugin.project_kind, 'distribution')
        self.assertFalse(plugin.registry_visible)

    def test_rejects_pyproject_without_project_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, 'project or tool.poetry metadata'):
            parse_pyproject_candidate(
                candidate_file(),
                """
[build-system]
requires = ["setuptools"]
""",
            )

    def test_rejects_malformed_toml(self) -> None:
        with self.assertRaisesRegex(ValueError, 'Unable to parse pyproject.toml'):
            parse_pyproject_candidate(candidate_file(), '[project')

    def test_project_path_is_none_for_repository_root_pyproject(self) -> None:
        self.assertIsNone(
            project_path_from_candidate(candidate_file(file_path='pyproject.toml')),
        )

    def test_entrypoint_type_inference_uses_canonical_registry_terms(self) -> None:
        examples = {
            'example_parser': 'parser',
            'example_schema_package': 'schema',
            'example_app': 'app',
            'example_normalizer': 'normalizer',
            'example_example_upload': 'example_upload',
            'example_north_tool': 'north_tool',
            'example_api': 'api',
            'example_action': 'action',
            'example_dashboard': 'dashboard',
            'afm_example': 'example_upload',
            'example_unknown': 'unknown',
        }

        self.assertEqual(
            {
                name: infer_entrypoint_type(name, f'package.{name}:entrypoint')
                for name in examples.keys()
            },
            examples,
        )

    def test_dependency_name_falls_back_for_malformed_requirements(self) -> None:
        warnings: list[str] = []

        self.assertEqual(parse_dependency_name('bad req !!!', warnings), 'bad')
        self.assertEqual(
            warnings, ['Could not parse dependency requirement: bad req !!!']
        )

    def test_same_url_ignores_git_suffix_case_and_trailing_slash(self) -> None:
        self.assertTrue(
            same_url(
                'https://github.com/Example/Plugin.git/',
                'https://github.com/example/plugin',
            ),
        )


def candidate_file(
    *,
    file_path: str = 'packages/parser/pyproject.toml',
    repository_url: str = 'https://github.com/example/nomad-parser-example',
) -> GitHubCandidateFile:
    return GitHubCandidateFile(
        repository_full_name='example/nomad-parser-example',
        repository_url=repository_url,
        file_path=file_path,
        api_url=(
            'https://api.github.com/repos/example/nomad-parser-example/'
            f'contents/{file_path}'
        ),
        html_url=f'{repository_url}/blob/main/{file_path}',
        raw_url=(
            'https://raw.githubusercontent.com/example/nomad-parser-example/'
            f'main/{file_path}'
        ),
        default_branch='main',
    )


if __name__ == '__main__':
    unittest.main()
