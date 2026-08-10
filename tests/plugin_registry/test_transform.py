from __future__ import annotations

import unittest

from nomad_plugins.registry import validate_snapshot_data
from nomad_plugins.transform import (
    PROJECT_KIND_DISTRIBUTION,
    DiscoveredAuthor,
    DiscoveredDeployment,
    DiscoveredEntrypoint,
    DiscoveredPlugin,
    DiscoveredStatus,
    build_registry_snapshot,
    discovered_plugins_to_legacy_plugin_data,
    snapshot_to_legacy_plugin_data,
    stable_plugin_id,
)


class RegistryTransformTests(unittest.TestCase):
    def test_builds_valid_snapshot(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    name='Beta Plugin',
                    repository_url='https://github.com/Example/beta-plugin.git',
                    project_path='packages/beta',
                    warnings=['Needs metadata review'],
                ),
                discovered_plugin(
                    name='Alpha Plugin',
                    repository_url='https://github.com/example/alpha-plugin',
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        validated_snapshot = validate_snapshot_data(snapshot)

        self.assertEqual(validated_snapshot.schema_version, 2)
        self.assertEqual(snapshot['sourceSummary']['pluginCount'], 2)
        self.assertEqual(snapshot['sourceSummary']['registryVisibleCount'], 2)
        self.assertEqual(snapshot['sourceSummary']['projectKindCounts'], {'plugin': 2})
        self.assertEqual(snapshot['sourceSummary']['warningCount'], 1)
        self.assertEqual(
            [plugin['name'] for plugin in snapshot['plugins']],
            ['Alpha Plugin', 'Beta Plugin'],
        )
        self.assertEqual(
            snapshot['plugins'][1]['id'],
            'github.com/example/beta-plugin#packages/beta',
        )

    def test_derives_plugin_types_from_entrypoints(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    entrypoints=[
                        DiscoveredEntrypoint(
                            name='schema',
                            module='example.schema:entrypoint',
                            type='Schema Package',
                        ),
                        DiscoveredEntrypoint(
                            name='parser',
                            module='example.parser:entrypoint',
                            type='parser',
                        ),
                    ],
                    plugin_types=['Normalizer', 'parser'],
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        self.assertEqual(
            snapshot['plugins'][0]['pluginTypes'],
            ['normalizer', 'parser', 'schema'],
        )

    def test_normalizes_dependencies(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    dependencies=['NOMAD_Lab', 'nomad-lab', ' Example_Dep '],
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        self.assertEqual(
            snapshot['plugins'][0]['dependencies'], ['example-dep', 'nomad-lab']
        )

    def test_preserves_hidden_project_kind_counts(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    name='Example Oasis',
                    entrypoints=[],
                    plugin_types=['unknown'],
                    project_kind=PROJECT_KIND_DISTRIBUTION,
                    registry_visible=False,
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        self.assertEqual(snapshot['sourceSummary']['pluginCount'], 1)
        self.assertEqual(snapshot['sourceSummary']['registryVisibleCount'], 0)
        self.assertEqual(
            snapshot['sourceSummary']['projectKindCounts'], {'distribution': 1}
        )
        self.assertEqual(snapshot['plugins'][0]['projectKind'], 'distribution')
        self.assertFalse(snapshot['plugins'][0]['registryVisible'])

    def test_uses_repository_owner_when_owner_is_missing(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    owner=None,
                    repository_url='https://github.com/fairmat-nfdi/example-plugin',
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        self.assertEqual(snapshot['plugins'][0]['owner'], 'fairmat-nfdi')

    def test_preserves_owner_type(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    owner='example-org',
                    owner_type='Organization',
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        self.assertEqual(snapshot['plugins'][0]['ownerType'], 'Organization')

    def test_omits_empty_optional_fields(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    documentation_url=' ',
                    pypi_url=None,
                    owner_type='',
                    owner_group='',
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        plugin = snapshot['plugins'][0]
        self.assertNotIn('documentationUrl', plugin)
        self.assertNotIn('pypiUrl', plugin)
        self.assertNotIn('ownerGroup', plugin)

    def test_stable_plugin_id_normalizes_git_suffix_and_subpath(self) -> None:
        self.assertEqual(
            stable_plugin_id(
                'https://github.com/Example/NOMAD-Plugin.git',
                './packages//parser/',
            ),
            'github.com/example/nomad-plugin#packages/parser',
        )

    def test_projects_snapshot_to_legacy_plugin_data(self) -> None:
        snapshot = build_registry_snapshot(
            [
                discovered_plugin(
                    repository_url='https://github.com/example/example-plugin',
                    project_path='packages/parser',
                    entrypoints=[
                        DiscoveredEntrypoint(
                            name='example_parser',
                            module='example.parsers:entrypoint',
                            type='parser',
                        ),
                        DiscoveredEntrypoint(
                            name='example_north_tool',
                            module='example.north:entrypoint',
                            type='north_tool',
                        ),
                    ],
                    dependencies=['nomad-lab', 'nomad-baseclasses'],
                ),
                discovered_plugin(
                    name='Dependency Package',
                    entrypoints=[],
                    plugin_types=[],
                    project_kind='nomad_dependent_package',
                ),
            ],
            data_updated_at='2026-07-20T00:00:00Z',
            discovery='unit-test',
        )

        legacy_plugins = snapshot_to_legacy_plugin_data(snapshot)

        self.assertEqual(len(legacy_plugins), 1)
        legacy_plugin = legacy_plugins[0]['data']
        self.assertEqual(
            legacy_plugin['m_def'],
            'nomad_plugins.schema_packages.plugin.Plugin',
        )
        self.assertEqual(legacy_plugin['toml_directory'], 'packages/parser')
        self.assertTrue(legacy_plugin['on_central'])
        self.assertTrue(legacy_plugin['on_pypi'])
        entrypoints_by_name = {
            entrypoint['name']: entrypoint
            for entrypoint in legacy_plugin['plugin_entry_points']
        }
        self.assertEqual(entrypoints_by_name['example_parser']['type'], 'Parser')
        self.assertNotIn('type', entrypoints_by_name['example_north_tool'])
        self.assertEqual(
            legacy_plugin['plugin_dependencies'],
            [
                {
                    'm_def': 'nomad_plugins.schema_packages.plugin.PluginReference',
                    'name': 'nomad-baseclasses',
                    'location': 'https://pypi.org/project/nomad-baseclasses/',
                },
            ],
        )

    def test_builds_legacy_plugin_data_from_discovered_records(self) -> None:
        legacy_plugins = discovered_plugins_to_legacy_plugin_data(
            [
                discovered_plugin(
                    name='Example Plugin',
                    authors=[DiscoveredAuthor(name='Ada', email='ada@example.org')],
                    maintainers=[DiscoveredAuthor(name='Grace')],
                    dependencies=['nomad-lab', 'helper-plugin', 'numpy'],
                    on_pypi=False,
                ),
                discovered_plugin(
                    name='Helper Plugin',
                    repository_url='https://github.com/example/helper-plugin',
                    on_pypi=True,
                ),
            ],
        )

        legacy_plugin = legacy_plugins[0]['data']

        self.assertFalse(legacy_plugin['on_pypi'])
        self.assertEqual(
            legacy_plugin['authors'],
            [{'name': 'Ada', 'email': 'ada@example.org'}],
        )
        self.assertEqual(legacy_plugin['maintainers'], [{'name': 'Grace'}])
        self.assertEqual(
            legacy_plugin['plugin_dependencies'],
            [
                {
                    'm_def': 'nomad_plugins.schema_packages.plugin.PluginReference',
                    'name': 'helper-plugin',
                    'location': 'https://github.com/example/helper-plugin',
                    'toml_directory': '',
                },
            ],
        )


def discovered_plugin(  # noqa: PLR0913
    *,
    name: str = 'Example Plugin',
    repository_url: str = 'https://github.com/example/example-plugin',
    project_path: str | None = None,
    owner: str | None = 'example',
    owner_type: str | None = None,
    owner_group: str | None = 'community',
    documentation_url: str | None = 'https://example.github.io/example-plugin',
    pypi_url: str | None = 'https://pypi.org/project/example-plugin/',
    entrypoints: list[DiscoveredEntrypoint] | None = None,
    plugin_types: list[str] | None = None,
    dependencies: list[str] | None = None,
    warnings: list[str] | None = None,
    authors: list[DiscoveredAuthor] | None = None,
    maintainers: list[DiscoveredAuthor] | None = None,
    on_pypi: bool = True,
    project_kind: str = 'plugin',
    registry_visible: bool = True,
) -> DiscoveredPlugin:
    return DiscoveredPlugin(
        name=name,
        description=f'{name} description.',
        repository_url=repository_url,
        project_path=project_path,
        documentation_url=documentation_url,
        pypi_url=pypi_url,
        owner=owner,
        owner_type=owner_type,
        owner_group=owner_group,
        entrypoints=entrypoints
        if entrypoints is not None
        else [
            DiscoveredEntrypoint(
                name='example_parser',
                module='example_plugin:entrypoint',
                type='parser',
            ),
        ],
        plugin_types=plugin_types if plugin_types is not None else [],
        dependencies=dependencies if dependencies is not None else ['nomad-lab'],
        authors=authors if authors is not None else [],
        maintainers=maintainers if maintainers is not None else [],
        on_pypi=on_pypi,
        status=DiscoveredStatus(
            archived=False,
            fork=False,
            stars=5,
            created_at='2025-01-01T00:00:00Z',
            last_pushed_at='2026-07-01T00:00:00Z',
        ),
        deployment=DiscoveredDeployment(on_central=True, on_example_oasis=False),
        project_kind=project_kind,
        registry_visible=registry_visible,
        metadata_source='unit-test',
        discovery_warnings=warnings if warnings is not None else [],
    )


if __name__ == '__main__':
    unittest.main()
