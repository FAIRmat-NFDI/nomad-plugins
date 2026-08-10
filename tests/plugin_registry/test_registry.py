from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from nomad_plugins.registry import (
    load_config,
    load_snapshot,
    load_snapshot_data,
    write_snapshot,
)

FIXTURES_PATH = Path(__file__).resolve().parent / 'fixtures'


class RegistrySnapshotTests(unittest.TestCase):
    def test_loads_valid_fixture(self) -> None:
        snapshot = load_snapshot(FIXTURES_PATH / 'valid-snapshot.json')

        self.assertEqual(snapshot.schema_version, 2)
        self.assertEqual(snapshot.data_updated_at, '2026-07-20T00:00:00Z')
        self.assertEqual(len(snapshot.plugins), 1)
        self.assertEqual(
            snapshot.plugins[0].id, 'github.com/example/nomad-parser#packages/parser'
        )
        self.assertEqual(snapshot.plugins[0].name, 'Example NOMAD Parser')
        self.assertEqual(snapshot.plugins[0].discovery_warnings, ['Fixture warning'])

    def test_rejects_duplicate_plugin_ids(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')
        snapshot['plugins'].append(copy.deepcopy(snapshot['plugins'][0]))
        snapshot['sourceSummary']['pluginCount'] = 2
        snapshot['sourceSummary']['registryVisibleCount'] = 2
        snapshot['sourceSummary']['projectKindCounts'] = {'plugin': 2}
        snapshot['sourceSummary']['warningCount'] = 2

        with self.assertRaisesRegex(ValueError, 'Duplicate plugin id'):
            write_snapshot(snapshot, Path('/tmp/unused-plugin-registry.json'))

    def test_rejects_invalid_urls(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')
        snapshot['plugins'][0]['repositoryUrl'] = 'javascript:alert(1)'

        with self.assertRaisesRegex(ValueError, 'repositoryUrl must be an http'):
            write_snapshot(snapshot, Path('/tmp/unused-plugin-registry.json'))

    def test_rejects_count_mismatch(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')
        snapshot['sourceSummary']['pluginCount'] = 2

        with self.assertRaisesRegex(ValueError, 'sourceSummary.pluginCount'):
            write_snapshot(snapshot, Path('/tmp/unused-plugin-registry.json'))

    def test_rejects_warning_count_mismatch(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')
        snapshot['sourceSummary']['warningCount'] = 0

        with self.assertRaisesRegex(ValueError, 'sourceSummary.warningCount'):
            write_snapshot(snapshot, Path('/tmp/unused-plugin-registry.json'))

    def test_accepts_fork_lineage_status_urls(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')
        snapshot['plugins'][0]['status']['fork'] = True
        snapshot['plugins'][0]['status']['parentRepositoryUrl'] = (
            'https://github.com/example/parent-parser'
        )
        snapshot['plugins'][0]['status']['sourceRepositoryUrl'] = (
            'https://github.com/example/source-parser'
        )

        written_snapshot = write_snapshot(
            snapshot, Path('/tmp/unused-plugin-registry.json')
        )

        self.assertEqual(
            written_snapshot.plugins[0].id,
            'github.com/example/nomad-parser#packages/parser',
        )

    def test_rejects_invalid_fork_lineage_status_urls(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')
        snapshot['plugins'][0]['status']['parentRepositoryUrl'] = 'javascript:alert(1)'

        with self.assertRaisesRegex(ValueError, 'parentRepositoryUrl must be an http'):
            write_snapshot(snapshot, Path('/tmp/unused-plugin-registry.json'))

    def test_writes_valid_snapshot_atomically(self) -> None:
        snapshot = load_fixture('valid-snapshot.json')

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / 'plugin-registry.json'
            written_snapshot = write_snapshot(snapshot, output_path)

            self.assertTrue(output_path.exists())
            self.assertEqual(written_snapshot.schema_version, 2)
            self.assertEqual(
                load_snapshot(output_path).plugins[0].name, 'Example NOMAD Parser'
            )
            self.assertEqual(output_path.read_text().splitlines()[0], '{')

    def test_loads_config_with_candidate_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / 'config.json'
            config_path.write_text(
                json.dumps(
                    {
                        'github': {
                            'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                            'excludeCandidates': ['github.com/example/template-plugin'],
                        },
                        'quality': {'minimumPluginCount': 0},
                    },
                ),
            )

            config = load_config(config_path)

        self.assertEqual(
            config['github']['excludeCandidates'],
            ['github.com/example/template-plugin'],
        )

    def test_rejects_empty_candidate_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / 'config.json'
            config_path.write_text(
                json.dumps(
                    {
                        'github': {
                            'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                            'excludeCandidates': [''],
                        },
                        'quality': {'minimumPluginCount': 0},
                    },
                ),
            )

            with self.assertRaisesRegex(ValueError, 'excludeCandidates'):
                load_config(config_path)


def load_fixture(name: str) -> dict:
    return copy.deepcopy(load_snapshot_data(FIXTURES_PATH / name))


if __name__ == '__main__':
    unittest.main()
