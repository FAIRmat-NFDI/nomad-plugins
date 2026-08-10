from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nomad_plugins.cli import format_snapshot, main

FIXTURES_PATH = Path(__file__).resolve().parent / 'fixtures'


class PluginRegistryCliTests(unittest.TestCase):
    def test_github_queries_prints_code_and_repository_queries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = Path(temporary_directory) / 'config.json'
            config_path.write_text(
                json.dumps(
                    {
                        'github': {
                            'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                            'repositorySearchQueries': ['topic:north-tool'],
                            'excludeCandidates': [],
                        },
                        'quality': {'minimumPluginCount': 0},
                    },
                ),
            )
            stdout = io.StringIO()

            with (
                patch.object(
                    sys,
                    'argv',
                    [
                        'python -m nomad_plugins.cli',
                        'github-queries',
                        '--config',
                        str(config_path),
                    ],
                ),
                patch('sys.stdout', stdout),
            ):
                exit_code = main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            ['nomad.plugin filename:pyproject.toml', 'topic:north-tool'],
        )

    def test_crawl_pyprojects_can_skip_repository_search(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            config_path = temporary_path / 'config.json'
            output_path = temporary_path / 'plugin-registry.json'
            config_path.write_text(
                json.dumps(
                    {
                        'github': {
                            'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                            'repositorySearchQueries': ['topic:north-tool'],
                            'excludeCandidates': [],
                        },
                        'quality': {'minimumPluginCount': 0},
                    },
                ),
            )
            snapshot = json.loads((FIXTURES_PATH / 'valid-snapshot.json').read_text())
            report = type(
                'Report',
                (),
                {
                    'snapshot': snapshot,
                    'parsed_count': 1,
                    'fetched_count': 1,
                    'skipped': [],
                },
            )()
            stdout = io.StringIO()

            with (
                patch.object(
                    sys,
                    'argv',
                    [
                        'plugin-registry',
                        'crawl-pyprojects',
                        '--config',
                        str(config_path),
                        '--output',
                        str(output_path),
                        '--skip-format',
                        '--skip-repository-search',
                        '--max-repository-candidates',
                        '5',
                        '--quiet',
                    ],
                ),
                patch(
                    'nomad_plugins.cli.crawl_pyproject_registry',
                    return_value=report,
                ) as crawl,
                patch('sys.stdout', stdout),
            ):
                exit_code = main()
            output_exists = output_path.exists()

        self.assertEqual(exit_code, 0)
        self.assertTrue(output_exists)
        crawl.assert_called_once()
        _, kwargs = crawl.call_args
        self.assertFalse(kwargs['include_repository_search'])
        self.assertEqual(kwargs['repository_candidate_limit'], 5)
        self.assertIsNone(kwargs['progress'])

    def test_format_snapshot_does_not_fall_back_to_npx(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            snapshot_path = Path(temporary_directory) / 'plugin-registry.json'
            snapshot_path.write_text(json.dumps({'schemaVersion': 1}))

            with (
                patch(
                    'nomad_plugins.cli.shutil.which',
                    side_effect=lambda command: (
                        '/usr/bin/npx' if command == 'npx' else None
                    ),
                ),
                patch('nomad_plugins.cli.subprocess.run') as run,
            ):
                formatted = format_snapshot(snapshot_path)

        self.assertFalse(formatted)
        run.assert_not_called()

    def test_format_snapshot_can_skip_when_formatter_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            snapshot_path = Path(temporary_directory) / 'plugin-registry.json'
            snapshot_path.write_text(json.dumps({'schemaVersion': 1}))

            with (
                patch(
                    'nomad_plugins.cli.shutil.which',
                    return_value=None,
                ),
                patch('nomad_plugins.cli.subprocess.run') as run,
            ):
                formatted = format_snapshot(snapshot_path)

        self.assertFalse(formatted)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
