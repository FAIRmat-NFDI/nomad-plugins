from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .crawler import crawl_pyproject_registry
from .registry import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_SNAPSHOT_PATH,
    load_config,
    load_snapshot,
    load_snapshot_data,
    validate_snapshot_data,
    write_snapshot,
)


def main() -> int:  # noqa: PLR0915
    parser = argparse.ArgumentParser(
        prog='plugin-registry',
        description='Maintain the static NOMAD plugin registry snapshot.',
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    validate_parser = subparsers.add_parser(
        'validate',
        help='Validate a plugin registry JSON snapshot.',
    )
    validate_parser.add_argument(
        '--input',
        type=Path,
        default=DEFAULT_SNAPSHOT_PATH,
        help=f'Path to the registry snapshot. Defaults to {DEFAULT_SNAPSHOT_PATH}.',
    )
    validate_parser.add_argument(
        '--config',
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f'Path to the crawler configuration. Defaults to {DEFAULT_CONFIG_PATH}.',
    )

    queries_parser = subparsers.add_parser(
        'github-queries',
        help='Print configured GitHub search queries without running them.',
    )
    queries_parser.add_argument(
        '--config',
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f'Path to the crawler configuration. Defaults to {DEFAULT_CONFIG_PATH}.',
    )

    crawl_parser = subparsers.add_parser(
        'crawl-pyprojects',
        help='Generate a registry snapshot from GitHub pyproject.toml discovery.',
    )
    crawl_parser.add_argument(
        '--config',
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f'Path to the crawler configuration. Defaults to {DEFAULT_CONFIG_PATH}.',
    )
    crawl_parser.add_argument(
        '--output',
        type=Path,
        help=(
            'Optional path to write the generated snapshot. Prints to stdout when '
            'omitted.'
        ),
    )
    crawl_parser.add_argument(
        '--legacy-output',
        type=Path,
        help=(
            'Optional path to write legacy NOMAD archive records for the '
            'plugin-crawler upload workflow.'
        ),
    )
    crawl_parser.add_argument(
        '--skip-format',
        action='store_true',
        help='Skip JSON formatting after writing the snapshot.',
    )
    crawl_parser.add_argument(
        '--skip-repository-search',
        action='store_true',
        help=(
            'Skip broad repository search and only use code-search pyproject '
            'discovery. Useful for quick local crawler tests.'
        ),
    )
    crawl_parser.add_argument(
        '--max-repository-candidates',
        type=int,
        default=None,
        help=(
            'Override github.maxRepositoryCandidates for this run. Use a small '
            'number for faster broad-discovery tests.'
        ),
    )
    crawl_parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress crawler progress messages.',
    )

    write_parser = subparsers.add_parser(
        'write-snapshot',
        help='Validate and atomically write a plugin registry JSON snapshot.',
    )
    write_parser.add_argument(
        '--input',
        type=Path,
        required=True,
        help='Path to the generated registry snapshot.',
    )
    write_parser.add_argument(
        '--output',
        type=Path,
        default=DEFAULT_SNAPSHOT_PATH,
        help=(
            'Path to write the validated snapshot. Defaults to '
            f'{DEFAULT_SNAPSHOT_PATH}.'
        ),
    )
    write_parser.add_argument(
        '--config',
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f'Path to the crawler configuration. Defaults to {DEFAULT_CONFIG_PATH}.',
    )

    args = parser.parse_args()

    if args.command == 'validate':
        config = load_config(args.config)
        snapshot = load_snapshot(args.input)
        enforce_quality(config, snapshot)

        print(
            json.dumps(
                {
                    'snapshot': str(args.input),
                    'schemaVersion': snapshot.schema_version,
                    'pluginCount': len(snapshot.plugins),
                    'registryVisibleCount': count_registry_visible(snapshot),
                    'warningCount': count_warnings(snapshot),
                },
                indent=2,
                sort_keys=True,
            ),
        )
        return 0

    if args.command == 'github-queries':
        config = load_config(args.config)
        search_queries = [
            *config['github']['searchQueries'],
            *config['github'].get('repositorySearchQueries', []),
        ]
        print(json.dumps(search_queries, indent=2))
        return 0

    if args.command == 'crawl-pyprojects':
        config = load_config(args.config)
        report = crawl_pyproject_registry(
            config,
            include_repository_search=not args.skip_repository_search,
            repository_candidate_limit=args.max_repository_candidates,
            progress=None if args.quiet else print_progress,
        )
        enforce_quality(config, validate_snapshot_data(report.snapshot))
        if args.legacy_output is not None:
            write_json(report.legacy_plugin_data, args.legacy_output)

        if args.output is None:
            print(json.dumps(report.snapshot, indent=2))
        else:
            write_snapshot(report.snapshot, args.output)
            formatted = False
            if not args.skip_format:
                formatted = format_snapshot(args.output)
                snapshot = load_snapshot(args.output)
                enforce_quality(config, snapshot)

            print(
                json.dumps(
                    {
                        'output': str(args.output),
                        'legacyOutput': str(args.legacy_output)
                        if args.legacy_output is not None
                        else None,
                        'pluginCount': report.parsed_count,
                        'registryVisibleCount': count_registry_visible(
                            validate_snapshot_data(report.snapshot),
                        ),
                        'fetchedCount': report.fetched_count,
                        'skippedCount': len(report.skipped),
                        'skipped': report.skipped,
                        'formatted': formatted,
                    },
                    indent=2,
                    sort_keys=True,
                ),
            )
        return 0

    if args.command == 'write-snapshot':
        config = load_config(args.config)
        snapshot_data = load_snapshot_data(args.input)
        snapshot = validate_snapshot_data(snapshot_data)
        enforce_quality(config, snapshot)
        write_snapshot(snapshot_data, args.output)

        print(
            json.dumps(
                {
                    'input': str(args.input),
                    'output': str(args.output),
                    'schemaVersion': snapshot.schema_version,
                    'pluginCount': len(snapshot.plugins),
                    'registryVisibleCount': count_registry_visible(snapshot),
                    'warningCount': count_warnings(snapshot),
                },
                indent=2,
                sort_keys=True,
            ),
        )
        return 0

    return 1


def enforce_quality(config, snapshot) -> None:
    plugin_count = count_registry_visible(snapshot)
    minimum_count = config['quality']['minimumPluginCount']

    if plugin_count < minimum_count:
        raise ValueError(
            f'Registry contains {plugin_count} visible plugins, expected at least '
            f'{minimum_count}.',
        )


def count_registry_visible(snapshot) -> int:
    return sum(1 for plugin in snapshot.plugins if plugin.registry_visible)


def count_warnings(snapshot) -> int:
    return sum(len(plugin.discovery_warnings) for plugin in snapshot.plugins)


def print_progress(message: str) -> None:
    print(message, file=sys.stderr)


def format_snapshot(path: Path) -> bool:
    prettier = shutil.which('prettier')
    if prettier is None:
        print(
            'prettier not found; leaving snapshot with Python JSON formatting.',
            file=sys.stderr,
        )
        return False

    subprocess.run([prettier, '--write', str(path)], check=True)

    return True


def write_json(data, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as output_file:
        json.dump(data, output_file, indent=2, sort_keys=True)
        output_file.write('\n')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'plugin registry error: {error}', file=sys.stderr)
        raise SystemExit(1)
