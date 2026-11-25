"""Build a stable-ID review table without changing the catalogue snapshot."""

import csv
import json
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from nomad_plugins.catalogue import CatalogueSnapshot

REVIEW_FIELDS = (
    'Reviewer verdict',
    'Reviewer comment',
    'Expected handling',
    'Evidence URL',
)
REVIEW_VERDICTS = (
    '',
    'Looks right',
    'Should be hidden',
    'Should be excluded',
    'Should be visible',
    'Metadata wrong',
    'Needs research',
)
REVIEW_COLUMNS = (
    'Review group',
    'Name',
    'Stable ID',
    'Original stable ID',
    'Presence',
    'Visibility',
    'Visibility reason',
    'Move basis',
    *REVIEW_FIELDS,
    'Repository URL',
    'Original repository URL',
    'pyproject.toml URL',
    'Documentation URL',
    'PyPI URL',
    'Original catalogue URL',
    'Current kind',
    'Original kind',
    'Current plugin types',
    'Original plugin types',
    'Audit flags',
    'Owner',
    'Owner type',
    'Archived',
    'Fork',
    'Entry point count',
    'Warnings',
)
GROUP_ORDER = (
    'Moved',
    'Reference plugin absent',
    'Hidden plugin',
    'Potential link collision',
    'New visible',
    'Changed classification or types',
    'Other visible',
    'Hidden non-plugin',
    'Reference-only non-plugin',
    'Prior-review only',
)


@dataclass(frozen=True)
class ReviewMove:
    original_id: str
    current_id: str
    basis: str


def load_review_moves(path: Path | None) -> dict[str, ReviewMove]:
    """Load explicit, one-to-one ID moves for a particular comparison."""
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    entries = data['moves']
    if not isinstance(entries, list):
        raise ValueError('Review moves must be a list.')
    moves = {}
    target_ids = set()
    for entry in entries:
        original_id = entry['originalId']
        current_id = entry['currentId']
        basis = entry['basis']
        if not all(
            isinstance(value, str) and value.strip()
            for value in (original_id, current_id, basis)
        ):
            raise ValueError('Review moves require non-empty IDs and basis.')
        old_key = original_id.casefold()
        new_key = current_id.casefold()
        if old_key == new_key or old_key in moves or new_key in target_ids:
            raise ValueError(
                f'Duplicate or self-referential move: {original_id} => {current_id}'
            )
        moves[old_key] = ReviewMove(original_id, current_id, basis)
        target_ids.add(new_key)
    return moves


def load_reference(path: Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    plugins = data['plugins']
    if not isinstance(plugins, list):
        raise ValueError('Reference plugins must be a list.')
    return _index_by_id(plugins, source='reference')


def load_previous_review(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    if path.suffix.lower() == '.json':
        payload = json.loads(path.read_text(encoding='utf-8'))
        if (
            payload.get('format') != 'nomad-catalogue-review'
            or payload.get('version') != 1
            or not isinstance(payload.get('records'), dict)
        ):
            raise ValueError('Not a catalogue review JSON export (version 1).')
        rows = []
        for stable_id, record in payload['records'].items():
            fields = record['fields']
            if not isinstance(fields, dict) or any(
                not isinstance(fields.get(key, ''), str) for key in REVIEW_FIELDS
            ):
                raise ValueError('Review JSON fields must contain text.')
            if fields.get('Reviewer verdict', '') not in REVIEW_VERDICTS:
                raise ValueError('Unknown reviewer verdict in review JSON.')
            if record.get('conflicts'):
                raise ValueError(
                    'Resolve imported conflicts in the browser before using '
                    'the JSON as --previous.'
                )
            row = record['row']
            if row['Stable ID'].casefold() != stable_id.casefold():
                raise ValueError('Review row and stable ID disagree.')
            rows.append({**row, **fields})
        return _index_by_id(rows, source='previous review')
    with path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {'Stable ID', *REVIEW_FIELDS}.issubset(
            reader.fieldnames
        ):
            raise ValueError(
                'Previous review is missing stable ID or reviewer columns.'
            )
        return _index_by_id(list(reader), source='previous review')


def build_review_rows(  # noqa: PLR0912, PLR0915
    snapshot: CatalogueSnapshot,
    *,
    reference: dict[str, dict] | None = None,
    previous: dict[str, dict[str, str]] | None = None,
    moves: dict[str, ReviewMove] | None = None,
) -> list[dict[str, str]]:
    """Include visible, hidden, missing and previously annotated IDs."""
    current = _index_by_id(
        [
            plugin.model_dump(mode='json', by_alias=True, exclude_none=True)
            for plugin in snapshot.plugins
        ],
        source='current snapshot',
    )
    reference = reference or {}
    previous = previous or {}
    moves = moves or {}
    for original_id, move in moves.items():
        target_id = move.current_id.casefold()
        if original_id not in reference or original_id in current:
            raise ValueError(
                f'Review move source is not original-only: {move.original_id}'
            )
        if target_id not in current or target_id in reference:
            raise ValueError(
                f'Review move target is not current-only: {move.current_id}'
            )
    moves_by_current = {move.current_id.casefold(): move for move in moves.values()}
    pypi_repositories: dict[str, set[str]] = {}
    for plugin in current.values():
        pypi_url = plugin.get('pypiUrl')
        if pypi_url:
            pypi_repositories.setdefault(pypi_url.casefold(), set()).add(
                plugin['repositoryUrl'].casefold()
            )
    pypi_collisions = {
        url for url, repositories in pypi_repositories.items() if len(repositories) > 1
    }

    rows = []
    review_ids = (current.keys() | reference.keys() | previous.keys()) - moves.keys()
    for stable_id in review_ids:
        move = moves_by_current.get(stable_id)
        plugin = current.get(stable_id)
        original = reference.get(move.original_id.casefold() if move else stable_id)
        prior = previous.get(stable_id, {})
        prior_original = previous.get(move.original_id.casefold(), {}) if move else {}
        source = plugin or original
        flags = []
        if move:
            presence = 'Moved ID'
        elif plugin and original:
            presence = 'Current and original'
        elif plugin:
            presence = 'Current only'
        elif original:
            presence = 'Original only'
        else:
            presence = 'Prior review only'

        if plugin:
            visibility = 'Visible' if plugin['registryVisible'] else 'Hidden'
            reasons = _visibility_reasons(plugin)
            if plugin.get('pypiUrl', '').casefold() in pypi_collisions:
                flags.append('PyPI URL shared by different repositories')
            if plugin.get('discoveryWarnings'):
                flags.append('Discovery warning')
            if original and plugin['projectKind'] != original['projectKind']:
                flags.append('Project kind changed')
            if original and plugin.get('pluginTypes') != original.get('pluginTypes'):
                flags.append('Plugin types changed')
            if original and plugin.get('entrypoints') != original.get('entrypoints'):
                flags.append('Entry points changed')
        else:
            visibility = 'Absent'
            reasons = []

        if move:
            group = 'Moved'
        elif not plugin and original and original['projectKind'] == 'plugin':
            group = 'Reference plugin absent'
        elif (
            plugin
            and plugin['projectKind'] == 'plugin'
            and not plugin['registryVisible']
        ):
            group = 'Hidden plugin'
        elif 'PyPI URL shared by different repositories' in flags:
            group = 'Potential link collision'
        elif plugin and not original and plugin['registryVisible']:
            group = 'New visible'
        elif 'Project kind changed' in flags or 'Plugin types changed' in flags:
            group = 'Changed classification or types'
        elif plugin and plugin['registryVisible']:
            group = 'Other visible'
        elif plugin:
            group = 'Hidden non-plugin'
        elif original:
            group = 'Reference-only non-plugin'
        else:
            group = 'Prior-review only'

        row = {column: '' for column in REVIEW_COLUMNS}
        row.update(
            {
                'Review group': group,
                'Name': source['name'] if source else prior.get('Name', ''),
                'Stable ID': source['id'] if source else prior['Stable ID'],
                'Original stable ID': original['id'] if move else '',
                'Presence': presence,
                'Visibility': visibility,
                'Visibility reason': '; '.join(reasons),
                'Move basis': move.basis if move else '',
                'Repository URL': source.get('repositoryUrl', '')
                if source
                else prior.get('Repository URL', ''),
                'Original repository URL': original.get('repositoryUrl', '')
                if original
                else prior.get('Original repository URL', ''),
                'pyproject.toml URL': _pyproject_url(source)
                if source
                else prior.get('pyproject.toml URL', ''),
                'Documentation URL': (source.get('documentationUrl') or '')
                if source
                else prior.get('Documentation URL', ''),
                'PyPI URL': (source.get('pypiUrl') or '')
                if source
                else prior.get('PyPI URL', ''),
                'Original catalogue URL': _original_url(original)
                if original
                else prior.get('Original catalogue URL', ''),
                'Current kind': plugin['projectKind'] if plugin else '',
                'Original kind': original['projectKind'] if original else '',
                'Current plugin types': ', '.join(plugin.get('pluginTypes') or [])
                if plugin
                else '',
                'Original plugin types': ', '.join(original.get('pluginTypes') or [])
                if original
                else '',
                'Audit flags': '; '.join(flags),
                'Owner': source.get('owner', '') if source else prior.get('Owner', ''),
                'Owner type': source.get('ownerType', '')
                if source
                else prior.get('Owner type', ''),
                'Archived': str(source.get('status', {}).get('archived', ''))
                if source
                else prior.get('Archived', ''),
                'Fork': str(source.get('status', {}).get('fork', ''))
                if source
                else prior.get('Fork', ''),
                'Entry point count': str(len(plugin.get('entrypoints', [])))
                if plugin
                else '',
                'Warnings': '; '.join(plugin.get('discoveryWarnings', []))
                if plugin
                else '',
            }
        )
        for column in REVIEW_FIELDS:
            current_value = prior.get(column, '')
            original_value = prior_original.get(column, '')
            if current_value and original_value and current_value != original_value:
                raise ValueError(
                    f'Conflicting reviewer values for moved ID {row["Stable ID"]}: '
                    f'{column}'
                )
            row[column] = current_value or original_value
        rows.append(row)

    order = {group: rank for rank, group in enumerate(GROUP_ORDER)}
    return sorted(
        rows,
        key=lambda row: (
            order[row['Review group']],
            row['Name'].casefold(),
            row['Stable ID'].casefold(),
        ),
    )


def write_review_csv(rows: list[dict[str, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            'w',
            encoding='utf-8-sig',
            newline='',
            dir=output.parent,
            prefix=f'.{output.name}.',
            suffix='.tmp',
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=REVIEW_COLUMNS)
            writer.writeheader()
            writer.writerows(
                {column: _safe_csv_value(row[column]) for column in REVIEW_COLUMNS}
                for row in rows
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output)
    except Exception:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        raise


def review_summary(rows: list[dict[str, str]]) -> dict[str, int]:
    return dict(Counter(row['Review group'] for row in rows))


def _index_by_id(rows: list[dict], *, source: str) -> dict[str, dict]:
    indexed = {}
    for row in rows:
        stable_id = row['Stable ID'] if source == 'previous review' else row['id']
        if not isinstance(stable_id, str) or not stable_id.strip():
            raise ValueError(f'Missing stable ID in {source}.')
        key = stable_id.casefold()
        if key in indexed:
            raise ValueError(f'Duplicate stable ID in {source}: {stable_id}')
        indexed[key] = row
    return indexed


def _visibility_reasons(plugin: dict) -> list[str]:
    if plugin['registryVisible']:
        return []
    reasons = []
    if plugin['status']['archived']:
        reasons.append('archived repository')
    if plugin['status']['fork']:
        reasons.append('fork')
    if plugin['projectKind'] not in {
        'plugin',
        'nomad_dependent_package',
        'official_template',
        'official_software',
    }:
        reasons.append(f'project kind: {plugin["projectKind"]}')
    return reasons or ['visibility policy requires review']


def _pyproject_url(plugin: dict) -> str:
    if plugin.get('metadataSource') == 'crawler-config':
        return ''
    repository_url = plugin['repositoryUrl'].rstrip('/')
    branch = plugin.get('status', {}).get('defaultBranch')
    if not branch:
        return ''
    project_path = plugin['id'].split('#', 1)[1] if '#' in plugin['id'] else ''
    parts = [part for part in project_path.split('/') if part]
    parts.append('pyproject.toml')
    encoded_path = '/'.join(quote(part, safe='') for part in parts)
    return f'{repository_url}/blob/{quote(branch, safe="")}/{encoded_path}'


def _original_url(plugin: dict) -> str:
    if not plugin.get('registryVisible'):
        return ''
    anchor = re.sub(r'[^a-z0-9]+', '-', plugin['id'].lower()).strip('-')
    return f'https://about.nomad-lab.eu/plugin-registry#plugin-{anchor}'


def _safe_csv_value(value: str) -> str:
    """Avoid evaluating repository metadata or comments as spreadsheet formulas."""
    return f"'{value}" if value.lstrip().startswith(('=', '+', '-', '@')) else value
