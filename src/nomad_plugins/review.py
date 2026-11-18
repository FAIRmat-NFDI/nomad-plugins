"""Build a stable-ID review table without changing the catalogue snapshot."""

import csv
import json
import os
import re
import tempfile
from collections import Counter
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
    'Presence',
    'Visibility',
    'Visibility reason',
    *REVIEW_FIELDS,
    'Repository URL',
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
    for stable_id in current.keys() | reference.keys() | previous.keys():
        plugin = current.get(stable_id)
        original = reference.get(stable_id)
        prior = previous.get(stable_id, {})
        source = plugin or original
        flags = []
        if plugin and original:
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

        if not plugin and original and original['projectKind'] == 'plugin':
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
                'Presence': presence,
                'Visibility': visibility,
                'Visibility reason': '; '.join(reasons),
                'Repository URL': source.get('repositoryUrl', '')
                if source
                else prior.get('Repository URL', ''),
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
            row[column] = prior.get(column, '')
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
