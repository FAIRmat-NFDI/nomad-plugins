import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from nomad_plugins.catalogue import (
    SCHEMA_VERSION,
    CatalogueSnapshot,
    CatalogueSourceSummary,
    build_catalogue_snapshot,
)
from nomad_plugins.crawler import Plugin, PluginReference

SCHEMA_PATH = Path(__file__).resolve().parents[1] / 'plugin-catalogue.schema.json'


def _plugin(
    name: str,
    *,
    repository: str | None = None,
    plugin_dependencies: list[PluginReference] | None = None,
) -> Plugin:
    return Plugin(
        repository=repository or f'https://github.com/example/{name}',
        stars=1,
        created='2024-01-01T00:00:00Z',
        last_updated='2024-01-02T00:00:00Z',
        owner='example',
        name=name,
        description=None,
        plugin_dependencies=plugin_dependencies or [],
        authors=[],
        maintainers=[],
        on_central=False,
        on_example_oasis=False,
        on_pypi=True,
        plugin_entry_points=[],
    )


def test_build_catalogue_snapshot_sorts_plugins_and_dependencies():
    snapshot = build_catalogue_snapshot(
        [
            _plugin(
                'zeta-plugin',
                plugin_dependencies=[
                    PluginReference(
                        name='zeta-dependency',
                        location='https://example.test/z',
                    ),
                    PluginReference(
                        name='alpha-dependency',
                        location='https://example.test/a',
                    ),
                ],
            ),
            _plugin('alpha-plugin'),
        ],
        data_updated_at=datetime(2024, 1, 3, tzinfo=UTC),
    )

    data = snapshot.model_dump(mode='json', by_alias=True, exclude_none=True)

    assert data['schemaVersion'] == '1.0.0'
    assert data['dataUpdatedAt'] == '2024-01-03T00:00:00Z'
    assert data['sourceSummary'] == {'pluginCount': 2}
    assert [plugin['name'] for plugin in data['plugins']] == [
        'alpha-plugin',
        'zeta-plugin',
    ]
    assert [
        dependency['name'] for dependency in data['plugins'][1]['plugin_dependencies']
    ] == ['alpha-dependency', 'zeta-dependency']


def test_catalogue_snapshot_rejects_duplicate_plugin_identities():
    with pytest.raises(ValidationError, match='Duplicate plugin identities'):
        CatalogueSnapshot(
            schema_version=SCHEMA_VERSION,
            source_summary=CatalogueSourceSummary(plugin_count=2),
            plugins=[
                _plugin('alpha-plugin'),
                _plugin(
                    'ALPHA-PLUGIN',
                    repository='https://github.com/example/alpha-plugin/',
                ),
            ],
        )


def test_catalogue_snapshot_rejects_source_summary_count_mismatch():
    with pytest.raises(ValidationError, match='sourceSummary.pluginCount'):
        CatalogueSnapshot(
            schema_version=SCHEMA_VERSION,
            source_summary=CatalogueSourceSummary(plugin_count=2),
            plugins=[_plugin('alpha-plugin')],
        )


def test_catalogue_snapshot_rejects_invalid_timestamp():
    with pytest.raises(ValidationError, match='dataUpdatedAt'):
        CatalogueSnapshot.model_validate(
            {
                'schemaVersion': '1.0.0',
                'dataUpdatedAt': 'not-a-timestamp',
                'sourceSummary': {'pluginCount': 0},
                'plugins': [],
            }
        )


def test_catalogue_snapshot_requires_schema_version():
    with pytest.raises(ValidationError, match='schemaVersion'):
        CatalogueSnapshot.model_validate(
            {
                'sourceSummary': {'pluginCount': 0},
                'plugins': [],
            }
        )


def test_catalogue_snapshot_rejects_unsupported_schema_version():
    with pytest.raises(ValidationError, match='schemaVersion'):
        CatalogueSnapshot.model_validate(
            {
                'schemaVersion': '1.0.1',
                'sourceSummary': {'pluginCount': 0},
                'plugins': [],
            }
        )


def test_catalogue_schema_file_is_current():
    current_schema = (
        json.dumps(
            CatalogueSnapshot.model_json_schema(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + '\n'
    )

    assert SCHEMA_PATH.read_text(encoding='utf-8') == current_schema
