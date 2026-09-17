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
from nomad_plugins.crawler import DeploymentInfo, Plugin, RepositoryStatus
from nomad_plugins.pyproject import PluginEntryPoint

SCHEMA_PATH = Path(__file__).resolve().parents[1] / 'plugin-catalogue.schema.json'


def _plugin(  # noqa: PLR0913
    name: str,
    *,
    plugin_id: str | None = None,
    project_kind: str = 'plugin',
    registry_visible: bool = True,
    entrypoints: list[PluginEntryPoint] | None = None,
    plugin_types: list[str] | None = None,
    dependencies: list[str] | None = None,
    discovery_warnings: list[str] | None = None,
) -> Plugin:
    return Plugin(
        id=plugin_id or f'github.com/example/{name}',
        name=name,
        repository_url=f'https://github.com/example/{name}',
        owner='example',
        entrypoints=entrypoints or [],
        plugin_types=plugin_types,
        dependencies=dependencies or [],
        status=RepositoryStatus(
            archived=False,
            fork=False,
            stars=1,
            created_at='2024-01-01T00:00:00Z',
            last_pushed_at='2024-01-02T00:00:00Z',
        ),
        deployment=DeploymentInfo(
            on_central=False,
            on_example_oasis=False,
        ),
        project_kind=project_kind,
        registry_visible=registry_visible,
        metadata_source='pyproject.toml',
        discovery_warnings=discovery_warnings or [],
    )


def _summary(plugin_count: int) -> CatalogueSourceSummary:
    return CatalogueSourceSummary(
        plugin_count=plugin_count,
        registry_visible_count=plugin_count,
        project_kind_counts={'plugin': plugin_count} if plugin_count else {},
        warning_count=0,
    )


def test_build_catalogue_snapshot_normalizes_public_output():
    snapshot = build_catalogue_snapshot(
        [
            _plugin(
                'zeta-plugin',
                entrypoints=[
                    PluginEntryPoint(
                        name='zeta.parser',
                        module='zeta.parser:entry',
                        type='parser',
                    ),
                    PluginEntryPoint(
                        name='zeta.app',
                        module='zeta.app:entry',
                        type='app',
                    ),
                ],
                plugin_types=['parser', 'app'],
                dependencies=['zeta-dependency', 'alpha-dependency'],
                discovery_warnings=['Z warning', 'A warning'],
            ),
            _plugin(
                'alpha-package',
                project_kind='ecosystem_package',
                registry_visible=False,
            ),
        ],
        data_updated_at=datetime(2024, 1, 3, tzinfo=UTC),
    )

    data = snapshot.model_dump(mode='json', by_alias=True, exclude_none=True)

    assert data['schemaVersion'] == '2.0.0'
    assert data['dataUpdatedAt'] == '2024-01-03T00:00:00Z'
    assert data['sourceSummary'] == {
        'pluginCount': 2,
        'registryVisibleCount': 1,
        'projectKindCounts': {'ecosystem_package': 1, 'plugin': 1},
        'warningCount': 2,
    }
    assert [plugin['name'] for plugin in data['plugins']] == [
        'alpha-package',
        'zeta-plugin',
    ]
    assert data['plugins'][0]['pluginTypes'] is None
    assert data['plugins'][1]['pluginTypes'] == ['app', 'parser']
    assert data['plugins'][1]['dependencies'] == [
        'alpha-dependency',
        'zeta-dependency',
    ]
    assert [entrypoint['type'] for entrypoint in data['plugins'][1]['entrypoints']] == [
        'app',
        'parser',
    ]
    assert data['plugins'][1]['discoveryWarnings'] == ['A warning', 'Z warning']


def test_plugin_public_contract_excludes_crawler_only_metadata():
    plugin = _plugin('alpha-plugin')
    plugin = plugin.model_copy(
        update={
            'project_path': 'packages/alpha',
            'declared_repository_url': 'https://example.com/declared',
            'homepage_url': 'https://example.com',
            'issues_url': 'https://example.com/issues',
        }
    )

    data = plugin.model_dump(mode='json', by_alias=True, exclude_none=True)

    assert set(data) == {
        'id',
        'name',
        'description',
        'repositoryUrl',
        'owner',
        'entrypoints',
        'pluginTypes',
        'dependencies',
        'status',
        'deployment',
        'projectKind',
        'registryVisible',
        'metadataSource',
        'discoveryWarnings',
    }


def test_catalogue_snapshot_rejects_duplicate_plugin_ids():
    with pytest.raises(ValidationError, match='Duplicate plugin identities'):
        CatalogueSnapshot(
            schema_version=SCHEMA_VERSION,
            source_summary=_summary(2),
            plugins=[
                _plugin('alpha-plugin'),
                _plugin('another-name', plugin_id='GITHUB.COM/EXAMPLE/ALPHA-PLUGIN'),
            ],
        )


def test_catalogue_snapshot_rejects_source_summary_count_mismatch():
    with pytest.raises(ValidationError, match='sourceSummary.pluginCount'):
        CatalogueSnapshot(
            schema_version=SCHEMA_VERSION,
            source_summary=_summary(2),
            plugins=[_plugin('alpha-plugin')],
        )


def test_catalogue_snapshot_rejects_invalid_timestamp():
    with pytest.raises(ValidationError, match='dataUpdatedAt'):
        CatalogueSnapshot.model_validate(
            {
                'schemaVersion': '2.0.0',
                'dataUpdatedAt': 'not-a-timestamp',
                'sourceSummary': {
                    'pluginCount': 0,
                    'registryVisibleCount': 0,
                    'projectKindCounts': {},
                    'warningCount': 0,
                },
                'plugins': [],
            }
        )


def test_catalogue_snapshot_requires_schema_version():
    with pytest.raises(ValidationError, match='schemaVersion'):
        CatalogueSnapshot.model_validate(
            {
                'sourceSummary': {
                    'pluginCount': 0,
                    'registryVisibleCount': 0,
                    'projectKindCounts': {},
                    'warningCount': 0,
                },
                'plugins': [],
            }
        )


def test_catalogue_snapshot_rejects_unsupported_schema_version():
    with pytest.raises(ValidationError, match='schemaVersion'):
        CatalogueSnapshot.model_validate(
            {
                'schemaVersion': '1.0.0',
                'sourceSummary': {
                    'pluginCount': 0,
                    'registryVisibleCount': 0,
                    'projectKindCounts': {},
                    'warningCount': 0,
                },
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
