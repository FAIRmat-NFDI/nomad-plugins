import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nomad_plugins.crawler import Plugin
from nomad_plugins.transform import ProjectKind

# Schema versioning is independent of the package version.
# MAJOR: breaking JSON contract changes; MINOR: compatible additions;
# PATCH: schema/documentation fixes that do not change valid JSON instances.
SCHEMA_VERSION: Final = '2.0.0'
DEFAULT_SCHEMA_PATH = Path('plugin-catalogue.schema.json')


class CatalogueSourceSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    plugin_count: int = Field(alias='pluginCount', ge=0)
    registry_visible_count: int = Field(alias='registryVisibleCount', ge=0)
    project_kind_counts: dict[ProjectKind, int] = Field(alias='projectKindCounts')
    warning_count: int = Field(alias='warningCount', ge=0)


class CatalogueSnapshot(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_version: Literal[SCHEMA_VERSION] = Field(
        alias='schemaVersion',
    )
    data_updated_at: datetime | None = Field(default=None, alias='dataUpdatedAt')
    source_summary: CatalogueSourceSummary = Field(alias='sourceSummary')
    plugins: list[Plugin]

    @model_validator(mode='after')
    def validate_snapshot(self) -> 'CatalogueSnapshot':
        if self.source_summary.plugin_count != len(self.plugins):
            raise ValueError(
                'sourceSummary.pluginCount must match the number of plugins.'
            )

        registry_visible_count = sum(plugin.registry_visible for plugin in self.plugins)
        if self.source_summary.registry_visible_count != registry_visible_count:
            raise ValueError(
                'sourceSummary.registryVisibleCount must match the number of '
                'registry-visible plugins.'
            )

        project_kind_counts: dict[ProjectKind, int] = {}
        for plugin in self.plugins:
            project_kind_counts[plugin.project_kind] = (
                project_kind_counts.get(plugin.project_kind, 0) + 1
            )
        if self.source_summary.project_kind_counts != project_kind_counts:
            raise ValueError(
                'sourceSummary.projectKindCounts must match the plugin project kinds.'
            )

        warning_count = sum(len(plugin.discovery_warnings) for plugin in self.plugins)
        if self.source_summary.warning_count != warning_count:
            raise ValueError(
                'sourceSummary.warningCount must match the number of discovery '
                'warnings.'
            )

        seen: set[str] = set()
        duplicates: set[str] = set()
        for plugin in self.plugins:
            identity = plugin.id.casefold()
            if identity in seen:
                duplicates.add(identity)
            seen.add(identity)

        if duplicates:
            duplicate_list = ', '.join(sorted(duplicates))
            raise ValueError(f'Duplicate plugin identities found: {duplicate_list}.')

        return self


def build_catalogue_snapshot(
    plugins: list[Plugin],
    *,
    data_updated_at: datetime | None = None,
) -> CatalogueSnapshot:
    sorted_plugins = [_normalize_plugin(plugin) for plugin in plugins]
    sorted_plugins.sort(key=_plugin_sort_key)
    project_kind_counts: dict[ProjectKind, int] = {}
    for plugin in sorted_plugins:
        project_kind_counts[plugin.project_kind] = (
            project_kind_counts.get(plugin.project_kind, 0) + 1
        )
    return CatalogueSnapshot(
        schema_version=SCHEMA_VERSION,
        data_updated_at=data_updated_at,
        source_summary=CatalogueSourceSummary(
            plugin_count=len(sorted_plugins),
            registry_visible_count=sum(
                plugin.registry_visible for plugin in sorted_plugins
            ),
            project_kind_counts=project_kind_counts,
            warning_count=sum(
                len(plugin.discovery_warnings) for plugin in sorted_plugins
            ),
        ),
        plugins=sorted_plugins,
    )


def serialize_catalogue_snapshot(snapshot: CatalogueSnapshot) -> str:
    data = snapshot.model_dump(mode='json', by_alias=True, exclude_none=True)
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n'


def write_catalogue_snapshot(snapshot: CatalogueSnapshot, output: Path) -> None:
    content = serialize_catalogue_snapshot(snapshot)
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            'w',
            encoding='utf-8',
            dir=output.parent,
            prefix=f'.{output.name}.',
            suffix='.tmp',
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(content)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, output)
    except Exception:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        raise


def write_catalogue_schema(output: Path = DEFAULT_SCHEMA_PATH) -> None:
    schema = CatalogueSnapshot.model_json_schema()
    output.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + '\n',
        encoding='utf-8',
    )


def _plugin_sort_key(plugin: Plugin) -> tuple[str, str]:
    return (plugin.name.casefold(), plugin.id)


def _normalize_plugin(plugin: Plugin) -> Plugin:
    return plugin.model_copy(
        update={
            'entrypoints': sorted(
                plugin.entrypoints,
                key=lambda entrypoint: (
                    entrypoint.type,
                    entrypoint.name.casefold(),
                    entrypoint.module.casefold(),
                ),
            )
            if plugin.entrypoints
            else [],
            'plugin_types': sorted(plugin.plugin_types)
            if plugin.plugin_types is not None
            else None,
            'dependencies': sorted(set(plugin.dependencies), key=str.casefold),
            'discovery_warnings': sorted(
                set(plugin.discovery_warnings),
                key=str.casefold,
            ),
        },
    )
