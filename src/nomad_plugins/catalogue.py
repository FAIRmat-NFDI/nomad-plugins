import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nomad_plugins.crawler import Plugin

# Schema versioning is independent of the package version.
# MAJOR: breaking JSON contract changes; MINOR: compatible additions;
# PATCH: schema/documentation fixes that do not change valid JSON instances.
SCHEMA_VERSION: Final = '1.0.0'
DEFAULT_SCHEMA_PATH = Path('plugin-catalogue.schema.json')


class CatalogueSourceSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    plugin_count: int = Field(alias='pluginCount', ge=0)


class CatalogueSnapshot(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_version: Literal[SCHEMA_VERSION] = Field(
        default=SCHEMA_VERSION,
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

        seen: set[tuple[str, str]] = set()
        duplicates: set[tuple[str, str]] = set()
        for plugin in self.plugins:
            identity = (
                plugin.name.casefold(),
                str(plugin.repository).rstrip('/').casefold(),
            )
            if identity in seen:
                duplicates.add(identity)
            seen.add(identity)

        if duplicates:
            duplicate_list = ', '.join(
                f'{name} ({repository})' for name, repository in sorted(duplicates)
            )
            raise ValueError(f'Duplicate plugin identities found: {duplicate_list}.')

        return self


def build_catalogue_snapshot(
    plugins: list[Plugin],
    *,
    data_updated_at: datetime | None = None,
) -> CatalogueSnapshot:
    sorted_plugins = [
        _sort_plugin_dependencies(plugin)
        for plugin in sorted(plugins, key=_plugin_sort_key)
    ]
    return CatalogueSnapshot(
        data_updated_at=data_updated_at,
        source_summary=CatalogueSourceSummary(plugin_count=len(sorted_plugins)),
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
    return (plugin.name.casefold(), str(plugin.repository))


def _plugin_reference_sort_key(reference: Any) -> tuple[str, str]:
    return (reference.name.casefold(), reference.location)


def _sort_plugin_dependencies(plugin: Plugin) -> Plugin:
    return plugin.model_copy(
        update={
            'plugin_dependencies': sorted(
                plugin.plugin_dependencies,
                key=_plugin_reference_sort_key,
            )
        },
    )
