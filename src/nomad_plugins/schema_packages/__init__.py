from nomad.config.models.plugins import SchemaPackageEntryPoint
from pydantic import Field


class PluginSchemaPackageEntryPoint(SchemaPackageEntryPoint):
    upload_id: str = Field('', description='The main upload id for the plugins.')

    def load(self):
        from nomad_plugins_metadata.schema_packages.schema_package import m_package

        return m_package


schema_package_entry_point = PluginSchemaPackageEntryPoint(
    name='PluginMetadataSchemaPackage',
    description=(
        'Compatibility wrapper loading canonical PluginMetadata schema package.'
    ),
)
