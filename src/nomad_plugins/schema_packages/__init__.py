from nomad.config.models.plugins import SchemaPackageEntryPoint
from pydantic import Field


class PluginSchemaPackageEntryPoint(SchemaPackageEntryPoint):
    upload_id: str = Field('', description='The main upload id for the plugins.')

    def load(self):
        from nomad_plugins.schema_packages.plugin import m_package

        return m_package


schema_package_entry_point = PluginSchemaPackageEntryPoint(
    name='PluginSchemaPackage',
    description='Schema package for Plugins.',
)
