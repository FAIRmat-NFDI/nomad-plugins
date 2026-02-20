from typing import (
    TYPE_CHECKING,
)

from nomad.datamodel.datamodel import EntryMetadata
from nomad.datamodel.results import ELN, Results

if TYPE_CHECKING:
    from nomad.datamodel.datamodel import (
        EntryArchive,
    )
    from structlog.stdlib import (
        BoundLogger,
    )

    from nomad_plugins.schema_packages import PluginSchemaPackageEntryPoint


from nomad.config import config
from nomad.datamodel.data import ArchiveSection, Schema
from nomad.metainfo import Datetime, MEnum, Quantity, SchemaPackage, SubSection

configuration: 'PluginSchemaPackageEntryPoint' = config.get_plugin_entry_point(
    'nomad_plugins.schema_packages:schema_package_entry_point'
)

m_package = SchemaPackage()


class PyprojectAuthor(ArchiveSection):
    name = Quantity(
        type=str,
    )
    email = Quantity(
        type=str,
    )


class PluginEntryPoint(ArchiveSection):
    name = Quantity(
        type=str,
    )
    module = Quantity(
        type=str,
    )
    type = Quantity(
        type=MEnum(
            'App', 'Schema package', 'Normalizer', 'Parser', 'Example upload', 'API'
        )
    )


class Plugin(Schema):
    repository = Quantity(
        type=str,
    )
    toml_directory = Quantity(
        type=str,
    )
    created = Quantity(
        type=Datetime,
    )
    last_updated = Quantity(
        type=Datetime,
    )
    stars = Quantity(
        type=int,
    )
    name = Quantity(
        type=str,
    )
    description = Quantity(
        type=str,
    )
    owner = Quantity(
        type=str,
    )
    owner_type = Quantity(
        type=MEnum('Organization', 'User'),
    )
    docs_url = Quantity(
        type=str,
    )
    on_pypi = Quantity(
        type=bool,
    )
    archived = Quantity(
        type=bool,
    )
    on_central = Quantity(
        type=bool,
    )
    on_example_oasis = Quantity(
        type=bool,
    )
    authors = SubSection(
        section=PyprojectAuthor,
        repeats=True,
    )
    maintainers = SubSection(
        section=PyprojectAuthor,
        repeats=True,
    )
    plugin_entry_points = SubSection(
        section=PluginEntryPoint,
        repeats=True,
    )
    plugin_dependencies = SubSection(
        section='PluginReference',
        repeats=True,
    )

    def normalize(self, archive: 'EntryArchive', logger: 'BoundLogger') -> None:
        super().normalize(archive, logger)
        if not archive.metadata:
            archive.metadata = EntryMetadata()
        if not archive.results:
            archive.results = Results()
        if not archive.results.eln:
            archive.results.eln = ELN()
        archive.results.eln.lab_ids = []
        archive.metadata.references = []
        if self.repository:
            archive.results.eln.lab_ids.append(self.repository)
            archive.metadata.references.append(self.repository)
        if self.on_pypi:
            pypi_url = f'https://pypi.org/project/{self.name}/'
            archive.results.eln.lab_ids.append(pypi_url)
            archive.metadata.references.append(pypi_url)
        if self.description:
            archive.metadata.comment = self.description


class PluginReference(ArchiveSection):
    name = Quantity(
        type=str,
    )
    location = Quantity(
        type=str,
    )
    toml_directory = Quantity(
        type=str,
    )
    plugin = Quantity(
        type=Plugin,
    )

    def normalize(self, archive: 'EntryArchive', logger: 'BoundLogger') -> None:
        super().normalize(archive, logger)
        from nomad.datamodel.context import ServerContext

        if not isinstance(archive.m_context, ServerContext):
            return
        from nomad.search import MetadataPagination, search

        query = {'results.eln.lab_ids': self.location}
        search_result = search(
            owner='all',
            query=query,
            pagination=MetadataPagination(page_size=1),
            user_id=archive.metadata.main_author.user_id,
        )
        if search_result.pagination.total > 0:
            entry_id = search_result.data[0]['entry_id']
            upload_id = search_result.data[0]['upload_id']
            self.plugin = f'../uploads/{upload_id}/archive/{entry_id}#data'
            if search_result.pagination.total > 1:
                logger.warn(
                    f'Found {search_result.pagination.total} entries with repository: '
                    f'"{self.location}". Will use the first one found.'
                )
        else:
            logger.warn(f'Found no plugins with repository: "{self.location}".')


m_package.__init_metainfo__()
