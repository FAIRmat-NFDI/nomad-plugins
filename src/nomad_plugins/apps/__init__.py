from nomad.config import _plugins
from nomad.config.models.plugins import AppEntryPoint
from nomad.config.models.ui import (
    App,
    Column,
    Columns,
    Menu,
    MenuItemHistogram,
    MenuItemTerms,
    MenuSizeEnum,
    SearchQuantities,
)

schema = 'nomad_plugins.schema_packages.plugin.Plugin'
filters_locked = {
    'section_defs.definition_qualified_name': [schema], 
    'entry_type': 'Plugin',
}

# Workaround: read the upload_ids from plugin's raw config.
try:
    upload_id = _plugins['entry_points']['options'][
        'nomad_plugins.schema_packages:schema_package_entry_point']['upload_id']
except KeyError:
    upload_id = None

if upload_id:
    filters_locked['upload_id'] = upload_id

plugin_app_entry_point = AppEntryPoint(
    name='NOMAD plugins',
    description='App for searching for plugins.',
    app=App(
        label='NOMAD plugins',
        path='plugins',
        category='NOMAD',
        search_quantities=SearchQuantities(
            include=[
                f'*#{schema}',
            ],
        ),
        columns=Columns(
            selected=[
                f'data.name#{schema}',
                f'data.owner#{schema}',
                f'data.repository#{schema}',
                f'data.on_central#{schema}',
                f'data.on_example_oasis#{schema}',
                f'data.on_pypi#{schema}',
                f'data.stars#{schema}',
            ],
            options={
                f'data.name#{schema}': Column(
                    label='Name',
                ),
                f'data.owner#{schema}': Column(
                    label='Owner',
                ),
                f'data.repository#{schema}': Column(
                    label='Repository',
                ),
                f'data.on_central#{schema}': Column(
                    label='On central NOMAD',
                ),
                f'data.on_example_oasis#{schema}': Column(
                    label='On NOMAD example oasis',
                ),
                f'data.on_pypi#{schema}': Column(
                    label='On PyPI',
                ),
                f'data.stars#{schema}': Column(
                    label='Stars',
                ),
                f'data.created#{schema}': Column(
                    label='Created on',
                ),
                f'data.last_updated#{schema}': Column(
                    label='Last modified',
                ),
            },
        ),
        menu=Menu(
            title='Plugins',
            size=MenuSizeEnum.MD,
            items=[
                MenuItemTerms(
                    search_quantity=f'data.authors.name#{schema}',
                    title='Author',
                    show_input=True,
                    options=8,
                ),
                MenuItemTerms(
                    search_quantity=f'data.plugin_dependencies.name#{schema}',
                    title='Depends on',
                    show_input=True,
                    options=8,
                ),
                MenuItemTerms(
                    search_quantity=f'data.plugin_entry_points.type#{schema}',
                    title='Plugin entry points',
                    show_input=False,
                    options=5,
                ),
                MenuItemHistogram(
                    x=f'data.created#{schema}',
                    title='Plugin creation date',
                    show_input=False,
                ),
                MenuItemHistogram(
                    x=f'data.last_updated#{schema}',
                    title='Last modification date',
                    show_input=False,
                ),
                MenuItemTerms(
                    search_quantity=f'data.on_central#{schema}',
                    title='On central NOMAD',
                    show_input=False,
                    options=2,
                    n_columns=2,
                ),
                MenuItemTerms(
                    search_quantity=f'data.on_example_oasis#{schema}',
                    title='On NOMAD example oasis',
                    show_input=False,
                    options=2,
                    n_columns=2,
                ),
                MenuItemTerms(
                    search_quantity=f'data.on_pypi#{schema}',
                    title='On PyPI',
                    show_input=False,
                    options=2,
                    n_columns=2,
                ),
            ],
        ),
        filters_locked=filters_locked,
    ),
)
