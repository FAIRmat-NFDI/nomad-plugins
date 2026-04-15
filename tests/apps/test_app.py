def test_importing_app():
    # this will raise an exception if pydantic model validation fails for th app
    from nomad_plugins.apps import plugin_app_entry_point

    assert plugin_app_entry_point.app.label == 'NOMAD plugins'
    schema = 'nomad_plugins_metadata.schema_packages.schema_package.PluginMetadata'
    assert any(
        column.search_quantity == f'data.archived#{schema}'
        for column in plugin_app_entry_point.app.columns
    )
    assert any(
        column.search_quantity == f'data.owner_type#{schema}'
        for column in plugin_app_entry_point.app.columns
    )
    assert any(
        column.search_quantity == f'data.documentation#{schema}'
        for column in plugin_app_entry_point.app.columns
    )
    assert any(
        item.title == 'Archived' and item.search_quantity == f'data.archived#{schema}'
        for item in plugin_app_entry_point.app.menu.items
    )
    assert any(
        item.title == 'Owner type'
        and item.search_quantity == f'data.owner_type#{schema}'
        for item in plugin_app_entry_point.app.menu.items
    )
