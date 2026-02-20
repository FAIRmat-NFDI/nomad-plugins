def test_importing_app():
    # this will raise an exception if pydantic model validation fails for th app
    from nomad_plugins.apps import plugin_app_entry_point

    assert plugin_app_entry_point.app.label == 'NOMAD plugins'
    schema = 'nomad_plugins.schema_packages.plugin.Plugin'
    assert any(
        column.search_quantity == f'data.archived#{schema}'
        for column in plugin_app_entry_point.app.columns
    )
    assert any(
        item.title == 'Archived'
        and item.search_quantity == f'data.archived#{schema}'
        for item in plugin_app_entry_point.app.menu.items
    )
