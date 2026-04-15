def test_schema_package():
    import yaml

    with open('tests/data/test.archive.yaml', encoding='utf-8') as handle:
        payload = yaml.safe_load(handle)

    data = payload['data']
    assert (
        data['m_def']
        == 'nomad_plugins_metadata.schema_packages.schema_package.PluginMetadata'
    )
    assert data['id'] == 'nomad-plugin-test'
    assert data['name'] == 'Test Plugin'
    assert (
        data['upstream_repository']
        == 'https://github.com/FAIRmat-NFDI/nomad-material-processing'
    )
    assert data['deployment']['on_pypi'] is True
