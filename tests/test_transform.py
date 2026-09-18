from nomad_plugins.transform import (
    classify_project,
    derive_plugin_types,
    infer_entrypoint_type,
    is_registry_visible,
    normalize_dependencies,
    stable_plugin_id,
)


def test_stable_ids_include_normalized_nested_project_paths():
    repository_url = 'https://github.com/FAIRmat-NFDI/example-plugin.git'

    assert stable_plugin_id(repository_url) == (
        'github.com/fairmat-nfdi/example-plugin'
    )
    assert stable_plugin_id(repository_url, './packages\\parser/') == (
        'github.com/fairmat-nfdi/example-plugin#packages/parser'
    )


def test_entrypoint_capabilities_include_homepage_and_compatibility_types():
    assert infer_entrypoint_type('example.tool', 'example.tools:entry') == 'action'
    assert infer_entrypoint_type('example.dashboard', 'example:entry') == 'dashboard'
    assert infer_entrypoint_type('custom.extension', 'custom:entry') == 'unknown'
    assert derive_plugin_types([]) is None
    assert derive_plugin_types(['tool', 'parser', 'parser']) == ['action', 'parser']


def test_dependencies_are_canonical_and_deterministic():
    assert normalize_dependencies(
        ['Helper_Plugin', 'nomad.lab', 'helper-plugin', 'NOMAD-lab']
    ) == ['helper-plugin', 'nomad-lab']


def test_project_classification_and_visibility():
    assert _classify(name='nomad-baseclasses', dependencies=['nomad-lab']) == (
        'nomad_dependent_package'
    )
    assert _classify(name='nomad-parser', has_entrypoints=True) == 'plugin'
    assert _classify(name='nomad-distribution') == 'distribution'
    assert _classify(name='copied-example', project_path='examples/copied') == (
        'template_or_example'
    )
    assert _classify(name='helper') == 'ecosystem_package'

    assert is_registry_visible('plugin') is True
    assert is_registry_visible('nomad_dependent_package') is True
    assert is_registry_visible('distribution') is False
    assert is_registry_visible('template_or_example') is False
    assert is_registry_visible('ecosystem_package') is False


def test_official_project_kinds_can_be_represented_explicitly():
    assert _classify(name='template', explicit_kind='official_template') == (
        'official_template'
    )
    assert _classify(name='nomad', explicit_kind='official_software') == (
        'official_software'
    )
    assert is_registry_visible('official_template') is True
    assert is_registry_visible('official_software') is True


def _classify(
    *,
    name: str,
    dependencies: list[str] | None = None,
    has_entrypoints: bool = False,
    project_path: str | None = None,
    explicit_kind: str | None = None,
) -> str:
    return classify_project(
        name=name,
        description='',
        repository_url=f'https://github.com/example/{name}',
        project_path=project_path,
        dependencies=dependencies or [],
        has_entrypoints=has_entrypoints,
        explicit_kind=explicit_kind,
    )
