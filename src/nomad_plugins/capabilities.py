from __future__ import annotations

PLUGIN_TYPE_ALIASES = {
    'action': 'action',
    'actions': 'action',
    'apps': 'app',
    'app': 'app',
    'application': 'app',
    'api': 'api',
    'apis': 'api',
    'dashboard': 'dashboard',
    'dashboards': 'dashboard',
    'example': 'example_upload',
    'example-upload': 'example_upload',
    'example_upload': 'example_upload',
    'example-uploads': 'example_upload',
    'example_uploads': 'example_upload',
    'normalizer': 'normalizer',
    'normalizers': 'normalizer',
    'north-tool': 'north_tool',
    'north_tool': 'north_tool',
    'north-tools': 'north_tool',
    'north_tools': 'north_tool',
    'parser': 'parser',
    'parsers': 'parser',
    'schema': 'schema',
    'schema-package': 'schema',
    'schema_package': 'schema',
    'schemas': 'schema',
    'tool': 'action',
    'tools': 'action',
    'unknown': 'unknown',
}

ENTRYPOINT_TYPE_HINTS = (
    ('example_upload', ('example_upload', 'example-upload', 'exampleupload')),
    ('north_tool', ('north_tool', 'north-tool', 'northtool')),
    ('normalizer', ('normalizer',)),
    ('parser', ('parser',)),
    ('schema', ('schema_package', 'schema-package', 'schema')),
    ('dashboard', ('dashboard',)),
    ('action', ('action',)),
    ('app', ('app',)),
    ('api', ('api',)),
)


def normalize_plugin_type(plugin_type: str) -> str | None:
    normalized_type = plugin_type.strip().lower().replace(' ', '_').replace('-', '_')

    if normalized_type == '':
        return None

    return PLUGIN_TYPE_ALIASES.get(normalized_type, normalized_type)


def infer_entrypoint_type(name: str, module: str) -> str:
    normalized_name = normalize_hint_text(name)
    if normalized_name.endswith('_example'):
        return 'example_upload'

    name_hint = inferred_type_from_hint_text(normalized_name)
    if name_hint is not None:
        return name_hint

    hint_text = normalize_hint_text(module)
    return inferred_type_from_hint_text(hint_text) or 'unknown'


def inferred_type_from_hint_text(hint_text: str) -> str | None:
    for plugin_type, hints in ENTRYPOINT_TYPE_HINTS:
        if any(hint in hint_text for hint in hints):
            return plugin_type

    return None


def normalize_hint_text(value: str) -> str:
    return value.strip().lower().replace('-', '_').replace('.', '_')
