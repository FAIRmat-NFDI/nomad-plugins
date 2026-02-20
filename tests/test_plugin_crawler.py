import asyncio
from types import SimpleNamespace

from nomad_plugins import plugin_crawler


def test_get_plugin_maps_archived_fields(monkeypatch):
    async def fake_fetch_page_async(url, *, headers=None, params=None):
        class FakeResponse:
            def json(self):
                return {}

        return FakeResponse()

    async def fake_get_toml_project(search_result):
        return SimpleNamespace(
            name='test-plugin',
            entry_points=None,
            authors=[],
            maintainers=[],
            all_dependencies=set(),
            description='test description',
        )

    async def fake_package_exists_on_pypi(package_name):
        return True

    def fake_model_validate(_value):
        return SimpleNamespace(
            stargazers_count=42,
            created_at='2024-01-01T00:00:00Z',
            updated_at='2025-01-01T00:00:00Z',
            archived=True,
        )

    monkeypatch.setattr(plugin_crawler, 'fetch_page_async', fake_fetch_page_async)
    monkeypatch.setattr(plugin_crawler, 'get_toml_project', fake_get_toml_project)
    monkeypatch.setattr(
        plugin_crawler, 'package_exists_on_pypi', fake_package_exists_on_pypi
    )
    monkeypatch.setattr(
        plugin_crawler.GitHubRepositoryDetailed, 'model_validate', fake_model_validate
    )

    item = SimpleNamespace(
        repository=SimpleNamespace(
            url='https://api.github.com/repos/example/test-plugin',
            html_url='https://github.com/example/test-plugin',
            owner=SimpleNamespace(login='example'),
        )
    )

    plugin = asyncio.run(
        plugin_crawler.get_plugin(
            item=item,
            headers={},
            central_plugins={'test-plugin'},
            example_oasis_plugins=set(),
        )
    )

    assert plugin is not None
    assert plugin.archived is True
