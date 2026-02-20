import asyncio
from types import SimpleNamespace

from nomad_plugins import plugin_crawler


def test_get_plugin_maps_archived_and_owner_type_fields(monkeypatch):
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

    async def fake_check_github_pages_exists(repository_url):
        return 'https://example.github.io/test-plugin/'

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
        plugin_crawler, 'check_github_pages_exists', fake_check_github_pages_exists
    )
    monkeypatch.setattr(
        plugin_crawler.GitHubRepositoryDetailed, 'model_validate', fake_model_validate
    )

    item = SimpleNamespace(
        repository=SimpleNamespace(
            url='https://api.github.com/repos/example/test-plugin',
            html_url='https://github.com/example/test-plugin',
            owner=SimpleNamespace(login='example', type='Bot'),
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
    assert plugin.owner_type is None
    assert str(plugin.docs_url) == 'https://example.github.io/test-plugin/'


def test_get_plugin_maps_owner_type_organization(monkeypatch):
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

    async def fake_check_github_pages_exists(repository_url):
        return None

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
        plugin_crawler, 'check_github_pages_exists', fake_check_github_pages_exists
    )
    monkeypatch.setattr(
        plugin_crawler.GitHubRepositoryDetailed, 'model_validate', fake_model_validate
    )

    item = SimpleNamespace(
        repository=SimpleNamespace(
            url='https://api.github.com/repos/example/test-plugin',
            html_url='https://github.com/example/test-plugin',
            owner=SimpleNamespace(login='example', type='Organization'),
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
    assert plugin.owner_type == 'Organization'
    assert plugin.docs_url is None


def test_check_github_pages_exists_non_github_url():
    docs_url = asyncio.run(
        plugin_crawler.check_github_pages_exists('https://gitlab.com/example/repo')
    )
    assert docs_url is None


def test_resolve_deployed_plugin_packages_prefers_info_endpoint(monkeypatch):
    async def fake_fetch_nomad_deployment_plugins_from_info(info_url):
        return {'nomad-parser-plugins-workflow'}

    async def fake_fetch_nomad_deployment_plugins_from_pyproject(pyproject_url):
        return {'nomad-parser-plugins-atomistic'}

    monkeypatch.setattr(
        plugin_crawler,
        'fetch_nomad_deployment_plugins_from_info',
        fake_fetch_nomad_deployment_plugins_from_info,
    )
    monkeypatch.setattr(
        plugin_crawler,
        'fetch_nomad_deployment_plugins_from_pyproject',
        fake_fetch_nomad_deployment_plugins_from_pyproject,
    )

    resolved = asyncio.run(
        plugin_crawler.resolve_deployed_plugin_packages(
            info_url='https://nomad-lab.eu/prod/v1/api/v1/info',
            pyproject_url='https://gitlab.example/pyproject.toml',
        )
    )
    assert resolved == {'nomad-parser-plugins-workflow'}


def test_resolve_deployed_plugin_packages_falls_back_to_pyproject(monkeypatch):
    async def fake_fetch_nomad_deployment_plugins_from_info(info_url):
        return set()

    async def fake_fetch_nomad_deployment_plugins_from_pyproject(pyproject_url):
        return {'nomad-parser-plugins-atomistic'}

    monkeypatch.setattr(
        plugin_crawler,
        'fetch_nomad_deployment_plugins_from_info',
        fake_fetch_nomad_deployment_plugins_from_info,
    )
    monkeypatch.setattr(
        plugin_crawler,
        'fetch_nomad_deployment_plugins_from_pyproject',
        fake_fetch_nomad_deployment_plugins_from_pyproject,
    )

    resolved = asyncio.run(
        plugin_crawler.resolve_deployed_plugin_packages(
            info_url='https://nomad-lab.eu/prod/v1/api/v1/info',
            pyproject_url='https://gitlab.example/pyproject.toml',
        )
    )
    assert resolved == {'nomad-parser-plugins-atomistic'}


def test_resolve_deployed_plugin_packages_returns_empty_when_both_sources_fail(monkeypatch):
    async def fake_fetch_nomad_deployment_plugins_from_info(info_url):
        return set()

    async def fake_fetch_nomad_deployment_plugins_from_pyproject(pyproject_url):
        return set()

    monkeypatch.setattr(
        plugin_crawler,
        'fetch_nomad_deployment_plugins_from_info',
        fake_fetch_nomad_deployment_plugins_from_info,
    )
    monkeypatch.setattr(
        plugin_crawler,
        'fetch_nomad_deployment_plugins_from_pyproject',
        fake_fetch_nomad_deployment_plugins_from_pyproject,
    )

    resolved = asyncio.run(
        plugin_crawler.resolve_deployed_plugin_packages(
            info_url='https://nomad-lab.eu/prod/v1/api/v1/info',
            pyproject_url='https://gitlab.example/pyproject.toml',
        )
    )
    assert resolved == set()


def test_fetch_nomad_deployment_plugins_from_pyproject(monkeypatch):
    pyproject_toml = """
[project]
name = "nomad-distribution"
[project.optional-dependencies]
plugins = [
  "nomad-plugin-gui>=1.0.0",
  "nomad-porous-materials @ git+https://github.com/FAIRmat-NFDI/nomad-porous-materials.git@abc",
  "pynxtools[convert]==0.9.1",
]
"""

    async def fake_fetch_page_async(url, *, headers=None, params=None):
        class FakeResponse:
            text = pyproject_toml

        return FakeResponse()

    monkeypatch.setattr(plugin_crawler, 'fetch_page_async', fake_fetch_page_async)
    parsed = asyncio.run(
        plugin_crawler.fetch_nomad_deployment_plugins_from_pyproject(
            'https://gitlab.example/pyproject.toml'
        )
    )
    assert 'nomad-plugin-gui' in parsed
    assert 'nomad-porous-materials' in parsed
    assert 'pynxtools' in parsed
