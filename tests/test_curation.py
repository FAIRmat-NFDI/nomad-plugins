import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from nomad_plugins.cli import main
from nomad_plugins.config import (
    PRIMARY_CODE_SEARCH_QUERY,
    CatalogueConfig,
    CatalogueCurationConfig,
    DeploymentSourcesConfig,
)
from nomad_plugins.crawler import (
    DeploymentInfo,
    EnrichmentError,
    Plugin,
    RepositoryStatus,
    apply_url_suppressions,
    candidate_is_excluded,
    fetch_nomad_deployment_packages,
    find_plugins,
    load_manual_project_seeds,
    package_exists_on_pypi,
)
from nomad_plugins.github import GitHubClient, GitHubNotFoundError
from nomad_plugins.pyproject import parse_pyproject


@pytest.mark.parametrize(
    'curation',
    [
        {
            'officialTemplateRepositories': [
                {'repository': 'bad', 'name': 'x', 'description': 'template'}
            ]
        },
        {
            'officialSoftwareRepositories': [
                {'repository': 'owner/repo', 'name': ' ', 'description': 'core'}
            ]
        },
        {
            'officialSoftwareRepositories': [
                {'repository': 'owner/repo', 'name': 'core', 'description': ' '}
            ]
        },
        {
            'manualProjectSeeds': [
                {'repository': 'owner/repo', 'projectPath': '../other'}
            ]
        },
        {
            'manualProjectSeeds': [
                {'repository': 'owner/repo'},
                {'repository': 'OWNER/REPO'},
            ]
        },
        {'excludeCandidates': ['github.com/owner/repo', 'GITHUB.COM/OWNER/REPO']},
        {'excludeCandidates': ['github.com/owner/repo#../other']},
        {
            'excludeCandidates': ['github.com/owner/repo'],
            'manualProjectSeeds': [{'repository': 'owner/repo'}],
        },
        {'excludeDocumentationUrls': ['not-a-url']},
        {
            'excludePypiUrls': [
                'https://pypi.org/project/x/',
                'https://pypi.org/project/x',
            ]
        },
        {
            'officialTemplateRepositories': [
                {'repository': 'owner/repo', 'name': 'a', 'description': 'template'}
            ],
            'officialSoftwareRepositories': [
                {'repository': 'OWNER/REPO', 'name': 'b', 'description': 'software'}
            ],
        },
        {
            'officialSoftwareRepositories': [
                {'repository': 'owner/repo', 'name': 'core', 'description': 'software'}
            ],
            'manualProjectSeeds': [{'repository': 'owner/repo'}],
        },
    ],
)
def test_curation_configuration_rejects_invalid_or_duplicate_entries(curation):
    with pytest.raises(ValidationError):
        CatalogueCurationConfig.model_validate(curation)


def test_deployment_sources_reject_invalid_urls():
    with pytest.raises(ValidationError):
        DeploymentSourcesConfig.model_validate({'centralInfoUrl': 'not-a-url'})


def test_repository_root_exclusion_applies_to_nested_projects():
    excluded = {'github.com/example/template'}
    assert candidate_is_excluded(
        'github.com/example/template#packages/plugin', excluded
    )
    assert not candidate_is_excluded('github.com/example/other', excluded)


def test_manual_project_seed_requires_valid_metadata_and_deduplicates():
    config = CatalogueConfig.model_validate(
        {
            'github': {'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY]},
            'curation': {
                'manualProjectSeeds': [
                    {'repository': 'example/known'},
                    {'repository': 'example/new', 'projectPath': 'packages/parser'},
                ]
            },
        }
    )
    github = SimpleNamespace(
        base_url='https://api.github.test',
        fetch_text=AsyncMock(
            return_value=(
                '[project]\nname = "seeded"\n'
                '[project.entry-points."nomad.plugin"]\n'
                'parser = "seeded.parser:entry"\n'
            )
        ),
    )
    known_project = parse_pyproject(
        '[project]\nname = "known"\n[project.entry-points."nomad.plugin"]\n'
    )
    items, projects = asyncio.run(
        load_manual_project_seeds(
            github,
            config,
            {('example/known', '')},
            {('example/known', ''): known_project},
        )
    )
    assert len(items) == 1
    assert items[0].path == 'packages/parser/pyproject.toml'
    assert projects[('example/new', 'packages/parser')].name == 'seeded'
    github.fetch_text.assert_awaited_once_with(
        'https://api.github.test/repos/example/new/contents/packages/parser/pyproject.toml'
    )

    overlap_config = CatalogueConfig.model_validate(
        {
            'github': {'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY]},
            'curation': {'manualProjectSeeds': [{'repository': 'example/new'}]},
        }
    )
    overlap_items, overlap_projects = asyncio.run(
        load_manual_project_seeds(github, overlap_config, {('example/new', '')})
    )
    assert overlap_items == []
    assert overlap_projects[('example/new', '')].name == 'seeded'

    github.fetch_text = AsyncMock(return_value='[project]\nname = "unrelated"\n')
    with pytest.raises(ValueError, match='no NOMAD signal'):
        asyncio.run(load_manual_project_seeds(github, config, set()))
    github.fetch_text = AsyncMock(side_effect=GitHubNotFoundError('404'))
    with pytest.raises(ValueError, match='has no pyproject.toml'):
        asyncio.run(load_manual_project_seeds(github, config, set()))


def test_configured_official_rows_and_manual_seeds_merge_with_crawl():
    def handler(request):
        path = request.url.path
        if path == '/search/code':
            return httpx.Response(
                200, json={'total_count': 0, 'incomplete_results': False, 'items': []}
            )
        if path == '/repos/example/seeded/contents/packages/parser/pyproject.toml':
            return httpx.Response(
                200,
                text=(
                    '[project]\nname = "seeded-parser"\n'
                    '[project.entry-points."nomad.plugin"]\n'
                    'parser = "seeded.parser:entry"\n'
                ),
            )
        if path.startswith('/repos/'):
            return httpx.Response(
                200,
                json={
                    'owner': {'login': path.split('/')[2], 'type': 'Organization'},
                    'archived': path.endswith('/archived-template'),
                    'fork': False,
                    'stargazers_count': 2,
                },
            )
        raise AssertionError(f'Unexpected request: {request.url}')

    config = CatalogueConfig.model_validate(
        {
            'github': {'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY]},
            'curation': {
                'manualProjectSeeds': [
                    {'repository': 'example/seeded', 'projectPath': 'packages/parser'}
                ],
                'officialTemplateRepositories': [
                    {
                        'repository': 'example/archived-template',
                        'name': 'official-template',
                        'description': 'Reviewed template',
                    }
                ],
                'officialSoftwareRepositories': [
                    {
                        'repository': 'example/core',
                        'name': 'official-core',
                        'description': 'Reviewed software',
                    }
                ],
            },
        }
    )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient(
                'token', client=http, base_url='https://api.github.test'
            ) as github:
                return await find_plugins('token', config=config, github_client=github)

    with (
        patch(
            'nomad_plugins.crawler.fetch_nomad_deployment_packages',
            new=AsyncMock(return_value={'official-core'}),
        ),
        patch(
            'nomad_plugins.crawler.package_exists_on_pypi',
            new=AsyncMock(return_value=False),
        ),
    ):
        result = asyncio.run(run())

    plugins = {plugin.id: plugin for plugin in result.plugins}
    assert set(plugins) == {
        'github.com/example/seeded#packages/parser',
        'github.com/example/archived-template',
        'github.com/example/core',
    }
    assert result.unique_candidate_count == 1
    assert plugins['github.com/example/seeded#packages/parser'].metadata_source == (
        'pyproject.toml'
    )
    assert plugins['github.com/example/archived-template'].project_kind == (
        'official_template'
    )
    assert not plugins['github.com/example/archived-template'].registry_visible
    assert plugins['github.com/example/core'].project_kind == 'official_software'
    assert plugins['github.com/example/core'].metadata_source == 'crawler-config'
    assert plugins['github.com/example/core'].deployment.on_central


def test_discovered_official_root_does_not_require_pyproject_or_pypi():
    def handler(request):
        if request.url.path == '/search/code':
            return httpx.Response(
                200,
                json={
                    'total_count': 1,
                    'incomplete_results': False,
                    'items': [
                        {
                            'path': 'pyproject.toml',
                            'url': 'https://api.github.test/should-not-fetch',
                            'repository': {
                                'full_name': 'example/core',
                                'html_url': 'https://github.com/example/core',
                            },
                        }
                    ],
                },
            )
        if request.url.path == '/repos/example/core':
            return httpx.Response(
                200,
                json={
                    'owner': {'login': 'example', 'type': 'Organization'},
                    'archived': False,
                    'fork': False,
                    'stargazers_count': 3,
                },
            )
        raise AssertionError(f'Unexpected request: {request.url}')

    config = CatalogueConfig.model_validate(
        {
            'github': {'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY]},
            'curation': {
                'officialSoftwareRepositories': [
                    {
                        'repository': 'example/core',
                        'name': 'official-core',
                        'description': 'Reviewed core',
                    }
                ]
            },
        }
    )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient(
                'token', client=http, base_url='https://api.github.test'
            ) as github:
                return await find_plugins('token', config=config, github_client=github)

    with (
        patch(
            'nomad_plugins.crawler.fetch_nomad_deployment_packages',
            new=AsyncMock(return_value=set()),
        ),
        patch(
            'nomad_plugins.crawler.package_exists_on_pypi',
            new=AsyncMock(side_effect=AssertionError('PyPI must not be queried')),
        ),
    ):
        result = asyncio.run(run())
    assert [plugin.id for plugin in result.plugins] == ['github.com/example/core']
    assert result.plugins[0].metadata_source == 'crawler-config'


def test_curated_url_suppressions_do_not_change_other_fields():
    plugin = Plugin(
        id='github.com/example/semantic',
        name='nomad-semantic-web-service',
        repository_url='https://github.com/example/semantic',
        documentation_url='https://example.org/obsolete/',
        pypi_url='https://pypi.org/project/nomad-semantic-web-service/',
        owner='example',
        status=RepositoryStatus(archived=False, fork=False, stars=0),
        deployment=DeploymentInfo(on_central=False, on_example_oasis=False),
        project_kind='plugin',
        registry_visible=True,
        metadata_source='pyproject.toml',
    )
    curation = CatalogueCurationConfig(
        exclude_documentation_urls=['https://example.org/obsolete'],
        exclude_pypi_urls=['https://pypi.org/project/nomad-semantic-web-service/'],
    )
    result = apply_url_suppressions(plugin, curation)
    assert result.documentation_url is None
    assert result.pypi_url is None
    assert result.id == plugin.id
    assert result.registry_visible


def test_deployment_info_rejects_failed_or_malformed_sources():
    url = 'https://example.org/api/v1/info'
    with patch(
        'nomad_plugins.crawler.fetch_page_async',
        new=AsyncMock(
            return_value=httpx.Response(
                200,
                json={
                    'plugin_packages': [
                        {'name': 'Nomad_Plugin'},
                        {'name': 'other-plugin'},
                    ]
                },
            )
        ),
    ):
        assert asyncio.run(fetch_nomad_deployment_packages(url)) == {
            'nomad-plugin',
            'other-plugin',
        }
    with patch(
        'nomad_plugins.crawler.fetch_page_async',
        new=AsyncMock(return_value=httpx.Response(200, json={'other': []})),
    ):
        with pytest.raises(EnrichmentError, match='invalid plugin_packages'):
            asyncio.run(fetch_nomad_deployment_packages(url))
    with patch(
        'nomad_plugins.crawler.fetch_page_async',
        new=AsyncMock(side_effect=httpx.ConnectError('offline')),
    ):
        with pytest.raises(EnrichmentError, match='could not be checked'):
            asyncio.run(fetch_nomad_deployment_packages(url))


@pytest.mark.parametrize('status,expected', [(200, True), (404, False)])
def test_pypi_link_requires_confirmed_package_status(status, expected):
    def handler(_request):
        return httpx.Response(status)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with patch('nomad_plugins.crawler.httpx.AsyncClient', return_value=client):
        assert asyncio.run(package_exists_on_pypi('Nomad_Plugin')) is expected


def test_pypi_failure_is_not_treated_as_missing():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(503))
    )
    with patch('nomad_plugins.crawler.httpx.AsyncClient', return_value=client):
        with pytest.raises(EnrichmentError, match='PyPI availability'):
            asyncio.run(package_exists_on_pypi('nomad-plugin'))


def test_enrichment_failure_preserves_existing_catalogue(tmp_path):
    output = tmp_path / 'catalogue.json'
    output.write_text('previous validated snapshot', encoding='utf-8')
    with patch(
        'nomad_plugins.cli.find_plugins',
        new=AsyncMock(side_effect=EnrichmentError('deployment source unavailable')),
    ):
        result = CliRunner().invoke(
            main, ['crawl', '--github-token', 'token', '--output', str(output)]
        )
    assert result.exit_code != 0
    assert 'deployment source unavailable' in result.output
    assert output.read_text(encoding='utf-8') == 'previous validated snapshot'
