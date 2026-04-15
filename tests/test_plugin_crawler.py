import asyncio
from pathlib import Path

from nomad_plugins import plugin_crawler


def test_metadata_probe_paths_prioritize_plugin_root():
    paths = plugin_crawler._metadata_probe_paths('packages/example')
    assert paths[0] == 'packages/example/nomad_plugin_metadata.yaml'
    assert paths[1] == 'nomad_plugin_metadata.yaml'
    assert paths[2] == 'packages/example/nomad_plugin_metadata.yml'
    assert paths[3] == 'nomad_plugin_metadata.yml'


def test_finalize_metadata_sets_canonical_defaults():
    candidate = plugin_crawler.CandidateRepo(
        full_name='FAIRmat-NFDI/example-plugin',
        html_url='https://github.com/FAIRmat-NFDI/example-plugin',
        path='pyproject.toml',
        ref='deadbeef',
    )

    payload = plugin_crawler._finalize_metadata(candidate, {'description': 'Example'})

    assert payload['m_def'] == plugin_crawler.CANONICAL_MDEF
    assert payload['name'] == 'example-plugin'
    assert payload['id'] == 'example-plugin'
    assert payload['upstream_repository'] == candidate.html_url
    assert payload['metadata_schema_version'] == '1.0.0'


def test_process_candidate_fallback_uses_extractor(monkeypatch, tmp_path: Path):
    async def fake_load_metadata_file(candidate, *, headers, plugin_root):
        return None

    async def fake_download_tarball(candidate, *, headers, destination):
        tarball = destination / 'repo.tar.gz'
        tarball.write_bytes(b'placeholder')
        return tarball

    def fake_fallback_extract(candidate, *, tarball_path, plugin_root):
        assert tarball_path.exists()
        return {
            'id': 'extracted-id',
            'name': 'extracted-name',
            'upstream_repository': 'https://github.com/example/extracted',
            'metadata_schema_version': '1.0.0',
        }

    monkeypatch.setattr(
        plugin_crawler,
        '_load_repository_metadata_file',
        fake_load_metadata_file,
    )
    monkeypatch.setattr(plugin_crawler, '_download_tarball', fake_download_tarball)
    monkeypatch.setattr(
        plugin_crawler,
        '_fallback_extract_metadata',
        fake_fallback_extract,
    )

    candidate = plugin_crawler.CandidateRepo(
        full_name='example/repo',
        html_url='https://github.com/example/repo',
        path='pyproject.toml',
        ref='abc123',
    )

    result = asyncio.run(plugin_crawler._process_candidate(candidate, headers={}))

    assert result is not None
    assert result.data['m_def'] == plugin_crawler.CANONICAL_MDEF
    assert result.data['id'] == 'extracted-id'


def test_find_plugins_continues_on_partial_failures(monkeypatch):
    async def fake_search(*, url, headers, params):
        return [
            {
                'path': 'pyproject.toml',
                'url': 'https://api.github.com/search/code/1?ref=sha1',
                'repository': {
                    'full_name': 'org/one',
                    'html_url': 'https://github.com/org/one',
                },
            },
            {
                'path': 'pyproject.toml',
                'url': 'https://api.github.com/search/code/2?ref=sha2',
                'repository': {
                    'full_name': 'org/two',
                    'html_url': 'https://github.com/org/two',
                },
            },
        ]

    async def fake_process(candidate, headers):
        if candidate.full_name.endswith('one'):
            return plugin_crawler.PluginData(
                data={
                    'id': 'one',
                    'name': 'one',
                    'upstream_repository': 'https://github.com/org/one',
                    'metadata_schema_version': '1.0.0',
                    'm_def': plugin_crawler.CANONICAL_MDEF,
                }
            )
        return None

    monkeypatch.setattr(
        plugin_crawler,
        'fetch_all_results_parallel_async',
        fake_search,
    )
    monkeypatch.setattr(plugin_crawler, '_process_candidate', fake_process)

    plugins = asyncio.run(plugin_crawler.find_plugins('token'))

    assert len(plugins) == 1
    assert plugins[0].data['id'] == 'one'
