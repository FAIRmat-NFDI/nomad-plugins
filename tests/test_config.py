import json

import pytest
from pydantic import ValidationError

from nomad_plugins.config import (
    DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS,
    PRIMARY_CODE_SEARCH_QUERY,
    GitHubDiscoveryConfig,
    load_catalogue_config,
)


def test_packaged_default_config_loads_outside_repository(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    config = load_catalogue_config()

    assert config.github.code_search_queries == [
        PRIMARY_CODE_SEARCH_QUERY,
        'nomad-lab in:file filename:pyproject.toml',
    ]
    assert (
        config.github.code_search_request_delay_seconds
        == DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS
    )
    assert {
        'topic:north-tool',
        'nomad-semantic in:name,description',
        'org:FAIRmat-NFDI nomad in:name,description',
        'org:nomad-coe nomad in:name,description',
    } <= set(config.github.repository_search_queries)
    assert config.github.repository_search_candidate_limit == 120  # noqa: PLR2004
    assert config.github.repository_search_request_delay_seconds == 2.1  # noqa: PLR2004


def test_custom_config_is_loaded_and_normalized(tmp_path):
    path = tmp_path / 'config.json'
    path.write_text(
        json.dumps(
            {
                'github': {
                    'codeSearchQueries': [
                        f'  {PRIMARY_CODE_SEARCH_QUERY}  ',
                        'nomad-lab in:file filename:pyproject.toml',
                    ],
                    'codeSearchRequestDelaySeconds': 1,
                }
            }
        ),
        encoding='utf-8',
    )

    config = load_catalogue_config(path)

    assert config.github.code_search_queries[0] == PRIMARY_CODE_SEARCH_QUERY
    assert config.github.code_search_request_delay_seconds == 1
    assert config.github.repository_search_queries == []


@pytest.mark.parametrize(
    'queries',
    [
        [],
        [''],
        [PRIMARY_CODE_SEARCH_QUERY, PRIMARY_CODE_SEARCH_QUERY],
        [PRIMARY_CODE_SEARCH_QUERY, 'metadata filename:plugin.yaml'],
        ['nomad-lab in:file filename:pyproject.toml'],
        [PRIMARY_CODE_SEARCH_QUERY, 42],
    ],
)
def test_invalid_code_search_queries_are_rejected(tmp_path, queries):
    path = tmp_path / 'config.json'
    path.write_text(
        json.dumps(
            {
                'github': {
                    'codeSearchQueries': queries,
                }
            }
        ),
        encoding='utf-8',
    )

    with pytest.raises(ValidationError):
        load_catalogue_config(path)


def test_negative_search_delay_is_rejected(tmp_path):
    path = tmp_path / 'config.json'
    path.write_text(
        json.dumps(
            {
                'github': {
                    'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY],
                    'codeSearchRequestDelaySeconds': -1,
                }
            }
        ),
        encoding='utf-8',
    )

    with pytest.raises(ValidationError):
        load_catalogue_config(path)


@pytest.mark.parametrize('delay', [True, '6.5'])
def test_non_numeric_search_delay_is_rejected(tmp_path, delay):
    path = tmp_path / 'config.json'
    path.write_text(
        json.dumps(
            {
                'github': {
                    'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY],
                    'codeSearchRequestDelaySeconds': delay,
                }
            }
        ),
        encoding='utf-8',
    )

    with pytest.raises(ValidationError):
        load_catalogue_config(path)


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('repositorySearchQueries', ['']),
        ('repositorySearchQueries', ['topic:north-tool', ' TOPIC:NORTH-TOOL ']),
        ('repositorySearchQueries', [42]),
        ('repositorySearchQueries', 'topic:north-tool'),
        ('repositorySearchCandidateLimit', 0),
        ('repositorySearchCandidateLimit', 1001),
        ('repositorySearchCandidateLimit', True),
        ('repositorySearchCandidateLimit', '120'),
        ('repositorySearchRequestDelaySeconds', -1),
        ('repositorySearchRequestDelaySeconds', float('inf')),
        ('repositorySearchRequestDelaySeconds', True),
        ('repositorySearchRequestDelaySeconds', '2.1'),
    ],
)
def test_invalid_repository_discovery_settings_are_rejected(field, value):
    with pytest.raises(ValidationError):
        GitHubDiscoveryConfig.model_validate(
            {'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY], field: value}
        )


def test_repository_queries_can_be_normalized_or_disabled():
    config = GitHubDiscoveryConfig(
        code_search_queries=[PRIMARY_CODE_SEARCH_QUERY],
        repository_search_queries=['  topic:north-tool  '],
        repository_search_request_delay_seconds=0,
    )
    assert config.repository_search_queries == ['topic:north-tool']
    assert config.repository_search_request_delay_seconds == 0
    assert (
        GitHubDiscoveryConfig(
            code_search_queries=[PRIMARY_CODE_SEARCH_QUERY],
            repository_search_queries=[],
        ).repository_search_queries
        == []
    )
