import json

import pytest
from pydantic import ValidationError

from nomad_plugins.config import (
    DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS,
    PRIMARY_CODE_SEARCH_QUERY,
    GitHubDiscoveryConfig,
    GitHubOwnerSearch,
    load_catalogue_config,
)

EXPECTED_OWNER_COUNT = 69
EXPECTED_ORGANIZATION_COUNT = 23
EXPECTED_USER_COUNT = 46


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
    } <= set(config.github.repository_search_queries)
    assert (
        'nomad plugin in:name,description'
        not in config.github.repository_search_queries
    )
    assert config.github.repository_search_candidate_limit == 120  # noqa: PLR2004
    assert config.github.repository_search_request_delay_seconds == 2.1  # noqa: PLR2004
    assert len(config.github.owner_searches) == EXPECTED_OWNER_COUNT
    assert (
        sum(
            owner.owner_type == 'Organization' for owner in config.github.owner_searches
        )
        == EXPECTED_ORGANIZATION_COUNT
    )
    assert (
        sum(owner.owner_type == 'User' for owner in config.github.owner_searches)
        == EXPECTED_USER_COUNT
    )
    owner_queries = {owner.query for owner in config.github.owner_searches}
    assert {
        'org:FAIRmat-NFDI nomad in:name,description',
        'org:BAMresearch nomad in:name,description',
        'org:IKZ-Berlin nomad in:name,description',
        'org:ZBT-Tools nomad in:name,description',
        'user:Bondoki nomad in:name,description',
        'user:ladinesa nomad in:name,description',
        'user:mado89 nomad in:name,description',
        'user:PauloGitHB nomad in:name,description',
    } <= owner_queries
    assert all(
        'org:' not in owner.query
        for owner in config.github.owner_searches
        if owner.owner_type == 'User'
    )


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
    assert config.github.owner_searches == []


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


def test_owner_searches_preserve_verified_account_type_and_normalize_login():
    config = GitHubDiscoveryConfig.model_validate(
        {
            'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY],
            'ownerSearches': [
                {'login': ' FAIRmat-NFDI ', 'ownerType': 'Organization'},
                {'login': ' Bondoki ', 'ownerType': 'User'},
            ],
        }
    )
    assert config.owner_searches == [
        GitHubOwnerSearch(login='FAIRmat-NFDI', owner_type='Organization'),
        GitHubOwnerSearch(login='Bondoki', owner_type='User'),
    ]
    assert [owner.query for owner in config.owner_searches] == [
        'org:FAIRmat-NFDI nomad in:name,description',
        'user:Bondoki nomad in:name,description',
    ]


@pytest.mark.parametrize(
    'owners',
    [
        [{'login': 'example', 'ownerType': 'Person'}],
        [{'login': 'bad user', 'ownerType': 'User'}],
        [{'login': 'example', 'ownerType': 'User', 'unknown': True}],
        [
            {'login': 'example', 'ownerType': 'User'},
            {'login': 'EXAMPLE', 'ownerType': 'Organization'},
        ],
    ],
)
def test_invalid_owner_searches_are_rejected(owners):
    with pytest.raises(ValidationError):
        GitHubDiscoveryConfig.model_validate(
            {'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY], 'ownerSearches': owners}
        )


def test_owner_search_cannot_duplicate_explicit_repository_query():
    with pytest.raises(ValidationError, match='duplicate repositorySearchQueries'):
        GitHubDiscoveryConfig.model_validate(
            {
                'codeSearchQueries': [PRIMARY_CODE_SEARCH_QUERY],
                'repositorySearchQueries': [
                    'org:FAIRmat-NFDI nomad in:name,description'
                ],
                'ownerSearches': [
                    {'login': 'fairmat-nfdi', 'ownerType': 'Organization'}
                ],
            }
        )
