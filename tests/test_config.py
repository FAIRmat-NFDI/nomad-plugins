import json

import pytest
from pydantic import ValidationError

from nomad_plugins.config import (
    DEFAULT_CODE_SEARCH_REQUEST_DELAY_SECONDS,
    PRIMARY_CODE_SEARCH_QUERY,
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
