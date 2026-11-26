import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from zoneinfo import ZoneInfo

import httpx
import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from nomad_plugins.activity import ActivityWindow, RepositoryActivity
from nomad_plugins.catalogue import (
    CatalogueSnapshot,
    build_catalogue_snapshot,
    serialize_catalogue_snapshot,
    validate_catalogue_file,
)
from nomad_plugins.cli import main
from nomad_plugins.crawler import (
    CrawlResult,
    DeploymentInfo,
    Plugin,
    RepositoryStatus,
    enrich_repository_activity,
)
from nomad_plugins.github import GitHubActivitySample, GitHubClient, GitHubError

END = datetime(2026, 11, 25, tzinfo=timezone.utc)
WINDOW = ActivityWindow.ending_at(END)
ACTIVITY = RepositoryActivity(
    total_commits=10,
    recent_commits=3,
    last_commit_at='2026-11-24T12:00:00Z',
)


def _response():
    return {
        'data': {
            'repository': {
                'isEmpty': False,
                'defaultBranchRef': {
                    'name': 'main',
                    'target': {
                        '__typename': 'Commit',
                        'oid': 'a' * 40,
                        'committedDate': '2026-11-24T12:00:00Z',
                        'total': {'totalCount': 10},
                        'recent': {'totalCount': 3},
                    },
                },
            },
            'rateLimit': {'cost': 1},
        }
    }


def _plugin(plugin_id='github.com/example/project', *, visible=True):
    return Plugin(
        id=plugin_id,
        name='example',
        repository_url='https://' + plugin_id.split('#', 1)[0],
        owner='example',
        status=RepositoryStatus(archived=not visible, fork=False, stars=0),
        deployment=DeploymentInfo(on_central=False, on_example_oasis=False),
        project_kind='plugin',
        registry_visible=visible,
        metadata_source='pyproject.toml',
    )


def test_window_is_shared_180_day_utc_interval():
    shifted_end = END.astimezone(timezone(timedelta(hours=2)))
    window = ActivityWindow.ending_at(shifted_end)

    assert window == WINDOW
    assert window.end - window.start == timedelta(days=180)
    assert window.model_dump(mode='json') == {
        'start': '2026-05-29T00:00:00Z',
        'end': '2026-11-25T00:00:00Z',
    }


@pytest.mark.parametrize(
    ('start', 'end'),
    [
        (END, END),
        (END, END + timedelta(days=1)),
        (END, END - timedelta(days=180)),
        ('2026-05-29T00:00:00', END),
        (WINDOW.start, '2026-11-25T00:00:00'),
    ],
)
def test_window_rejects_wrong_duration_and_naive_timestamps(start, end):
    with pytest.raises(ValidationError):
        ActivityWindow(start=start, end=end)


def test_window_spans_exact_elapsed_days_across_daylight_saving_change():
    assert ActivityWindow.ending_at(END.astimezone(ZoneInfo('Europe/Berlin'))) == WINDOW


def test_window_factory_rejects_naive_cutoff():
    with pytest.raises(ValidationError):
        ActivityWindow.ending_at(END.replace(tzinfo=None))


@pytest.mark.parametrize(
    'updates',
    [
        {'total_commits': -1},
        {'recent_commits': -1},
        {'total_commits': True},
        {'recent_commits': '3'},
        {'recent_commits': 11},
        {'last_commit_at': None},
        {'last_commit_at': '2026-11-24T12:00:00'},
        {'total_commits': 0, 'recent_commits': 0},
    ],
)
def test_activity_rejects_inconsistent_or_malformed_counts(updates):
    values = ACTIVITY.model_dump()
    values.update(updates)
    with pytest.raises(ValidationError):
        RepositoryActivity.model_validate(values)


def test_confirmed_empty_history_is_zero_without_commit_time():
    activity = RepositoryActivity(total_commits=0, recent_commits=0)
    assert activity.model_dump(mode='json', by_alias=True, exclude_none=True) == {
        'totalCommits': 0,
        'recentCommits': 0,
    }


def _fetch(handler, *, retries=0):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            async with GitHubClient(
                'test-token',
                client=http,
                base_url='https://api.github.test',
                request_retries=retries,
                retry_backoff=0,
            ) as client:
                return await client.fetch_repository_activity(
                    'example/project', window=WINDOW
                )

    return asyncio.run(run())


def test_activity_reads_both_counts_at_same_head_in_one_graphql_query():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == 'POST'
        assert request.url.path == '/graphql'
        assert request.headers['Authorization'] == 'Bearer test-token'
        body = json.loads(request.content)
        assert body['variables'] == {
            'owner': 'example',
            'name': 'project',
            'since': WINDOW.start.isoformat(),
            'until': WINDOW.end.isoformat(),
        }
        assert 'total: history(first: 1)' in body['query']
        assert (
            'recent: history(first: 1, since: $since, until: $until)' in body['query']
        )
        assert 'mutation' not in body['query']
        return httpx.Response(200, json=_response())

    result = _fetch(handler)

    assert len(requests) == 1
    assert result.activity == ACTIVITY
    assert result.head_sha == 'a' * 40
    assert result.default_branch == 'main'
    assert result.query_cost == 1


def test_activity_accepts_zero_recent_commits_for_inactive_repository():
    payload = _response()
    payload['data']['repository']['defaultBranchRef']['target']['recent'][
        'totalCount'
    ] = 0
    result = _fetch(lambda _: httpx.Response(200, json=payload))
    assert result.activity.recent_commits == 0
    assert result.activity.total_commits == ACTIVITY.total_commits


def test_activity_accepts_only_confirmed_empty_repository_as_zero():
    payload = _response()
    payload['data']['repository'] = {'isEmpty': True, 'defaultBranchRef': None}
    result = _fetch(lambda _: httpx.Response(200, json=payload))
    assert result.activity == RepositoryActivity(total_commits=0, recent_commits=0)
    assert result.head_sha is None
    assert result.default_branch is None


@pytest.mark.parametrize(
    ('path', 'value'),
    [
        (
            ('errors',),
            [{'message': 'Resource not accessible by personal access token'}],
        ),
        (('data',), None),
        (('data', 'repository'), None),
        (('data', 'repository', 'defaultBranchRef'), None),
        (('data', 'repository', 'isEmpty'), None),
        (('data', 'repository', 'defaultBranchRef', 'target'), None),
        (('data', 'repository', 'defaultBranchRef', 'target', '__typename'), 'Tree'),
        (('data', 'repository', 'defaultBranchRef', 'target', 'oid'), ''),
        (('data', 'repository', 'defaultBranchRef', 'target', 'committedDate'), None),
        (('data', 'repository', 'defaultBranchRef', 'target', 'total'), {}),
        (('data', 'repository', 'defaultBranchRef', 'target', 'recent'), None),
        (
            ('data', 'repository', 'defaultBranchRef', 'target', 'total', 'totalCount'),
            -1,
        ),
        (
            (
                'data',
                'repository',
                'defaultBranchRef',
                'target',
                'recent',
                'totalCount',
            ),
            11,
        ),
        (('data', 'rateLimit', 'cost'), None),
    ],
)
def test_graphql_errors_and_partial_or_malformed_data_are_not_zero(path, value):
    payload = copy.deepcopy(_response())
    target = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(GitHubError, match="activity for 'example/project'") as error:
        _fetch(lambda _: httpx.Response(200, json=payload))
    assert error.value.__cause__ is not None


@pytest.mark.parametrize('payload', [[], {}, 'invalid'])
def test_graphql_invalid_document_fails_with_repository_context(payload):
    with pytest.raises(GitHubError, match="activity for 'example/project'"):
        _fetch(lambda _: httpx.Response(200, json=payload))


def test_graphql_invalid_json_fails_with_repository_context():
    with pytest.raises(GitHubError, match="activity for 'example/project'"):
        _fetch(lambda _: httpx.Response(200, text='{'))


@pytest.mark.parametrize('status', [401, 403, 404, 503])
def test_activity_http_failures_preserve_cause_and_repository_context(status):
    with pytest.raises(GitHubError, match="activity for 'example/project'") as error:
        _fetch(lambda _: httpx.Response(status, json={'message': 'unavailable'}))
    assert isinstance(error.value.__cause__, GitHubError)


def test_activity_transport_failure_retries_then_preserves_context():
    requests = []
    expected_attempts = 2

    def handler(request):
        requests.append(request)
        raise httpx.ReadTimeout('timed out', request=request)

    with pytest.raises(GitHubError, match="activity for 'example/project'") as error:
        _fetch(handler, retries=1)
    assert len(requests) == expected_attempts
    assert isinstance(error.value.__cause__.__cause__, httpx.ReadTimeout)


def test_activity_reuses_bounded_http_retry_policy():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json=_response())

    assert _fetch(handler, retries=1).activity == ACTIVITY
    expected_attempts = 2
    assert len(calls) == expected_attempts


def test_empty_catalogue_makes_no_activity_requests():
    github = SimpleNamespace(fetch_repository_activity=AsyncMock())
    assert asyncio.run(enrich_repository_activity([], github, WINDOW)) == ([], 0)
    github.fetch_repository_activity.assert_not_awaited()


def test_activity_sampling_is_deduplicated_bounded_and_preserves_order():
    plugins = [
        _plugin('github.com/example/project#packages/a'),
        _plugin('github.com/example/PROJECT#packages/b'),
        _plugin('github.com/example/project'),
        *(
            _plugin(f'github.com/example/repo-{index}', visible=False)
            for index in range(8)
        ),
    ]
    active = 0
    maximum_active = 0

    async def fetch(name, *, window):
        nonlocal active, maximum_active
        assert window is WINDOW
        active += 1
        maximum_active = max(active, maximum_active)
        await asyncio.sleep(0)
        active -= 1
        return GitHubActivitySample(
            activity=ACTIVITY, head_sha='a' * 40, default_branch='main', query_cost=1
        )

    github = SimpleNamespace(fetch_repository_activity=AsyncMock(side_effect=fetch))
    enriched, cost = asyncio.run(enrich_repository_activity(plugins, github, WINDOW))

    repository_count = 9
    concurrency_limit = 4
    assert github.fetch_repository_activity.await_count == repository_count
    assert cost == repository_count
    assert 1 < maximum_active <= concurrency_limit
    assert [plugin.id for plugin in enriched] == [plugin.id for plugin in plugins]
    assert [plugin.registry_visible for plugin in enriched] == [
        plugin.registry_visible for plugin in plugins
    ]
    assert all(plugin.status.activity == ACTIVITY for plugin in enriched)
    assert all(plugin.status.activity is None for plugin in plugins)


def test_activity_snapshot_serializes_global_context_and_public_facts_only():
    plugin = _plugin()
    plugin.status.activity = ACTIVITY
    snapshot = build_catalogue_snapshot(
        [plugin], data_updated_at=END, activity_window=WINDOW
    )

    serialized = serialize_catalogue_snapshot(snapshot)
    data = json.loads(serialized)
    assert data['activityWindow'] == WINDOW.model_dump(mode='json')
    assert data['dataUpdatedAt'] == '2026-11-25T00:00:00Z'
    assert data['plugins'][0]['status']['activity'] == {
        'totalCommits': 10,
        'recentCommits': 3,
        'lastCommitAt': '2026-11-24T12:00:00Z',
    }
    assert 'observedAt' not in serialized
    assert 'headSha' not in serialized
    assert CatalogueSnapshot.model_validate_json(serialized) == snapshot


def test_activity_is_optional_without_fabricating_zeroes():
    snapshot = build_catalogue_snapshot([_plugin()])
    data = json.loads(serialize_catalogue_snapshot(snapshot))
    assert 'activityWindow' not in data
    assert 'activity' not in data['plugins'][0]['status']


def test_snapshot_requires_window_for_activity_counts():
    plugin = _plugin()
    plugin.status.activity = ACTIVITY
    with pytest.raises(ValidationError, match='requires a global activityWindow'):
        build_catalogue_snapshot([plugin])


@pytest.mark.parametrize('timestamp', [None, END - timedelta(days=1)])
def test_snapshot_requires_consistent_collection_timestamp(timestamp):
    with pytest.raises(ValidationError, match='dataUpdatedAt must equal'):
        build_catalogue_snapshot([], data_updated_at=timestamp, activity_window=WINDOW)


def test_crawl_exports_activity_window_timestamp_and_cost(tmp_path):
    plugin = _plugin()
    plugin.status.activity = ACTIVITY
    result = CrawlResult(
        plugins=[plugin],
        search_diagnostics=[],
        unique_candidate_count=1,
        activity_window=WINDOW,
        activity_query_cost=1,
    )
    output = tmp_path / 'catalogue.json'
    with patch('nomad_plugins.cli.find_plugins', new=AsyncMock(return_value=result)):
        response = CliRunner().invoke(
            main, ['crawl', '--github-token', 'test-token', '--output', str(output)]
        )
    assert response.exit_code == 0, response.output
    assert '1 unique repositories; GraphQL cost: 1 point(s)' in response.output
    data = json.loads(output.read_text())
    assert data['activityWindow'] == WINDOW.model_dump(mode='json')
    assert data['dataUpdatedAt'] == '2026-11-25T00:00:00Z'
    assert (
        data['plugins'][0]['status']['activity']['recentCommits']
        == ACTIVITY.recent_commits
    )
    assert validate_catalogue_file(output).activity_window == WINDOW


def test_activity_failure_does_not_replace_existing_cli_output(tmp_path):
    output = tmp_path / 'catalogue.json'
    output.write_text('previous good output')
    with patch(
        'nomad_plugins.cli.find_plugins',
        new=AsyncMock(
            side_effect=GitHubError("GitHub activity for 'example/project' failed")
        ),
    ):
        result = CliRunner().invoke(
            main, ['crawl', '--github-token', 'test-token', '--output', str(output)]
        )
    assert result.exit_code != 0
    assert 'example/project' in result.output
    assert output.read_text() == 'previous good output'
    assert sorted(path.name for path in tmp_path.iterdir()) == ['catalogue.json']
