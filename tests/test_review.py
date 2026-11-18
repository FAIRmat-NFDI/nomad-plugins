import csv
import json

import pytest
from click.testing import CliRunner

from nomad_plugins.catalogue import build_catalogue_snapshot, write_catalogue_snapshot
from nomad_plugins.cli import main
from nomad_plugins.crawler import DeploymentInfo, Plugin, RepositoryStatus
from nomad_plugins.review import (
    ReviewMove,
    build_review_rows,
    load_previous_review,
    load_reference,
    load_review_moves,
    write_review_csv,
)


def _plugin(
    name: str, *, visible: bool = True, archived: bool = False, pypi: str | None = None
) -> Plugin:
    return Plugin(
        id=f'github.com/example/{name}',
        name=name,
        repository_url=f'https://github.com/example/{name}',
        pypi_url=pypi,
        owner='example',
        owner_type='Organization',
        status=RepositoryStatus(
            archived=archived, fork=False, stars=0, default_branch='main'
        ),
        deployment=DeploymentInfo(on_central=False, on_example_oasis=False),
        project_kind='plugin',
        registry_visible=visible,
        metadata_source='pyproject.toml',
    )


def test_review_includes_hidden_and_original_only_plugins_with_links():
    snapshot = build_catalogue_snapshot(
        [_plugin('hidden', visible=False, archived=True), _plugin('new')]
    )
    reference = {
        'github.com/example/old': {
            'id': 'github.com/example/old',
            'name': 'old',
            'repositoryUrl': 'https://github.com/example/old',
            'projectKind': 'plugin',
            'registryVisible': True,
            'status': {'defaultBranch': 'main'},
        }
    }

    rows = build_review_rows(snapshot, reference=reference)

    assert [row['Review group'] for row in rows] == [
        'Reference plugin absent',
        'Hidden plugin',
        'New visible',
    ]
    assert rows[0]['Original catalogue URL'].endswith('#plugin-github-com-example-old')
    assert rows[1]['Visibility reason'] == 'archived repository'
    assert rows[1]['pyproject.toml URL'].endswith('/blob/main/pyproject.toml')
    assert rows[1]['Reviewer comment'] == ''


def test_review_carries_comments_by_stable_id_after_sort_and_refresh(tmp_path):
    old_snapshot = build_catalogue_snapshot([_plugin('beta'), _plugin('alpha')])
    previous_path = tmp_path / 'review.csv'
    initial_rows = build_review_rows(old_snapshot)
    initial_rows[0]['Reviewer verdict'] = 'Should be excluded'
    initial_rows[0]['Reviewer comment'] = 'Specific false-positive example'
    initial_rows[0]['Expected handling'] = 'Add a narrow exclusion rule'
    write_review_csv(initial_rows, previous_path)

    new_snapshot = build_catalogue_snapshot([_plugin('gamma'), _plugin('alpha')])
    rows = build_review_rows(new_snapshot, previous=load_previous_review(previous_path))

    alpha = next(row for row in rows if row['Name'] == 'alpha')
    beta = next(row for row in rows if row['Name'] == 'beta')
    assert alpha['Reviewer verdict'] == 'Should be excluded'
    assert alpha['Reviewer comment'] == 'Specific false-positive example'
    assert alpha['Expected handling'] == 'Add a narrow exclusion rule'
    assert beta['Presence'] == 'Prior review only'
    assert beta['Review group'] == 'Prior-review only'


def test_review_flags_pypi_link_shared_by_different_repositories():
    pypi = 'https://pypi.org/project/shared/'
    snapshot = build_catalogue_snapshot(
        [_plugin('a', pypi=pypi), _plugin('b', pypi=pypi)]
    )

    rows = build_review_rows(snapshot)

    assert all(row['Review group'] == 'Potential link collision' for row in rows)
    assert all(
        'PyPI URL shared by different repositories' in row['Audit flags']
        for row in rows
    )


def test_review_command_writes_and_regenerates_annotated_csv(tmp_path):
    snapshot_path = tmp_path / 'catalogue.json'
    review_path = tmp_path / 'review.csv'
    write_catalogue_snapshot(
        build_catalogue_snapshot([_plugin('alpha')]), snapshot_path
    )
    runner = CliRunner()

    first = runner.invoke(
        main, ['review', '--input', str(snapshot_path), '--output', str(review_path)]
    )
    assert first.exit_code == 0, first.output
    assert 'New visible: 1' in first.output
    with review_path.open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.DictReader(stream))
    rows[0]['Reviewer comment'] = 'Check package identity'
    write_review_csv(rows, review_path)

    second = runner.invoke(
        main,
        [
            'review',
            '--input',
            str(snapshot_path),
            '--previous',
            str(review_path),
            '--output',
            str(review_path),
        ],
    )
    assert second.exit_code == 0, second.output
    assert (
        load_previous_review(review_path)['github.com/example/alpha'][
            'Reviewer comment'
        ]
        == 'Check package identity'
    )


def test_review_rejects_duplicate_previous_ids_without_overwriting(tmp_path):
    snapshot_path = tmp_path / 'catalogue.json'
    previous_path = tmp_path / 'duplicate.csv'
    output_path = tmp_path / 'review.csv'
    write_catalogue_snapshot(
        build_catalogue_snapshot([_plugin('alpha')]), snapshot_path
    )
    previous_path.write_text(
        'Stable ID,Reviewer verdict,Reviewer comment,Expected handling,Evidence URL\n'
        'github.com/example/alpha,,,,\nGITHUB.COM/EXAMPLE/ALPHA,,,,\n',
        encoding='utf-8',
    )
    output_path.write_text('keep me', encoding='utf-8')

    result = CliRunner().invoke(
        main,
        [
            'review',
            '--input',
            str(snapshot_path),
            '--previous',
            str(previous_path),
            '--output',
            str(output_path),
        ],
    )

    assert result.exit_code != 0
    assert 'Duplicate stable ID' in result.output
    assert output_path.read_text(encoding='utf-8') == 'keep me'


def test_reference_loader_rejects_duplicate_ids(tmp_path):
    reference = tmp_path / 'reference.json'
    reference.write_text(
        json.dumps({'plugins': [{'id': 'A'}, {'id': 'a'}]}),
        encoding='utf-8',
    )
    with pytest.raises(ValueError, match='Duplicate stable ID'):
        load_reference(reference)


def test_review_collapses_verified_move_and_carries_original_comment():
    snapshot = build_catalogue_snapshot([_plugin('new')])
    original_id = 'github.com/example/old'
    current_id = 'github.com/example/new'
    reference = {
        original_id: {
            'id': original_id,
            'name': 'old',
            'repositoryUrl': 'https://github.com/example/old',
            'projectKind': 'plugin',
            'registryVisible': True,
            'status': {'defaultBranch': 'main'},
        }
    }
    previous = {
        original_id: {
            'Stable ID': original_id,
            'Reviewer comment': 'Already checked this package',
        }
    }
    move = ReviewMove(original_id, current_id, 'Repository renamed')

    rows = build_review_rows(
        snapshot, reference=reference, previous=previous, moves={original_id: move}
    )

    assert len(rows) == 1
    assert rows[0]['Review group'] == 'Moved'
    assert rows[0]['Stable ID'] == current_id
    assert rows[0]['Original stable ID'] == original_id
    assert rows[0]['Presence'] == 'Moved ID'
    assert rows[0]['Move basis'] == 'Repository renamed'
    assert rows[0]['Repository URL'] == 'https://github.com/example/new'
    assert rows[0]['Original repository URL'] == 'https://github.com/example/old'
    assert rows[0]['Reviewer comment'] == 'Already checked this package'


def test_review_rejects_unmatched_move_and_conflicting_comments():
    snapshot = build_catalogue_snapshot([_plugin('new')])
    original_id = 'github.com/example/old'
    current_id = 'github.com/example/new'
    reference = {
        original_id: {
            'id': original_id,
            'name': 'old',
            'repositoryUrl': 'https://github.com/example/old',
            'projectKind': 'plugin',
            'registryVisible': True,
        }
    }
    move = ReviewMove(original_id, current_id, 'Repository renamed')

    with pytest.raises(ValueError, match='source is not original-only'):
        build_review_rows(snapshot, moves={original_id: move})
    with pytest.raises(ValueError, match='Conflicting reviewer values'):
        build_review_rows(
            snapshot,
            reference=reference,
            previous={
                original_id: {'Reviewer comment': 'Old comment'},
                current_id: {'Reviewer comment': 'Different comment'},
            },
            moves={original_id: move},
        )


def test_review_command_applies_explicit_move_file(tmp_path):
    snapshot_path = tmp_path / 'catalogue.json'
    reference_path = tmp_path / 'reference.json'
    moves_path = tmp_path / 'moves.json'
    output_path = tmp_path / 'review.csv'
    write_catalogue_snapshot(build_catalogue_snapshot([_plugin('new')]), snapshot_path)
    reference_path.write_text(
        json.dumps(
            {
                'plugins': [
                    {
                        'id': 'github.com/example/old',
                        'name': 'old',
                        'repositoryUrl': 'https://github.com/example/old',
                        'projectKind': 'plugin',
                        'registryVisible': True,
                    }
                ]
            }
        ),
        encoding='utf-8',
    )
    moves_path.write_text(
        json.dumps(
            {
                'moves': [
                    {
                        'originalId': 'github.com/example/old',
                        'currentId': 'github.com/example/new',
                        'basis': 'Repository renamed',
                    }
                ]
            }
        ),
        encoding='utf-8',
    )

    result = CliRunner().invoke(
        main,
        [
            'review',
            '--input',
            str(snapshot_path),
            '--reference',
            str(reference_path),
            '--moves',
            str(moves_path),
            '--output',
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert 'Moved: 1' in result.output
    with output_path.open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]['Review group'] == 'Moved'
    assert (
        load_review_moves(moves_path)['github.com/example/old'].basis
        == 'Repository renamed'
    )
