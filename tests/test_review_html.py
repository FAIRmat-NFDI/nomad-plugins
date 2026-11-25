import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from nomad_plugins.catalogue import build_catalogue_snapshot, write_catalogue_snapshot
from nomad_plugins.cli import main
from nomad_plugins.crawler import DeploymentInfo, Plugin, RepositoryStatus
from nomad_plugins.review import REVIEW_FIELDS, build_review_rows, load_previous_review
from nomad_plugins.review_html import build_review_payload, write_review_html


def _snapshot():
    return build_catalogue_snapshot(
        [
            Plugin(
                id='github.com/example/parser',
                name='parser',
                description='A test parser',
                repository_url='https://github.com/example/parser',
                owner='example',
                status=RepositoryStatus(archived=False, fork=False, stars=0),
                deployment=DeploymentInfo(on_central=False, on_example_oasis=False),
                project_kind='plugin',
                registry_visible=True,
                metadata_source='pyproject.toml',
            )
        ]
    )


def test_html_review_is_self_contained_and_escapes_repository_text(tmp_path):
    snapshot = _snapshot()
    snapshot.plugins[0].description = '</script><script>alert("metadata")</script>'
    rows = build_review_rows(snapshot)
    rows[0]['Reviewer comment'] = '</script><script>alert("comment")</script>'
    output = tmp_path / 'index.html'

    write_review_html(rows, output, snapshot=snapshot)

    html = output.read_text(encoding='utf-8')
    assert '<script>alert' not in html
    assert '__REVIEW_' not in html
    assert '<script src=' not in html
    encoded = re.search(r'id="review-data">(.*?)</script>', html, re.DOTALL)
    assert encoded is not None
    data = json.loads(encoded[1])
    assert (
        data['records'][0]['initial']['Reviewer comment'] == rows[0]['Reviewer comment']
    )
    assert (
        data['records'][0]['current']['description'] == snapshot.plugins[0].description
    )
    assert 'Import review' in html
    assert 'Expected handling' in html


def test_source_fingerprint_changes_only_for_source_evidence():
    snapshot = _snapshot()
    rows = build_review_rows(snapshot)
    initial = build_review_payload(rows, snapshot)['records'][0]['fingerprint']
    rows[0]['Reviewer comment'] = 'My note'
    assert build_review_payload(rows, snapshot)['records'][0]['fingerprint'] == initial
    snapshot.plugins[0].status.archived = True
    assert build_review_payload(rows, snapshot)['records'][0]['fingerprint'] != initial


@pytest.mark.parametrize('reference', [None, {}])
def test_html_distinguishes_absent_reference_from_empty_snapshot(reference):
    snapshot = _snapshot()
    rows = build_review_rows(snapshot, reference=reference)

    payload = build_review_payload(rows, snapshot, reference=reference)

    assert payload['hasReference'] is (reference is not None)


def test_html_review_cli_requires_no_auxiliary_files(tmp_path):
    input_path = tmp_path / 'catalogue.json'
    output = tmp_path / 'index.html'
    write_catalogue_snapshot(_snapshot(), input_path)

    result = CliRunner().invoke(
        main, ['review', '--input', str(input_path), '--output', str(output)]
    )

    assert result.exit_code == 0, result.output
    assert 'Other visible: 1' in result.output
    html = output.read_text(encoding='utf-8')
    encoded = re.search(r'id="review-data">(.*?)</script>', html, re.DOTALL)
    assert encoded is not None
    payload = json.loads(encoded[1])
    assert payload['hasReference'] is False
    assert payload['findings'] == []
    assert payload['savedReview'] is None
    assert payload['records'][0]['row']['Review group'] == 'Other visible'


def test_html_review_cli_embeds_agent_findings(tmp_path):
    input_path = tmp_path / 'catalogue.json'
    output = tmp_path / 'index.html'
    findings = tmp_path / 'findings.json'
    write_catalogue_snapshot(_snapshot(), input_path)
    findings.write_text(
        json.dumps(
            {
                'cases': [
                    {
                        'caseId': 'test-case',
                        'affectedStableIds': ['github.com/example/parser'],
                        'finding': 'Check this project',
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
            str(input_path),
            '--audit-findings',
            str(findings),
            '--output',
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert 'Check this project' in output.read_text(encoding='utf-8')


def test_failed_html_review_preserves_existing_file(tmp_path):
    input_path = tmp_path / 'catalogue.json'
    output = tmp_path / 'index.html'
    findings = tmp_path / 'findings.json'
    write_catalogue_snapshot(_snapshot(), input_path)
    output.write_text('existing review', encoding='utf-8')
    findings.write_text('{"cases": "invalid"}', encoding='utf-8')

    result = CliRunner().invoke(
        main,
        [
            'review',
            '--input',
            str(input_path),
            '--audit-findings',
            str(findings),
            '--output',
            str(output),
        ],
    )

    assert result.exit_code != 0
    assert output.read_text(encoding='utf-8') == 'existing review'


def test_browser_json_export_can_seed_the_existing_review_workflow(tmp_path):
    row = build_review_rows(_snapshot())[0]
    path = tmp_path / 'review.json'
    fields = dict.fromkeys(REVIEW_FIELDS, '')
    fields['Reviewer comment'] = 'Retain my note'
    record = {'row': row, 'fields': fields, 'fingerprint': 'old', 'conflicts': []}
    payload = {
        'format': 'nomad-catalogue-review',
        'version': 1,
        'records': {row['Stable ID']: record},
    }
    path.write_text(json.dumps(payload), encoding='utf-8')
    assert (
        load_previous_review(path)[row['Stable ID']]['Reviewer comment']
        == 'Retain my note'
    )
    record['conflicts'] = [fields]
    path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError, match='Resolve imported conflicts'):
        load_previous_review(path)


@pytest.mark.skipif(
    shutil.which('node') is None, reason='Node is needed for browser core checks'
)
def test_browser_review_core():
    result = subprocess.run(
        [
            'node',
            '--test',
            str(Path(__file__).with_name('review_core.test.cjs')),
            str(Path(__file__).with_name('review_ui.test.cjs')),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
