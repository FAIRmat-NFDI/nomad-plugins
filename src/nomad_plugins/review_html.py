"""Generate a self-contained, offline catalogue review workspace."""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from nomad_plugins.catalogue import CatalogueSnapshot
from nomad_plugins.review import (
    GROUP_ORDER,
    REVIEW_COLUMNS,
    REVIEW_FIELDS,
    REVIEW_VERDICTS,
)

GROUP_GUIDE = {
    'Moved': 'A verified repository or project-path move, combined into one row. '
    'Compare both IDs and the recorded move evidence.',
    'Reference plugin absent': 'A plugin in the reference is absent under its old ID '
    'and has no verified move. Check removal, archival, or an undiscovered path.',
    'Hidden plugin': 'A current plugin has registryVisible=false, usually because '
    'the repository is archived or a fork. It remains in the JSON.',
    'Potential link collision': 'Different repositories share a PyPI URL. '
    'Check package identity; sharing a URL is not proof of an error.',
    'New visible': 'A visible current record was not in the supplied reference.',
    'Changed classification or types': 'The project kind or plugin types changed '
    'relative to the reference. Inspect the upstream declarations.',
    'Other visible': 'A visible record not assigned to an earlier review group.',
    'Hidden non-plugin': 'A current non-plugin record is hidden by classification '
    'or repository status. It remains available for audit.',
    'Reference-only non-plugin': 'A non-plugin reference record is absent from '
    'the current snapshot.',
    'Prior-review only': 'A previously annotated record is absent from both '
    'snapshots. Its review notes are retained.',
}


def load_audit_findings(path: Path | None) -> list[dict]:
    if path is None:
        return []
    cases = json.loads(path.read_text(encoding='utf-8'))['cases']
    if not isinstance(cases, list) or any(
        not isinstance(case, dict)
        or not isinstance(case.get('caseId'), str)
        or not isinstance(case.get('affectedStableIds'), list)
        or any(not isinstance(value, str) for value in case['affectedStableIds'])
        for case in cases
    ):
        raise ValueError('Audit findings require cases with IDs and affectedStableIds.')
    return cases


def build_review_payload(
    rows: list[dict[str, str]],
    snapshot: CatalogueSnapshot,
    *,
    reference: dict[str, dict] | None = None,
    findings: list[dict] | None = None,
    saved_review: dict | None = None,
) -> dict:
    current = {
        plugin.id.casefold(): plugin.model_dump(
            mode='json', by_alias=True, exclude_none=True
        )
        for plugin in snapshot.plugins
    }
    has_reference = reference is not None
    reference = reference or {}
    records = []
    for row in rows:
        stable_id = row['Stable ID'].casefold()
        original_id = (row['Original stable ID'] or row['Stable ID']).casefold()
        source = {
            'row': {
                key: value for key, value in row.items() if key not in REVIEW_FIELDS
            },
            'current': current.get(stable_id),
            'reference': reference.get(original_id),
        }
        fingerprint = hashlib.sha256(
            json.dumps(source, sort_keys=True).encode('utf-8')
        ).hexdigest()
        records.append(
            {
                'id': stable_id,
                'fingerprint': fingerprint,
                **source,
                'initial': {key: row[key] for key in REVIEW_FIELDS},
            }
        )
    return {
        'format': 'nomad-catalogue-review-data',
        'builtAt': datetime.now(timezone.utc).isoformat(),
        'schemaVersion': snapshot.schema_version,
        'hasReference': has_reference,
        'records': records,
        'findings': findings or [],
        'savedReview': saved_review,
        'groups': [
            {'name': name, 'description': GROUP_GUIDE[name]} for name in GROUP_ORDER
        ],
        'fields': REVIEW_FIELDS,
        'verdicts': REVIEW_VERDICTS,
        'columns': REVIEW_COLUMNS,
    }


def write_review_html(  # noqa: PLR0913
    rows: list[dict[str, str]],
    output: Path,
    *,
    snapshot: CatalogueSnapshot,
    reference: dict[str, dict] | None = None,
    findings: list[dict] | None = None,
    saved_review: dict | None = None,
) -> None:
    payload = build_review_payload(
        rows,
        snapshot,
        reference=reference,
        findings=findings,
        saved_review=saved_review,
    )
    assets = files('nomad_plugins').joinpath('review_assets')
    # Escape script delimiters, including hostile repository metadata/comments.
    encoded = json.dumps(payload, ensure_ascii=True).replace('<', '\\u003c')
    html = assets.joinpath('template.html').read_text(encoding='utf-8')
    html = html.replace(
        '__REVIEW_CORE__', assets.joinpath('core.js').read_text('utf-8')
    )
    html = html.replace('__REVIEW_UI__', assets.joinpath('ui.js').read_text('utf-8'))
    html = html.replace('__REVIEW_DATA__', encoded)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            'w',
            encoding='utf-8',
            dir=output.parent,
            prefix=f'.{output.name}.',
            suffix='.tmp',
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(html)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output)
    except Exception:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        raise
