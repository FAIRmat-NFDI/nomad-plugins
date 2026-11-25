# Reviewing the catalogue baseline

## Offline browser workspace

Generate a self-contained HTML page to review the catalogue without Excel:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --reference /path/to/original/plugin-registry.json \
  --moves docs/catalogue_review_moves.json \
  --audit-findings docs/catalogue_review_findings.json \
  --output outputs/catalogue-review-local/index.html
```

Open `outputs/catalogue-review-local/index.html` in a browser. No server,
account, network connection, or new crawl is required to use the page.
Repository, metadata, documentation, and PyPI links open live sources when
you choose them. The embedded snapshot does not update automatically.

Use the review-group sidebar and the search, visibility, status, project-kind,
and attention filters to work through the records. Open a project's **Review**
detail to compare the current and original metadata, inspect move evidence and
agent findings, and edit your verdict, comment, expected handling, and evidence
URL. **Save and next** advances within the filtered list. The **Review guide**
explains every group and the visibility policy; **Agent findings** keeps the
preliminary agent audit separate from your decisions.

Edits autosave by stable ID in this browser's local storage. They do not modify
the HTML file, GitHub, the catalogue, or curation rules. Export review JSON
regularly as a portable backup; browser storage can be lost when clearing
browser data, using private browsing, or moving to a different file or origin.
If browser storage is unavailable, the page warns that edits are in memory only.

After generating a fresh page, import your exported review JSON. Notes follow
verified ID moves, and reviewed records with changed source evidence are
flagged for re-review. Conflicting reviews retain both versions in the project
detail; resolve the conflict and choose a verdict again. Annotated IDs absent
from both snapshots remain as `Prior-review only`. JSON exports preserve this
history; CSV exports preserve the four reviewer fields but not conflict history.

The generator also accepts a conflict-free exported JSON file as `--previous`
to seed a new page with notes and source-change markers. An existing CSV is
still accepted, but it has no source fingerprints for detecting changed
evidence. Back up browser edits before replacing an HTML page.

## CSV review workflow

The review table is a working audit, not another catalogue schema. It includes
all current records, whether visible or hidden, plus records from an optional
reference snapshot that no longer appear. Each row has a stable ID, a review
group, visibility reason, repository and `pyproject.toml` links, and four
editable reviewer fields. `Hidden plugin` is a separate group on every export;
other hidden project kinds remain in `Hidden non-plugin`.

For the initial comparison with the old homepage catalogue, use the verified
one-to-one mappings in `docs/catalogue_review_moves.json`. These collapse an
original-only and current-only ID into a single `Moved` row, showing both IDs,
both repository URLs, and the evidence basis. The mapping affects only the
review table; it does not rewrite catalogue IDs or assume that similar names
are the same project. Unverified possible matches remain separate for review.

Keep annotated files in `outputs/catalogue-review-<date>/` within the
repository. That folder is ignored by Git, so comments stay local until you
choose to share them; back it up if needed.

From the repository root, generate the first table:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --reference /path/to/original/plugin-registry.json \
  --moves docs/catalogue_review_moves.json \
  --output outputs/catalogue-review-local/catalogue-review.csv
```

The original `plugin-registry.json` from `plugin-registry/collapsed` commit
`6158333`, or the homepage's copy of that file, is suitable as the initial
reference. A later snapshot can instead be used to review a monthly change.
The command does not contact GitHub or modify `plugin-catalogue.json`.

Filter by `Review group`, then work through `Moved`, `Reference plugin absent`,
`Hidden plugin`, `New visible`, and `Potential link collision`. The `Audit flags`
column includes other differences and warnings. A repeated PyPI URL is a
review cue, not proof of a bad link. The `pyproject.toml` URL is inferred from
the stable ID and default branch; check the repository if a project has moved.
The original-catalogue link appears only for rows that were visible in the
original snapshot.

The browser detail form and CSV workflow use these same four reviewer fields.
If continuing with an older workbook, export its annotated `Review` sheet as
UTF-8 CSV first and pass that file as `--previous`; the CLI does not read
`.xlsx` directly:

- `Reviewer verdict`: `Looks right`, `Should be hidden`, `Should be excluded`,
  `Should be visible`, `Metadata wrong`, or `Needs research`.
- `Reviewer comment`: why this is a useful example or what seems wrong.
- `Expected handling`: the desired general rule or narrow exception.
- `Evidence URL`: a source supporting the decision.

To regenerate after a new snapshot, pass the existing CSV as `--previous`.
The same path can be used for `--previous` and `--output`; the command reads
and validates it before replacing it atomically:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --reference /path/to/original/plugin-registry.json \
  --moves docs/catalogue_review_moves.json \
  --previous outputs/catalogue-review-local/catalogue-review.csv \
  --output outputs/catalogue-review-local/catalogue-review.csv
```

Reviewer fields are matched by stable ID, not row position. A previously
reviewed ID that is absent from both current and reference snapshots remains
in `Prior-review only`, so its comments are not lost. Keep a backup of the
annotated CSV when sharing or regenerating it. Review verdicts do not directly
change catalogue output: confirmed findings become tested crawler/policy fixes
or explicit reviewed curation, followed by a new crawl and comparison.
For a moved ID, a comment on either the original or current ID is carried into
the single row. Conflicting comments on both IDs make regeneration fail rather
than silently discarding either one.

Preliminary agent findings from this baseline review are recorded separately in
`docs/catalogue_review_findings.json`. Pass this as `--audit-findings` when
generating HTML to show the findings in a separate view and label affected
records, leaving the editable reviewer fields untouched. These findings are
audit notes, not approved curation or changes to the generated catalogue.
