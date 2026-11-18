# Reviewing the catalogue baseline

The review table is a working audit, not another catalogue schema. It includes
all current records, whether visible or hidden, plus records from an optional
reference snapshot that no longer appear. Each row has a stable ID, a review
group, visibility reason, repository and `pyproject.toml` links, and four
editable reviewer fields. `Hidden plugin` is a separate group on every export;
other hidden project kinds remain in `Hidden non-plugin`.

Keep annotated files in `outputs/catalogue-review-<date>/` within the
repository. That folder is ignored by Git, so comments stay local until you
choose to share them; back it up if needed.

From the repository root, generate the first table:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --reference /path/to/original/plugin-registry.json \
  --output outputs/catalogue-review-local/catalogue-review.csv
```

The original `plugin-registry.json` from `plugin-registry/collapsed` commit
`6158333`, or the homepage's copy of that file, is suitable as the initial
reference. A later snapshot can instead be used to review a monthly change.
The command does not contact GitHub or modify `plugin-catalogue.json`.

Filter by `Review group`, then work through `Reference plugin absent`, `Hidden
plugin`, `New visible`, and `Potential link collision`. The `Audit flags`
column includes other differences and warnings. A repeated PyPI URL is a
review cue, not proof of a bad link. The `pyproject.toml` URL is inferred from
the stable ID and default branch; check the repository if a project has moved.
The original-catalogue link appears only for rows that were visible in the
original snapshot.

Edit these columns in a spreadsheet application and save as UTF-8 CSV:

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
  --previous outputs/catalogue-review-local/catalogue-review.csv \
  --output outputs/catalogue-review-local/catalogue-review.csv
```

Reviewer fields are matched by stable ID, not row position. A previously
reviewed ID that is absent from both current and reference snapshots remains
in `Prior-review only`, so its comments are not lost. Keep a backup of the
annotated CSV when sharing or regenerating it. Review verdicts do not directly
change catalogue output: confirmed findings become tested crawler/policy fixes
or explicit reviewed curation, followed by a new crawl and comparison.
