# Reviewing the catalogue baseline

## Local workspace

Use one reusable folder, `outputs/catalogue-review-local/`, for the generated
page and your latest exported decisions. The folder keeps these local files
together and is ignored by Git; it is not an archive of review sessions.
You can choose another output path, but keeping the same page location helps
retain browser autosave.

The normal working files are:

- `index.html`: the generated review page. Regenerate it at the same path.
- `catalogue-review.json`: your latest exported verdicts and comments. Keep
  this file to back up your work and carry it into a refreshed page.

There is no need for dated folders, copies of old HTML pages, or a sequence
of previous review exports. Older exports are optional backups; the latest
complete JSON export contains the retained decisions.

### What belongs in Git

The generated page and review JSON are local working files and should not be
committed. The JSON backs up your notes; it is not approved curation or a
second catalogue source. Share it explicitly when collaborating on a review,
and keep a backup outside Git if the notes need to be retained. Optional move
mappings and supplementary audit notes are also local inputs, not packaged
data required by the tool.

Commit the outcomes instead: concise reviewed findings in documentation,
confirmed curation or crawler changes, regression tests, and a regenerated
catalogue snapshot where appropriate. The committed `plugin-catalogue.json`
is catalogue data and is separate from the local `catalogue-review.json`.

## Generate the review page

Generate a self-contained HTML page from the repository root:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --output outputs/catalogue-review-local/index.html
```

Open `outputs/catalogue-review-local/index.html` in a browser. No server,
account, network connection, or new crawl is required to use the page.
Repository, metadata, documentation, and PyPI links open live sources when
you choose them. The embedded snapshot does not update automatically.

No reference snapshot, move mappings, or agent-generated notes are required.
The page includes visible and hidden current records and flags warnings and
potential PyPI link collisions. Without a reference, visible entries are not
labeled as new, and absent or changed records cannot be identified by comparison.

Use the review-group sidebar and the search, visibility, status, project-kind,
and attention filters to work through the records. Open a project's **Review**
detail to inspect metadata and edit your verdict, comment, expected handling,
and evidence URL. **Save and next** advances within the filtered list. The
**Review guide** explains every group and the visibility policy.

## Save decisions and refresh the page

Edits autosave by stable ID in this browser's local storage. They do not modify
the HTML file, GitHub, the catalogue, or curation rules. Use **Export review
JSON** to save your latest decisions as `catalogue-review.json` in the local
workspace. Your browser may download it elsewhere or add a suffix if a file
already exists; replace your working copy only after the new export succeeds.

Browser storage can be lost when clearing browser data, using private browsing,
or moving to a different file or origin. If storage is unavailable, the page
warns that edits are in memory only. Export before replacing the page.

After a new crawl, regenerate `index.html` using your latest decisions:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --previous outputs/catalogue-review-local/catalogue-review.json \
  --output outputs/catalogue-review-local/index.html
```

Here, `--previous` means the latest saved decisions, not an old HTML page or a
required archive. Alternatively, generate the page without that option and
use **Import review** in the browser. Resolve any import conflicts there
before using a JSON export as `--previous`.

Notes follow stable IDs, and reviewed records with changed source evidence are
flagged for re-review. A saved ID absent from the supplied snapshots remains as
`Prior-review only`, so its comment is not discarded. These retained notes are
part of the latest decisions file; no older review files are needed. When
refreshing a comparison, also supply its reference and any optional move mappings.

## Compare against an earlier catalogue

Add `--reference` to compare the current catalogue with an earlier snapshot:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --reference /path/to/earlier-catalogue.json \
  --output outputs/catalogue-review-local/index.html
```

This input is an earlier **catalogue snapshot**, not a review export. The
comparison adds new, absent, and changed records by stable ID. Git retains
committed catalogue versions, so separate local snapshot archives are not
required. The command does not contact GitHub or modify `plugin-catalogue.json`.
No repository-specific reference or mapping file is required.

Renamed repositories and relocated nested projects have different stable IDs.
Without verified move mappings, they remain separate absent and current-only
rows for investigation; matching names alone never merge records.

## Review groups and decisions

The review table is a working audit, not another catalogue schema. It includes
all current records, whether visible or hidden, plus records from an optional
reference snapshot that no longer appear. Each row has a stable ID, a review
group, visibility reason, repository and `pyproject.toml` links, and four
editable reviewer fields. `Hidden plugin` is a separate group on every export;
other hidden project kinds remain in `Hidden non-plugin`.

Filter by `Review group` to focus on hidden plugins and potential link
collisions, or on new, absent, and changed entries when comparing snapshots.
The page's review guide explains every group. A repeated PyPI URL is a review
cue, not proof of a bad link. The `pyproject.toml` URL is inferred from the
stable ID and default branch; check the repository if a project has moved.
The original-catalogue link appears only for rows that were visible in the
reference snapshot.

The browser detail form has four reviewer fields:

- `Reviewer verdict`: `Looks right`, `Should be hidden`, `Should be excluded`,
  `Should be visible`, `Metadata wrong`, or `Needs research`.
- `Reviewer comment`: why this is a useful example or what seems wrong.
- `Expected handling`: the desired general rule or narrow exception.
- `Evidence URL`: a source supporting the decision.

`Looks right` confirms the current classification and visibility, including
intentional hiding. Leaving the verdict blank means not reviewed; it does not
reject the record or change its current handling.

Reviewer fields are matched by stable ID, not row position. Review verdicts do
not directly change catalogue output: confirmed findings become tested
crawler/policy fixes or explicit reviewed curation, followed by a new crawl
and comparison. For a moved ID, notes on either ID are carried into the single
row. Conflicting notes on both IDs make regeneration fail rather than silently
discarding either one.

## Optional CSV export

Use **Export CSV** when a flat table is useful for another tool. CSV is not
needed for the browser workflow. The CLI can also generate it directly:

```bash
uv run plugin-catalogue review \
  --input plugin-catalogue.json \
  --previous outputs/catalogue-review-local/catalogue-review.json \
  --output outputs/catalogue-review-local/catalogue-review.csv
```

CSV retains the four reviewer fields, but not source fingerprints or conflict
history. An existing CSV is accepted as `--previous` for interoperability;
use JSON as the complete browser-review backup.

## Optional advanced inputs

These inputs supplement a particular review. They are authored manually by a
reviewer or collaborator; the crawler and review command do not create them.
Keep them in the ignored local workspace if needed. Ordinary use requires
neither file.

### Verified moves

With a reference snapshot, `--moves /path/to/review-moves.json` accepts:

```json
{
  "moves": [
    {
      "originalId": "github.com/example/old-name",
      "currentId": "github.com/example/new-name",
      "basis": "Verified repository rename"
    }
  ]
}
```

Each mapping must be one-to-one, from an original-only ID to a current-only
ID in the supplied comparison. It combines those rows into a single `Moved`
row with both IDs and the evidence basis. It does not rewrite catalogue IDs
or affect crawler discovery. Mappings must be checked again when changing
the reference; they are not universal aliases. Recording a move directly in
the browser is not currently supported.

### Supplementary audit notes

For HTML output, `--audit-findings /path/to/audit-findings.json` accepts:

```json
{
  "cases": [
    {
      "caseId": "example-check",
      "affectedStableIds": ["github.com/example/project"],
      "finding": "Check the declared upstream repository."
    }
  ]
}
```

The page shows these observations under **Agent findings** and labels affected
records, leaving reviewer fields untouched. These are supplementary evidence,
not review verdicts or approved curation. With no file supplied, this section
contains no findings.
