# Maintaining the catalogue

Run commands from the repository root.

## Development checks

```sh
uv sync --all-extras
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run plugin-catalogue validate --input plugin-catalogue.json
```

Tests mock network calls. Install Node.js to run the browser review tests;
pytest skips them if Node is unavailable. They can also be run directly:

```sh
node --test tests/review_core.test.cjs tests/review_ui.test.cjs
```

[CI](.github/workflows/actions.yml) runs pytest with coverage and Ruff on pushes.

## Code layout

| Component | Contents |
| --- | --- |
| [github.py](src/nomad_plugins/github.py) | GitHub requests, retries, pagination, repository status, and activity queries. |
| [pyproject.py](src/nomad_plugins/pyproject.py) | PEP 621 metadata, entry points, dependencies, and parsing warnings. |
| [crawler.py](src/nomad_plugins/crawler.py) | Discovery, merging, enrichment, and the `Plugin` model. |
| [transform.py](src/nomad_plugins/transform.py) | IDs, normalization, classification, capabilities, and visibility. |
| [activity.py](src/nomad_plugins/activity.py) | Activity models and the shared measurement window. |
| [catalogue.py](src/nomad_plugins/catalogue.py) | Snapshot model, schema generation, validation, and JSON output. |
| [config.py](src/nomad_plugins/config.py) | Configuration loading and validation. |
| [cli.py](src/nomad_plugins/cli.py) | Command-line interface. |
| [review.py](src/nomad_plugins/review.py), [review_html.py](src/nomad_plugins/review_html.py), [review_assets/](src/nomad_plugins/review_assets) | Snapshot comparison, reviewer notes, and the browser review page. |

## Discovery and curation

Defaults are in [plugin_catalogue_config.json](src/nomad_plugins/plugin_catalogue_config.json).
Print the effective configuration with:

```sh
uv run plugin-catalogue queries
```

Both `queries` and `crawl` accept `--config path.json`. A custom file replaces
the packaged configuration; it does not merge with it. Omitted lists use model
defaults, not the packaged lists.

### Queries and owners

- `codeSearchQueries` must start with
  `nomad.plugin in:file filename:pyproject.toml`. Additional queries must also
  target `pyproject.toml`. Code search finds root and nested projects.
- `repositorySearchQueries` adds targeted repository searches. Each candidate
  is checked for a root `pyproject.toml` on its default branch.
- `ownerSearches` accepts `{ "login": "...", "ownerType": "Organization" | "User" }`.
  Check the account type before adding it. The query uses `org:` or `user:`
  with `nomad in:name,description`; it does not list every repository.
- Request delays default to 6.5 seconds for code search and 2.1 seconds for
  repository search. Each repository query considers at most 120 raw candidates
  by default. Rejected and duplicate candidates still count towards that cap.

For a query or owner change, include an example missed project in the PR, add
mocked tests, and compare a live crawl with the baseline. See
[configuration and diagnostics](docs/how_to/use_this_plugin.md) for the full
field definitions and search-audit outcomes.

### Curation fields

| Field | Use |
| --- | --- |
| `manualProjectSeeds` | Add a root or nested project. It must have valid PEP 621 metadata and a NOMAD entry-point table or dependency. An invalid seed fails the crawl. |
| `officialTemplateRepositories`, `officialSoftwareRepositories` | Supply repository, name, and description for official entries that need not have a `pyproject.toml`. Live repository status is still checked. |
| `excludeCandidates` | Exclude an exact stable ID. A root exclusion also covers nested search candidates, but not an explicit official entry. |
| `excludeDocumentationUrls`, `excludePypiUrls` | Suppress incorrect links without removing the project. |

IDs use `github.com/owner/repository`, with `#relative/project/path` for nested
projects. Add evidence and regression tests for curation changes. Do not edit
generated JSON to implement an exception.

See [classification and visibility](docs/explanation/explanation.md) for the
rules that determine which records are shown.

## Refreshing the baseline locally

Set `GITHUB_TOKEN` in the shell, or use the crawl command's hidden prompt.
A local `.env` can also supply it. Keep credentials out of Git and logs.

When changing activity retrieval, first run the three-repository smoke check:

```sh
uv run python scripts/check_repository_activity.py
```

Check its counts, elapsed times, and GraphQL costs, then run a full crawl into
the local review workspace:

```sh
mkdir -p outputs/catalogue-review-local
uv run plugin-catalogue crawl --audit-searches \
  --output outputs/catalogue-review-local/candidate.json \
  > outputs/catalogue-review-local/crawl.log 2>&1 && \
uv run plugin-catalogue validate \
  --input outputs/catalogue-review-local/candidate.json
```

The full crawl takes several minutes. Query summaries are printed after a
successful crawl. A failed run preserves an existing output file; check the
exit status before using a candidate.

Follow the [audit process](docs/catalogue_review.md#audit-a-proposed-catalogue-refresh)
to compare the candidate with the baseline, investigate changes, and promote
the accepted file. Commit the catalogue and any related code, configuration,
tests, or schema changes. Keep raw logs, review pages, and reviewer JSON local.
Record the audit result in the PR; a separate Markdown report is optional.

The committed baseline is audited, but GitHub search is not exhaustive.
Each crawl searches afresh, so investigate missing records rather than
assuming their repositories were deleted.

### Activity data

Activity counts cover the default branch and include inherited and automated
commits. Nested projects share their repository's counts. `activityWindow`
covers 180 days; `dataUpdatedAt` is its end and the crawl-start cutoff.

Missing activity means unknown, not zero. A confirmed empty repository has zero
counts. Activity is not a quality score and does not affect visibility or output
ordering. See [field definitions](docs/explanation/explanation.md#repository-activity-not-a-maturity-score).

## Changing the schema

Update the Pydantic models and `SCHEMA_VERSION` in
[catalogue.py](src/nomad_plugins/catalogue.py). Schema and package versions are
independent:

- **Major:** incompatible fields or meanings.
- **Minor:** compatible optional additions.
- **Patch:** corrections that do not change valid JSON instances.

Regenerate the schema:

```sh
uv run python -c 'from nomad_plugins.catalogue import write_catalogue_schema; write_catalogue_schema()'
```

Update contract tests, run the suite, and validate the baseline. The schema test
catches model/schema drift, not an incorrect version choice. Coordinate breaking
changes with consumers. Generate new catalogue data through the crawler.

## Scheduled refresh

[Refresh plugin catalogue](.github/workflows/plugin-catalogue-refresh.yml) runs
on the first day of each month at **00:00 UTC**. To run it manually, open
**Actions → Refresh plugin catalogue → Run workflow**.

Configure `PLUGIN_CATALOGUE_GITHUB_TOKEN` under **Settings → Secrets and
variables → Actions**. This is the read token for discovery. The separate
workflow token creates the update PR; repository Actions settings must allow PR
creation.

1. `crawl-and-validate` crawls once, validates the result, and saves
   `plugin-catalogue.json` in an Actions artifact named `plugin-catalogue`.
2. On `main` only, `update-catalogue-pr` creates or updates
   `automated/plugin-catalogue` → `main`, containing only the generated JSON.

Manual runs on other branches produce an artifact without creating a PR.
Review the changes before merging. The crawl job has a 90-minute timeout.

### Troubleshooting

| Problem | Action |
| --- | --- |
| No scheduled run or Run workflow button | Check that the workflow exists on the default branch and is enabled. Schedules can be delayed or disabled after repository inactivity. See [GitHub troubleshooting](https://docs.github.com/en/actions/how-tos/troubleshoot-workflows). |
| Authentication failure | Check the token, secret name, API access, and organization authorization. Replace the token if needed. |
| Search cap warning | Review which query was capped and document the coverage limit. A deliberate candidate cap can still produce a valid, non-exhaustive snapshot. |
| Incomplete search or early pagination exhaustion | Inspect the named query and rerun after resolving the cause. Do not accept a partial result. |
| Rate-limit, HTTP, or GraphQL failure | Check the endpoint and reset time. Wait before retrying; keep request pacing. GraphQL errors can arrive with HTTP 200. |
| Invalid metadata | Check whether this is a skipped search candidate or a failed required seed/enrichment. Inspect the source before changing parsing or curation. |
| Schema validation failure | Check the models, generated schema, version, summary counts, and duplicate IDs. Do not promote the failed output. |
| No update PR | Check that the run used `main`, validation succeeded, the artifact exists, and the PR job has permission. Also check for an existing update PR. |
| Update-branch conflict | Compare with current `main` and resolve through the PR. Obtain a new validated crawl if needed; do not hand-edit records to resolve it. |
| No CI on an automated PR | Check workflow triggers. Current CI uses `push`, which pushes made with the workflow token do not trigger. Missing checks are not passing checks; see [GitHub token-trigger rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow). |

After a failure, rerun on the intended branch and review the new run's artifact
and diagnostics. Do not substitute a result from an older run.
