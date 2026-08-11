# Maintaining the Plugin Registry

Run commands from the `nomad-plugins` repository root unless noted otherwise.

This is a maintainer note for the crawler and generated registry snapshot. It is
intentionally not linked from `mkdocs.yml`; keep it reachable from the
repository README only.

## Responsibilities and Data Flow

The registry workflow has two outputs from one crawler pipeline:

1. `plugin-registry.json`, the public schema v2 snapshot consumed by the NOMAD
   homepage.
2. Legacy NOMAD archive JSON, uploaded by `plugin-crawler` for the existing
   NOMAD/Oasis plugin app.

The important boundary is between discovery and publication. Finding a
repository does not automatically mean it is visible in the public catalogue.
Hidden distributions, examples, archived repositories, and reviewed non-page
rows remain in the snapshot so the crawler decisions can be audited.

```text
GitHub code search ---------\
GitHub repository search ----+--> candidate merge/deduplication
configured repositories ----/              |
                                             v
                                  fetch pyproject + repo status
                                             |
                                             v
                         classify rows + enrich legacy metadata
                                             |
                              +--------------+--------------+
                              v                             v
                    homepage registry JSON        legacy NOMAD archives
```

## Code Map

- `src/nomad_plugins/cli.py`: `plugin-registry` command line interface and
  final quality checks.
- `src/nomad_plugins/plugin_registry_config.json`: search criteria, exclusions,
  configured official repositories, owner groups, deployment sources, and
  quality settings.
- `src/nomad_plugins/github.py`: GitHub code search, repository search, file
  fetching, repository status, retries, and request timeout.
- `src/nomad_plugins/crawler.py`: discovery orchestration, deduplication,
  fetching, enrichment, configured inclusions, and report construction.
- `src/nomad_plugins/pyproject.py`: PEP 621 and Poetry metadata parsing,
  `nomad.plugin` entry points, dependencies, links, and classification.
- `src/nomad_plugins/capabilities.py`: entry point type normalization and
  inference.
- `src/nomad_plugins/transform.py`: public snapshot projection, stable IDs,
  summary counts, and direct legacy NOMAD archive projection.
- `src/nomad_plugins/registry.py`: configuration validation, schema v2 snapshot
  validation, and atomic writes.
- `src/nomad_plugins/nomad_upload.py`: ZIP archive creation, NOMAD
  authentication, upload, processing wait, and reprocessing trigger.
- `src/nomad_plugins/plugin_crawler.py`: backward-compatible legacy upload CLI
  that uses the shared crawler for live crawls.
- `tests/plugin_registry/`: unit tests with fake GitHub responses. Crawler tests
  must not depend on the live GitHub API.

## Common Commands

Install development dependencies:

```sh
uv sync --extra dev
```

Set a GitHub token for a live crawl:

```sh
export PLUGIN_REGISTRY_GITHUB_TOKEN='...'
```

Print all configured GitHub query strings without running a crawl:

```sh
uv run plugin-registry github-queries
```

Validate a registry snapshot:

```sh
uv run plugin-registry validate --input plugin-registry.json
```

Run a fast local smoke test that skips broad repository search:

```sh
uv run plugin-registry crawl-pyprojects \
  --output /tmp/plugin-registry.json \
  --skip-repository-search
```

Run a small broad-discovery test:

```sh
uv run plugin-registry crawl-pyprojects \
  --output /tmp/plugin-registry.json \
  --max-repository-candidates 10
```

Run the full crawler and also emit legacy NOMAD archive input:

```sh
uv run plugin-registry crawl-pyprojects \
  --output /tmp/plugin-registry.json \
  --legacy-output /tmp/plugin-crawler-upload.json
```

Upload legacy plugin archives to NOMAD from a live crawl:

```sh
uv run plugin-crawler
```

Upload from an existing public registry snapshot, for compatibility:

```sh
uv run plugin-crawler --input plugin-registry.json
```

Run tests:

```sh
uv run pytest tests/plugin_registry
```

## Reading Crawl Output

A successful write prints a report similar to:

```json
{
  "fetchedCount": 369,
  "formatted": false,
  "legacyOutput": "/tmp/plugin-crawler-upload.json",
  "output": "/tmp/plugin-registry.json",
  "pluginCount": 373,
  "registryVisibleCount": 243,
  "skipped": [],
  "skippedCount": 0
}
```

- `fetchedCount` counts candidate pyprojects downloaded far enough to process.
  It does not include configured official repositories.
- `pluginCount` counts all snapshot rows after merging, including hidden rows,
  NOMAD-dependent packages, official software, and templates.
- `registryVisibleCount` counts rows eligible for one of the public homepage
  tabs.
- `skipped` contains candidate-specific fetch, parse, repository-status, or fork
  errors. Treat a non-empty list as review input before accepting a snapshot.
- `formatted` says whether a local `prettier` binary was used after writing.
  The crawler never invokes `npx`; if `prettier` is not installed, Python JSON
  formatting is kept.

Do not accept a lower but schema-valid snapshot without inspecting the diff.
GitHub search results can drift, and a successful crawl is not automatically a
complete crawl.

## Discovery Paths

`github.searchQueries` is the broad discovery path. The crawler currently
executes only entries containing `pyproject.toml`, follows GitHub pagination,
keeps root and subdirectory pyprojects, and deduplicates by stable ID.

`github.repositorySearchQueries` supplements code search with repository
queries such as plugin name families and GitHub topics. For every repository
result, the crawler probes only the root `pyproject.toml`. The candidate is
retained only if the raw text contains `nomad.plugin` or `nomad-lab`,
case-insensitively.

The config also includes org-scoped repository queries for GitHub organizations
that already have visible plugin rows. These queries are not repository-specific
exceptions; they give known plugin-producing organizations their own repository
search windows when broad GitHub code search drops older or less prominent
repositories.

Update the org-scoped list only after reviewing a generated snapshot. Add an
organization when a visible plugin from that organization is intentionally
accepted into the catalogue, and remove one only if the organization no longer
has any accepted visible plugin rows.

`github.maxRepositoryCandidates` is a per-query local work cap. It does not
remove GitHub's own search-result limit and does not prove completeness.
`github.searchRequestDelaySeconds` paces GitHub search API calls so the
org-scoped query layer does not immediately trip GitHub's search limits.

Configured official rows are intentionally curated because they are not always
discoverable plugin packages:

- `github.officialTemplateRepositories`
- `github.officialSoftwareRepositories`

Keep these lists small and reviewed. They are page curation, while search
queries are discovery criteria.

## Candidate Identity

Stable IDs have these forms:

```text
github.com/owner/repository
github.com/owner/repository#path/to/package
```

The scheme and `.git` suffix are discarded, repository identity is lowercased,
and subproject paths are normalized. Code-search and repository-search
candidates with the same ID are merged before fetching. Multiple packages in
one monorepo remain separate rows.

`github.excludeCandidates` uses this stable-ID syntax. Prefer it only for known
discovery artifacts, such as invalid cookiecutter placeholders.

## Entry Point Types

The public snapshot uses these canonical entry point types:

- `action`
- `api`
- `app`
- `dashboard`
- `example_upload`
- `normalizer`
- `north_tool`
- `parser`
- `schema`

Legacy `tool` is normalized to `action`. An actual non-empty `nomad.plugin`
entry point that cannot be mapped is preserved as `unknown`. An absent or empty
entry point group produces no entry points and therefore `pluginTypes: null`,
not `unknown`.

## Project Kinds and Visibility

`projectKind` describes what a row is. `registryVisible` separately controls
whether it appears on the public page.

| `projectKind` | Meaning | Normal visibility |
| --- | --- | --- |
| `plugin` | At least one valid `nomad.plugin` entry point was parsed. | Visible unless archived. |
| `nomad_dependent_package` | No entry point, but package depends on `nomad-lab`. | Visible unless archived. |
| `official_template` | Reviewed official template/reference repository. | Visible unless archived. |
| `official_software` | Reviewed official NOMAD ecosystem software. | Visible unless archived. |
| `distribution` | Likely NOMAD/Oasis distribution, deployment, or image. | Hidden. |
| `template_or_example` | Copied/unmodified example, templated package, or package under `examples/`. | Hidden. |
| `ecosystem_package` | Broad signal but no plugin entry point or direct `nomad-lab` dependency. | Hidden. |

Archived repositories are retained in the snapshot with `status.archived: true`
but are hidden when they reach status enrichment.

## Legacy NOMAD Upload

The live `plugin-crawler` command now uploads legacy archive records directly
from the enriched crawl report. This preserves legacy-only metadata such as
authors, maintainers, actual PyPI existence, deployment flags, and plugin-only
dependency references.

The public snapshot can still be used as `plugin-crawler --input
plugin-registry.json` for compatibility, but that path necessarily reconstructs
legacy fields from public JSON and should not be used as the preferred workflow.

## Safe Refresh Checklist

1. Start from a known committed snapshot and a clean worktree.
2. Review the query set with `uv run plugin-registry github-queries`.
3. Run `crawl-pyprojects` with a token and inspect `skippedCount` and every
   skipped message.
4. Rerun after transient failures.
5. Validate the generated snapshot.
6. Compare the generated snapshot against the committed baseline, especially
   removed rows, `projectKind`, `registryVisible`, `pluginTypes`, archival
   changes, warnings, and reviewed link suppression.
7. Run tests.
8. Commit the generated snapshot together with crawler/config changes that
   explain the diff.

Useful read-only checks:

```sh
git diff --stat -- plugin-registry.json
git diff -- plugin-registry.json
uv run plugin-registry validate --input plugin-registry.json
```

## Search Limits and Completeness

There are two separate limits:

1. `maxRepositoryCandidates` is imposed by this crawler per repository query to
   bound API work.
2. GitHub search itself exposes a bounded result window and can report
   incomplete results.

A local cap, local filtering, or skipping known repositories does not recover a
repository that GitHub omitted before returning results. Targeted queries are
still useful because small, meaningful searches have their own result windows.

The current snapshot is a strong working catalogue, not yet a proven complete
baseline. The planned completeness audit is to shard broad discovery by
creation or update date, recursively narrow capped shards, include archived
repositories, and then move routine refreshes toward direct maintenance of
known repositories plus incremental discovery for new ones.
