# Use the Catalogue Generator

The catalogue generator crawls public GitHub repositories for Python packages that
expose NOMAD plugin entry points or depend on NOMAD, and writes the discovered
metadata as JSON.

Inspect the effective discovery queries without contacting GitHub:

```sh
plugin-catalogue queries
```

## Export a catalogue snapshot

Run the crawler with a GitHub token and an output path:

```sh
plugin-catalogue crawl --github-token <token> --output plugins.json
```

Pass `--config <path>` to either command to override the packaged configuration.
Add `--audit-searches` to a crawl to print every code- and repository-search
result with its per-query outcome and, when present, the final exported project
kind. This audit is CLI output only; it does not change the catalogue JSON.

## Configure repository discovery

The packaged configuration adds reviewed repository queries for NOMAD plugin
topics and name families, including NORTH tools and the semantic web service.
It also includes owner-scoped searches for the organizations and personal
accounts represented by plugins in the reference catalogue snapshot. Their
GitHub owner types determine whether an `org:` or `user:` query is used.
It probes only the root `pyproject.toml` on each repository's default branch.
Code search continues to discover both root and nested projects.

The `github` configuration accepts:

- `repositorySearchQueries`: a list of unique, non-empty GitHub repository
  queries. Set it to `[]` to disable targeted repository queries.
- `ownerSearches`: a reviewed list of `{ "login": "...", "ownerType":
  "Organization" | "User" }` entries. Each produces a separate
  `org:<login> nomad in:name,description` or
  `user:<login> nomad in:name,description` query. Omit or set it to `[]` to
  disable owner searches. Custom configurations that omit both query lists
  retain code-search-only behavior.
- `repositorySearchCandidateLimit`: an integer from 1 to 1000, defaulting to
  120. The limit applies independently to the raw repository candidates from
  each targeted or owner query, before exclusions and TOML filtering.
- `repositorySearchRequestDelaySeconds`: a finite, non-negative number,
  defaulting to 2.1 seconds between repository-search requests, including
  pagination and subsequent targeted or owner queries. This is separate from
  code-search pacing.

The packaged owner list was derived from `projectKind == plugin` records in the
reviewed reference snapshot at `6158333`: 23 organizations and 46 personal
accounts. The public `QEDeD` account is omitted because GitHub rejects its
`user:` repository search; its plugin is still found by code search. The list
is a discovery seed, not proof that every listed plugin is valid
or that every producer has been found. When reviewing a new owner, verify its
GitHub account type and update `ownerSearches` explicitly; do not automatically
expand the list from unreviewed search results. Owner-scoped searches remain
bounded and do not replace a future direct refresh of known repositories.

Repository and owner-search candidates, as well as manual seeds, require a
valid PEP 621 project with a `[project.entry-points."nomad.plugin"]` table
(including an empty table) or a `nomad-lab` runtime or optional dependency.
Code search is textual and can also retain a valid project whose match was
only in a comment, description, or URL. See [catalogue discovery and
visibility](../explanation/explanation.md) for the classification and hiding
rules. No Poetry or YAML fallback is used.

Root files and parsed metadata are reused across overlapping queries. A root
already discovered by code search is processed through that existing path.
Archived repositories and forks retain the existing classification and
visibility policy. An owner match by itself never qualifies a repository.

## Curate entries and check availability

The packaged `curation` section contains reviewed `officialTemplateRepositories`
and `officialSoftwareRepositories` rows. Each row has a GitHub `repository` in
`owner/name` form, a public `name`, and a `description`. These rows use live
GitHub repository status but intentionally do not require a `pyproject.toml`;
their `metadataSource` is `crawler-config`. They replace a discovered
root record with the same stable ID, while nested projects remain distinct.

`manualProjectSeeds` accepts `{ "repository": "owner/name", "projectPath":
"optional/nested/path" }`. Unlike official rows, seeds must have a valid PEP
621 `pyproject.toml` and the same NOMAD signal required of discovered projects.
An invalid or missing seed fails the crawl. Seeds already found by search
deduplicate by stable ID and project path; parsed repository-search metadata is
reused, while code-search overlaps are verified from the default-branch file.

`excludeCandidates` lists exact catalogue IDs; excluding a repository root
also excludes its nested candidates from discovery, but does not prevent an
explicit official row. `excludeDocumentationUrls` and `excludePypiUrls`
suppress known incorrect links without removing otherwise valid records. These
lists are small, reviewed exceptions, not alternate discovery rules.
The packaged candidate exclusions include two temporary test repositories
surfaced by owner search; their metadata describes them as tests/removable.

`deploymentSources` names the central and example Oasis `/info` endpoints.
The crawler reads their installed `plugin_packages`. It emits a PyPI link only
when PyPI's project JSON metadata links to the discovered GitHub repository;
matching the package name alone is insufficient. A PyPI 404 or metadata without
a matching repository leaves the link empty. Failed or malformed deployment or
PyPI responses abort the crawl without replacing an existing output file.
This prevents source outages from being recorded as confirmed missing links.

## Interpret discovery diagnostics

Each repository query reports its latest GitHub total, raw fetched count,
number of candidates considered, accepted roots, existing code candidates,
and exclusions split into missing files, invalid metadata, absent NOMAD
signals, and excluded repositories. Counts are per query: an overlapping root
can appear in several query reports but only once in the final snapshot.
The optional candidate audit makes those overlaps visible by stable ID. For
repository search, `accepted_new` means the root passed the NOMAD signal check
and was not contributed by an earlier query; `accepted_overlap` means an earlier
repository query had already accepted it. `existing_code_candidate` means code
search had already found its root, so repository search did not re-probe it.
For code search, `new_candidate` and `overlap` describe candidate discovery,
before parsing; `not exported` identifies a candidate that did not become a
catalogue record. Rejection outcomes such as `missing`, `invalid`, and
`no_signal` are listed with their repository IDs. Audit lines are sorted within
each query for reproducibility, while GitHub's search results and totals may
change between crawls.

Candidate limits apply before filtering and deduplication; rejected or already
known candidates do not free slots in the query's result window. A final page
can fetch more results than the configured limit, but only candidates within
the limit are considered. The page size stays constant to avoid shifting
pagination offsets.

An intentional local cap produces a visible warning. GitHub's 1000-result
window is reported separately, including when the configured local cap is
smaller. These bounded searches are not evidence of an exhaustive inventory.

GitHub `incomplete_results`, unexpected early pagination exhaustion, and final
authentication, HTTP, or transport failures abort the export. The failure
identifies the query or repository; the existing output is preserved. Only
HTTP 404 on a supplementary root probe is treated as a normally missing file.
Malformed TOML or invalid PEP 621 metadata is reported and excluded.

The current snapshot contract uses schema version `2.3.0`, including optional
repository activity metadata. Every full crawl samples default-branch activity
once per unique exported repository and records a common 180-day UTC window.
See [repository activity semantics](../explanation/explanation.md#repository-activity-not-a-maturity-score)
before using these values for sorting or filtering.

## Check activity enrichment live

Before a full crawl, run the bounded, read-only smoke check from the repository
root in a shell where `GITHUB_TOKEN` is set:

```sh
uv run python scripts/check_repository_activity.py
```

This queries three known repositories, including the larger NOMAD repository,
and prints counts, sampled head, elapsed time, and GraphQL point cost. It does
not write a catalogue or modify GitHub. You can pass other `owner/name` arguments
to select the repositories. The sampled head is diagnostic only and is not
exported in catalogue JSON. A failure should be resolved before attempting the
full crawl; never interpret unavailable activity as zero.

For the complete sequence from a candidate crawl through comparison, human
review, and promotion into Git, follow the
[catalogue refresh audit process](../catalogue_review.md#audit-a-proposed-catalogue-refresh).
The [2026-11-25 activity audit](../catalogue_activity_audit.md) is a historical
record of that process, not a required input or a report created automatically
by the command.
