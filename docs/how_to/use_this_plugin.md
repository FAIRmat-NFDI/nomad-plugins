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
It probes only the root `pyproject.toml` on each repository's default branch.
Code search continues to discover both root and nested projects.

The `github` configuration accepts:

- `repositorySearchQueries`: a list of unique, non-empty GitHub repository
  queries. Set it to `[]` to disable supplementary discovery. Custom
  configurations that omit this setting retain code-search-only behavior.
- `repositorySearchCandidateLimit`: an integer from 1 to 1000, defaulting to
  120. The limit applies independently to the raw repository candidates from
  each query, before exclusions and TOML filtering.
- `repositorySearchRequestDelaySeconds`: a finite, non-negative number,
  defaulting to 2.1 seconds between repository-search requests, including
  pagination and subsequent queries. This is separate from code-search pacing.

A valid PEP 621 project qualifies when it contains a
`[project.entry-points."nomad.plugin"]` table (including an empty table), or
declares `nomad-lab` in runtime or optional dependencies. Dependency names use
the existing normalization rules. Mentions in comments, descriptions, or URLs
do not qualify. No Poetry or YAML fallback is used.

Root files and parsed metadata are reused across overlapping queries. A root
already discovered by code search is processed through that existing path.
Archived repositories and forks retain the existing classification and
visibility policy.

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

Discovery changes do not alter the public catalogue contract; snapshots remain
on schema version `2.1.0`.
