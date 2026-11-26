# Catalogue discovery, visibility, and repository activity

Discovery and visibility are separate decisions. The crawler can retain a
project in the JSON catalogue while setting `registryVisible` to `false`.
This keeps potentially useful evidence available for review without presenting
every search result as a usable plugin.

## How projects enter the catalogue

Code search finds root and nested `pyproject.toml` files containing the text
`nomad.plugin` or `nomad-lab`. A valid PEP 621 `[project]` table is required,
but the crawler does not recheck whether the search text represents an actual
entry-point declaration or dependency. A match in a comment, description, or
URL can therefore become a hidden catalogue record.

Targeted repository and reviewed-owner searches probe only the root
`pyproject.toml`. These candidates must have a `nomad.plugin` entry-point
table, even if it is empty, or a runtime or optional dependency whose name
normalizes to `nomad-lab`. Manually seeded projects must pass the same check.
An owner match alone is not sufficient. Explicitly curated official software
and template rows are different: they do not require a `pyproject.toml` and
use the classification supplied by the configuration.

## How project kinds are assigned

For projects parsed from `pyproject.toml`, the first matching rule wins:

1. **Template or example:** the name or nested project path contains `{{`;
   the path has an `examples` segment; the description is exactly
   `nomad example template` (ignoring case and surrounding whitespace);
   the repository URL contains `cookiecutter` or `plugin_template`; or the
   normalized name ends in `_template`. This rule takes precedence even when
   the project declares plugin entry points.
2. **Plugin:** at least one valid `nomad.plugin` entry point was parsed.
   An empty entry-point table does not meet this rule.
3. **Distribution:** the normalized name is `nomad-distribution`; the name,
   description, or repository URL contains `distro` or `distribution`; the
   combined text contains `oasis` and either `deployment` or `image`; the
   normalized name ends in `-image`; or the normalized repository URL contains
   `_image`. These text checks run only after the plugin rule.
4. **NOMAD-dependent package:** a runtime or optional dependency name
   normalizes to exactly `nomad-lab`.
5. **Other ecosystem package:** none of the preceding rules applies. This is
   a fallback category, not proof that the package has a working NOMAD
   integration. It can include an empty `nomad.plugin` table or a code-search
   result whose match was only textual.

The text checks are case-insensitive. Some also normalize hyphens, periods,
and spaces to underscores; the exact description match above does not. These
rules are heuristics, so a name or description can cause a misclassification.
Review the source metadata before adding an exception.

## Which records are visible

`registryVisible` is `true` for plugins, NOMAD-dependent packages, and
explicitly curated official software and templates. It is `false` for
distributions, ordinary templates or examples, and other ecosystem packages.
GitHub's `archived` or `fork` flag makes any kind invisible, including an
otherwise visible plugin or official row.

An invisible record remains in the JSON snapshot. By contrast,
`excludeCandidates` prevents a search candidate from becoming a record;
excluding a repository root also excludes its nested candidates. Explicit
official rows are not removed by that search-candidate exclusion. PyPI links,
deployment status, stars, repository activity, and discovery warnings do not
determine visibility.

## Repository activity, not a maturity score

Schema `2.3.0` adds an optional `status.activity` block for consumers that want
to sort or filter by repository activity. It does not change discovery,
classification, visibility, identity, or the deterministic snapshot ordering.
The existing `status.stars`, `createdAt`, and `lastPushedAt` remain separate.

| Field | Meaning |
| --- | --- |
| `status.activity.totalCommits` | Commit count reachable from the sampled default-branch head, as reported by GitHub history. |
| `status.activity.recentCommits` | Count from that same history restricted to the global `activityWindow.start` / `end` bounds. |
| `status.activity.lastCommitAt` | Committer timestamp of that default-branch head, not the last push or the latest commit across all branches. |
| `activityWindow.start` / `end` | One shared UTC interval spanning exactly 180 days, not six calendar months. |
| `dataUpdatedAt` | Crawl-start timestamp, equal to `activityWindow.end`; it is a common collection cutoff, not a claim that every repository was queried simultaneously. |

Both counts come from the same GitHub GraphQL `Commit` object. The sampled head
SHA is kept internally during retrieval, but is not a public catalogue field.
The query asks for history `totalCount` rather than downloading every commit.
See GitHub's [Commit history reference](https://docs.github.com/en/graphql/reference/commits).

Each unique exported repository is queried once per crawl, including archived,
forked, and explicitly configured repositories. At most four activity queries
run concurrently. Root and nested projects from one repository share the same
activity measurements; these are **not** counts of changes to a nested project's
directory. The default branch can move during a crawl, and the shared recent
window excludes later timestamps even when the sampled head has advanced.

The history includes inherited commits, merges, automated changes, and commits
unrelated to a particular plugin. Copied repositories can inherit substantial
history, and rewritten history can reduce counts. Stars and commit counts are
therefore useful signals, not proof of quality, maturity, independent authorship,
or which repository should be treated as canonical. Ranking and filters belong
to the consuming interface; no composite score or automatic merge is applied.

A confirmed empty repository has zero counts and no `lastCommitAt`. Missing
activity in an older or unsampled snapshot means **unknown**, not zero.
Authentication, transport, HTTP, GraphQL errors (including HTTP 200 with partial
data), and malformed or inconsistent counts abort a new crawl without replacing
the previous output. A non-empty repository whose default-branch history cannot
be read also fails rather than being called inactive.

The CLI reports unique repository count, the sum of GraphQL-reported query
costs, and the shared window. GraphQL has a separate rate-limit budget from
REST; retries may add requests beyond the one successful query per repository.
See GitHub's [GraphQL rate-limit documentation](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api).
