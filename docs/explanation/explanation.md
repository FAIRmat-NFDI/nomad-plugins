# Catalogue discovery and visibility

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
deployment status, stars, and discovery warnings do not determine visibility.
