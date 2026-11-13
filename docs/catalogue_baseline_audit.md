# Catalogue baseline audit (2026-11-13)

This audit accompanies [`plugin-catalogue.json`](../plugin-catalogue.json). It
compares the current live crawl with the reference `plugin-registry.json` at
commit `6158333`; changing GitHub, PyPI, and deployment data is not expected to
match byte-for-byte.

## Generation and validation

The catalogue was generated with the packaged step-11 configuration:

```bash
uv run plugin-catalogue crawl --audit-searches --output /tmp/plugin-catalogue-step12.json > /tmp/plugin-catalogue-step12.log 2>&1
```

The authenticated shell supplied `GITHUB_TOKEN`; the token value was not
recorded.

The run completed successfully with 419 unique `pyproject.toml` candidates and
422 exported records. The output validates as `CatalogueSnapshot` schema
`2.2.0`, has unique stable IDs, and matches its deterministic serializer. No
`dataUpdatedAt` value is included. Both code searches completed (224 and 337
results); no search reported incomplete results. The `nomad-parser` repository
search remained deliberately bounded at 120 of 161 reported results, so this is
not an exhaustive GitHub inventory. Two probed root `pyproject.toml` files had
no `[project]` table (`FAU-LAP/nomad-parser-plugins-camels` and
`nomad-hzb/nomad-pv-analysis-apps`); neither was a reference plugin row. No
transient fetch failure or unresolved skipped candidate was reported.

| Measure | Reference | Current |
| --- | ---: | ---: |
| All records | 390 | 422 |
| Plugin records | 220 | 238 |
| Registry-visible records | 253 | 264 |
| Warning messages | 243 | 5 |

There are 367 shared stable IDs, 55 new IDs, and 23 absent reference IDs. Of
the absent IDs, 12 were previously classified as plugins. Their dispositions
below require reviewer agreement; the crawler does not silently preserve stale
rows merely to match the reference count.

## Reference plugin IDs not present under the same ID

| Reference ID(s) | Current disposition |
| --- | --- |
| `github.com/ahm531/fairmat-members` | Repository transferred to [`FAIRmat-NFDI/fairmat-members`](https://github.com/FAIRmat-NFDI/fairmat-members); the plugin is present under its new repository-derived ID. |
| `github.com/fairmat-nfdi/nomad-topology-normalizer` | Repository renamed to [`nomad-results-normalizer`](https://github.com/FAIRmat-NFDI/nomad-results-normalizer); the plugin is present under the new ID. |
| `github.com/fairmat-nfdi/nomad-plugins` | This project was intentionally converted from a NOMAD plugin into the standalone catalogue generator; its current `pyproject.toml` has no NOMAD plugin signal. |
| `github.com/fairmat-nfdi/nomad-utility-workflows` | The current default-branch [`pyproject.toml`](https://github.com/FAIRmat-NFDI/nomad-utility-workflows/blob/develop/pyproject.toml) no longer has `nomad.plugin` entry points or a `nomad-lab` dependency. The owner search probes it but reports `no_signal`; retaining its historical plugin row would misstate current installability. |
| Five IDs below `github.com/harrytyp/econversion-nomad#` | The repository is now archived. Its root is retained as an archived distribution; the five formerly indexed nested plugin paths are not present in the current search results. |
| Three IDs below `github.com/harrytyp/unified-researchdata-mcp#nomad/plugins/` | The nested `instrument_data_old`, `instrument_data_old/instrument_data`, and `three_way_sync` projects moved beneath `nomad/plugins/legacy/`; all three plugins are present under their new path-derived IDs. |

The 12 omissions above are attributable to current repository identity, status,
or source changes, not loss of a Poetry-only plugin after removing the Poetry
fallback. Eleven other absent reference IDs were non-plugin rows; these are not
part of the 220-plugin parity gate.

## Field-level and representative checks

Across the 367 shared IDs, `projectKind`, `registryVisible`, `ownerType`, and
`status.fork` have no differences. The one archive-status change is
`harrytyp/econversion-nomad` (`false` to `true`). Twelve `pluginTypes` values
and 21 entry-point lists differ, consistent with changed upstream declarations;
none of the shared rows changed between `pluginTypes: null` and a non-null
value. Four current records have an `unknown` capability, each with an explicit
unclassified-entry-point warning. The reference's fifth `unknown` entry,
`pynxtools`, is now classified as `action` by its current declaration.

Current warnings describe parser issues, notably unclassified entry points;
the reference also emitted broader warnings such as missing entry points or a
different declared repository URL. PyPI links are now checked for package
existence (66 current links versus 381 reference links), and public NOMAD
deployment data is now populated. These policy/enrichment and changing telemetry
fields are not strict parity assertions.

Representative rows are present: `nomad-material-processing`, all 11 reviewed
`nomad-north-*` projects, `nomad-semantic-web-service` (including its now-valid
PyPI link), `nomad-baseclasses` as a visible dependent package, all five
official templates, and `nomad-lab`, `nomad-docs`, and `NOMAD-CAMELS` as official
software. The two NORTH projects that now declare action entry points are
reported as `action`; the other nine remain `north_tool`.
