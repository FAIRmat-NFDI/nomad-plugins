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
