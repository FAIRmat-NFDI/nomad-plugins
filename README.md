![](https://github.com/FAIRmat-NFDI/nomad-plugins/actions/workflows/python-publish.yml/badge.svg)
![](https://img.shields.io/pypi/pyversions/nomad-plugins)
![](https://img.shields.io/pypi/l/nomad-plugins)
![](https://img.shields.io/pypi/v/nomad-plugins)

# NOMAD Plugins

A standalone catalogue generator for discovering NOMAD plugins.

## Using the catalogue generator

The `plugin-catalogue` CLI crawls public GitHub repositories for Python packages
that expose NOMAD plugin entry points or depend on NOMAD, and writes the discovered
metadata as JSON.

### Running the crawler

Install the package with e.g. pip:

```
pip install nomad-plugins
```

Inspect the packaged discovery queries without contacting GitHub:

```
plugin-catalogue queries
```

Run the crawler export:

```
plugin-catalogue crawl --github-token <token> --output plugins.json
```

Both commands accept `--config <path>` to override the packaged
`plugin_catalogue_config.json`.

## Main contributors
| Name | E-mail     |
|------|------------|
| Hampus Näsström | [hampus.naesstroem@physik.hu-berlin.de](mailto:hampus.naesstroem@physik.hu-berlin.de)
