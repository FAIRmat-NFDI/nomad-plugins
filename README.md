![](https://github.com/FAIRmat-NFDI/nomad-plugins/actions/workflows/python-publish.yml/badge.svg)
![](https://img.shields.io/pypi/pyversions/nomad-plugins)
![](https://img.shields.io/pypi/l/nomad-plugins)
![](https://img.shields.io/pypi/v/nomad-plugins)

# NOMAD Plugins

A standalone catalogue generator for discovering NOMAD plugins.

## Using the catalogue generator

The `plugin-catalogue` CLI crawls public GitHub repositories for Python packages
that expose NOMAD plugin entry points and writes the discovered metadata as JSON.

### Running the crawler

Install the package with e.g. pip:

```
pip install nomad-plugins
```

and run the crawler export:

```
Usage: plugin-catalogue crawl [OPTIONS]

  Crawl plugin metadata and write the current crawler result as JSON.

Options:
  --github-token TEXT  Your GitHub personal access token to use when querying
                       for plugins.
  --output FILE        Path where the crawler JSON result should be written.
                       [required]
  --help               Show this message and exit.
```


## Main contributors
| Name | E-mail     |
|------|------------|
| Hampus Näsström | [hampus.naesstroem@physik.hu-berlin.de](mailto:hampus.naesstroem@physik.hu-berlin.de)
