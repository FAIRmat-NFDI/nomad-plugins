# Use the Catalogue Generator

The catalogue generator crawls public GitHub repositories for Python packages that
expose NOMAD plugin entry points and writes the discovered metadata as JSON.

## Export crawler results

Run the crawler with a GitHub token and an output path:

```sh
plugin-catalogue crawl --github-token <token> --output plugins.json
```
