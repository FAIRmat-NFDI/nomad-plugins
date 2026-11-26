"""Keep the repository-only maintainer entry point usable and unpublished."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'MAINTAINERS.md'


def test_readme_links_directly_to_repository_maintainer_guide():
    assert GUIDE.is_file()
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    assert '[maintainer guide](MAINTAINERS.md)' in readme


def test_maintainer_guide_is_outside_public_mkdocs_content_and_navigation():
    config = (ROOT / 'mkdocs.yml').read_text(encoding='utf-8')
    configured_docs = re.search(r'^docs_dir:\s*([^\n#]+)', config, re.MULTILINE)
    docs_dir = configured_docs[1].strip(' "\'') if configured_docs else 'docs'

    assert not GUIDE.resolve().is_relative_to((ROOT / docs_dir).resolve())
    assert GUIDE.name not in config


def test_maintainer_guide_repository_links_resolve():
    content = GUIDE.read_text(encoding='utf-8')
    targets = re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', content)

    assert targets
    for target in targets:
        if target.startswith(('https://', 'http://', '#')):
            continue
        relative_path = target.split('#', 1)[0]
        assert (ROOT / relative_path).exists(), f'Broken maintainer link: {target}'
