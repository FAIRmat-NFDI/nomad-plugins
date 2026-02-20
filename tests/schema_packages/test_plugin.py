import os.path

from nomad.client import normalize_all, parse


def test_schema_package():
    test_file = os.path.join('tests', 'data', 'test.archive.yaml')
    entry_archive = parse(test_file)[0]
    normalize_all(entry_archive)

    assert entry_archive.results.eln.lab_ids == [
        'https://github.com/FAIRmat-NFDI/nomad-material-processing',
        'https://pypi.org/project/nomad-material-processing/',
    ]
    assert entry_archive.metadata.comment == (
        'A plugin for NOMAD containing base sections for material processing.'
    )
    assert entry_archive.data.owner_type == 'Organization'
    assert entry_archive.data.archived is False
