from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from nomad_plugins.nomad_upload import (
    NomadUploadInfo,
    upload_legacy_plugin_data,
)


class NomadUploadTests(unittest.TestCase):
    def test_upload_legacy_plugin_data_writes_archive_zip(self) -> None:
        plugin_data = {
            'data': {
                'name': 'example-plugin',
                'm_def': 'nomad_plugins.schema_packages.plugin.Plugin',
                'repository': 'https://github.com/example/example-plugin',
            },
        }
        captured = {}

        def fake_put(url, *, headers, data, timeout):
            with tempfile.NamedTemporaryFile(delete=False) as output:
                output.write(data.read())
                captured['zip_path'] = output.name
            captured['url'] = url
            captured['headers'] = headers
            captured['timeout'] = timeout
            return FakeResponse({'upload_id': 'upload-123'})

        with patch('nomad_plugins.nomad_upload.requests.put', fake_put):
            upload_id = upload_legacy_plugin_data(
                NomadUploadInfo(
                    nomad_url='https://nomad.example/api/v1',
                    token='secret-token',
                    upload_id='existing-upload',
                ),
                [plugin_data],
            )

        self.assertEqual(upload_id, 'upload-123')
        self.assertEqual(
            captured['url'],
            'https://nomad.example/api/v1/uploads/existing-upload/raw/',
        )
        self.assertEqual(captured['headers']['Authorization'], 'Bearer secret-token')
        self.assertEqual(captured['timeout'], 30)

        zip_path = Path(captured['zip_path'])
        with ZipFile(zip_path) as archive:
            self.assertEqual(archive.namelist(), ['example-plugin.archive.json'])
            self.assertEqual(
                json.loads(archive.read('example-plugin.archive.json')),
                plugin_data,
            )


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


if __name__ == '__main__':
    unittest.main()
