from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from nomad_plugins.plugin_crawler import main


def test_cli_passes_crawler_results_to_upload():
    upload_info = SimpleNamespace(
        nomad_url='https://nomad.example/v1',
        token='nomad-token',
        upload_id=None,
    )
    plugins = [object()]

    with (
        patch(
            'nomad_plugins.plugin_crawler.get_upload_args',
            return_value=upload_info,
        ),
        patch(
            'nomad_plugins.plugin_crawler.find_plugins',
            new=AsyncMock(return_value=plugins),
        ),
        patch(
            'nomad_plugins.plugin_crawler.upload_to_NOMAD',
            return_value='upload-id',
        ) as upload,
        patch(
            'nomad_plugins.plugin_crawler.wait_for_processing',
            return_value=True,
        ),
        patch(
            'nomad_plugins.plugin_crawler.trigger_processing',
            return_value=True,
        ),
    ):
        result = CliRunner().invoke(
            main,
            [
                '--github-token',
                'github-token',
                '--nomad-username',
                'user',
                '--nomad-password',
                'password',
                '--nomad-url',
                'https://nomad.example/v1',
            ],
        )

    assert result.exit_code == 0
    upload.assert_called_once_with(
        nomad_upload_info=upload_info,
        plugins=plugins,
    )
    assert upload_info.upload_id == 'upload-id'
