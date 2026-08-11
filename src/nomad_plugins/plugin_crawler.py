from __future__ import annotations

import json
from pathlib import Path

import click

from nomad_plugins.crawler import crawl_pyproject_registry
from nomad_plugins.github import GitHubClient
from nomad_plugins.nomad_upload import (
    get_upload_args,
    trigger_processing,
    upload_legacy_plugin_data,
    upload_snapshot_to_nomad,
    wait_for_processing,
)
from nomad_plugins.registry import (
    load_config,
    load_snapshot_data,
    validate_snapshot_data,
)


@click.command()
@click.option(
    '--github-token',
    help='Your GitHub personal access token to use when querying for plugins.',
    envvar='GITHUB_TOKEN',
    hide_input=True,
)
@click.option(
    '--input',
    'input_path',
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help='Use an existing plugin registry snapshot instead of crawling GitHub.',
)
@click.option(
    '--nomad-username',
    envvar='NOMAD_USERNAME',
    prompt='NOMAD username',
    help='NOMAD username for the owner of the plugins upload.',
)
@click.option(
    '--nomad-password',
    prompt='NOMAD password',
    envvar='NOMAD_PASSWORD',
    help='NOMAD password for the owner of the plugins upload.',
    hide_input=True,
)
@click.option(
    '--nomad-url',
    envvar='NOMAD_URL',
    default=None,
    help='The NOMAD API URL, defaults to client.url in nomad.yaml.',
)
@click.option(
    '--upload-id',
    default=None,
    envvar='UPLOAD_ID',
    help='Optional upload ID for updating an existing upload.',
)
def main(  # noqa: PLR0913, PLR0917
    github_token, input_path, nomad_url, nomad_username, nomad_password, upload_id
):
    """
    Crawl GitHub repositories for NOMAD plugins and upload them to NOMAD.

    This command keeps the historical NOMAD upload behavior, but discovery now
    goes through the shared plugin registry crawler.
    """
    nomad_upload_info = get_upload_args(
        nomad_url=nomad_url,
        nomad_username=nomad_username,
        nomad_password=nomad_password,
        upload_id=upload_id,
    )
    if input_path is None:
        if github_token is None:
            github_token = click.prompt(
                'GitHub personal access token',
                hide_input=True,
            )
        legacy_plugin_data = crawl_pyproject_registry(
            load_config(),
            client=GitHubClient(token=github_token),
        ).legacy_plugin_data
        uploaded_id = upload_legacy_plugin_data(
            nomad_upload_info=nomad_upload_info,
            plugins=legacy_plugin_data,
        )
    else:
        input_data = load_json(input_path)
        if is_legacy_plugin_data(input_data):
            uploaded_id = upload_legacy_plugin_data(
                nomad_upload_info=nomad_upload_info,
                plugins=input_data,
            )
        else:
            snapshot = load_snapshot_data(input_path)
            validate_snapshot_data(snapshot)
            uploaded_id = upload_snapshot_to_nomad(
                nomad_upload_info=nomad_upload_info,
                snapshot=snapshot,
            )
    nomad_upload_info.upload_id = uploaded_id
    click.echo(f'Uploaded to NOMAD upload: {nomad_upload_info.upload_id}')
    click.echo(
        f'Waiting for processing of upload {nomad_upload_info.upload_id} to complete...'
    )
    if wait_for_processing(nomad_upload_info, timeout=1800):
        click.echo(
            f'First processing of upload {nomad_upload_info.upload_id} is complete.'
        )
        if trigger_processing(nomad_upload_info):
            click.echo(
                f'Second processing of upload {nomad_upload_info.upload_id} '
                'has been triggered.'
            )
    else:
        click.echo(
            'Timeout reached while waiting for upload '
            f'{nomad_upload_info.upload_id} to process.'
        )


def load_json(path: Path):
    with path.open(encoding='utf-8') as input_file:
        return json.load(input_file)


def is_legacy_plugin_data(value) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, dict) and isinstance(item.get('data'), dict) for item in value
    )


if __name__ == '__main__':
    main()
