import asyncio

import click

from nomad_plugins.crawler import *  # noqa: F403
from nomad_plugins.nomad_upload import *  # noqa: F403


@click.command()
@click.option(
    '--github-token',
    prompt='GitHub personal access token',
    help='Your GitHub personal access token to use when querying for plugins.',
    envvar='GITHUB_TOKEN',
    hide_input=True,
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
def main(github_token, nomad_url, nomad_username, nomad_password, upload_id):
    """
    Crawl GitHub repositories for NOMAD plugins and upload them to the NOMAD server.

    The nomad-url can be provided as an argument or in the nomad.yaml config file as:

    client:

        url: <nomad-url>

    The upload-id can be provided as an argument or in the nomad.yaml config file as:

    plugins:

        entry_points:

            options:

                nomad_plugins.apps:plugin_app_entry_point:

                    upload_id: <upload-id>

    """
    nomad_upload_info = get_upload_args(  # noqa: F405
        nomad_url=nomad_url,
        nomad_username=nomad_username,
        nomad_password=nomad_password,
        upload_id=upload_id,
    )
    plugins = asyncio.run(find_plugins(github_token))  # noqa: F405
    upload_id = upload_to_NOMAD(  # noqa: F405
        nomad_upload_info=nomad_upload_info,
        plugins=plugins,
    )
    nomad_upload_info.upload_id = upload_id
    click.echo(f'Uploaded to NOMAD upload: {nomad_upload_info.upload_id}')
    click.echo(
        f'Waiting for processing of upload {nomad_upload_info.upload_id} to complete...'
    )
    if wait_for_processing(nomad_upload_info, timeout=1800):  # noqa: F405
        click.echo(
            f'First processing of upload {nomad_upload_info.upload_id} is complete.'
        )
        if trigger_processing(nomad_upload_info):  # noqa: F405
            click.echo(
                f'Second processing of upload {nomad_upload_info.upload_id} '
                'has been triggered.'
            )
    else:
        click.echo(
            'Timeout reached while waiting for upload '
            f'{nomad_upload_info.upload_id} to process.'
        )


if __name__ == '__main__':
    main()
