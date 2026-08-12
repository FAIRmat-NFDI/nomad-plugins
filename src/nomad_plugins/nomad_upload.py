import os
import sys
import tempfile
import time
from dataclasses import dataclass
from zipfile import ZIP_DEFLATED, ZipFile

import click
import requests
from nomad.config import config

from nomad_plugins.crawler import PluginData


def get_authentication_token(
    *, nomad_url: str, username: str, password: str
) -> str | None:
    """
    Retrieves an authentication token from the specified Nomad URL using the provided
    username and password.
    Args:
        nomad_url (str): The base URL of the Nomad server.
        username (str): The username for authentication.
        password (str): The password for authentication.
    Returns:
        str: The authentication token if successfully retrieved, otherwise None.
    """
    try:
        response = requests.post(
            f'{nomad_url}/auth/token',
            data=dict(username=username, password=password, grant_type='password'),
            timeout=10,
        )
        token = response.json().get('access_token')
        if token:
            return token

        click.echo('response is missing token: ')
        click.echo(response.json())
        return
    except Exception:
        return


@dataclass
class NomadUploadInfo:
    nomad_url: str
    token: str
    upload_id: str | None = None


def upload_to_NOMAD(
    nomad_upload_info: NomadUploadInfo,
    plugins: list[PluginData],
) -> str | None:
    """
    Uploads a file to the NOMAD server.
    Args:
        nomad_upload_info: A dataclass containing the NOMAD URL, token, and upload ID.
        plugins (dict): A dictionary where keys are plugin names and values are plugin
                        data
    Returns:
        str: The upload ID if the upload is successful, otherwise None.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_file = os.path.join(temp_dir, 'plugins.zip')
        with ZipFile(zip_file, 'w', ZIP_DEFLATED, allowZip64=True) as zf:
            for plugin in plugins:
                zip_entry_name = f'{plugin.data.name}.archive.json'
                zf.writestr(
                    zip_entry_name,
                    plugin.model_dump_json(exclude_none=True).encode('utf-8'),
                )

        with open(zip_file, 'rb') as f:
            try:
                if not nomad_upload_info.upload_id:
                    response = requests.post(
                        f'{nomad_upload_info.nomad_url}/uploads/',
                        headers={
                            'Authorization': f'Bearer {nomad_upload_info.token}',
                            'Accept': 'application/json',
                        },
                        data=f,
                        timeout=30,
                    )
                else:
                    response = requests.put(
                        f'{nomad_upload_info.nomad_url}/uploads/{nomad_upload_info.upload_id}/raw/',
                        headers={
                            'Authorization': f'Bearer {nomad_upload_info.token}',
                            'Accept': 'application/json',
                        },
                        data=f,
                        timeout=30,
                    )
                upload_id = response.json().get('upload_id')
                if upload_id:
                    return upload_id

                click.echo('response is missing upload_id: ')
                click.echo(response.json())
                return
            except Exception:
                click.echo('something went wrong uploading to NOMAD')
                return


def wait_for_processing(
    nomad_upload_info: NomadUploadInfo,
    timeout: int = 1800,
    interval: int = 10,
) -> bool:
    """
    Waits for the processing of the upload to be completed.
    Args:
        nomad_upload_info: A dataclass containing the NOMAD URL, token, and upload ID.
        timeout (int): Timeout in seconds.
        interval (int): Polling interval in seconds.
    Returns:
        bool: True if processing is complete, False if timeout is reached.
    """
    headers = {'Authorization': f'Bearer {nomad_upload_info.token}'}
    url = f'{nomad_upload_info.nomad_url}/uploads/{nomad_upload_info.upload_id}'
    start_time = time.time()

    while time.time() - start_time < timeout:
        response = requests.get(url, headers=headers)
        if response.ok:
            running = response.json().get('data', {}).get('process_running')
            if not running:
                return True
        time.sleep(interval)

    return False


def trigger_processing(nomad_upload_info: NomadUploadInfo) -> bool:
    headers = {'Authorization': f'Bearer {nomad_upload_info.token}'}
    url = (
        f'{nomad_upload_info.nomad_url}/uploads/'
        f'{nomad_upload_info.upload_id}/action/process'
    )
    response = requests.post(url, headers=headers)
    return response.ok


def get_upload_args(
    *,
    nomad_url: str,
    nomad_username: str,
    nomad_password: str,
    upload_id: str,
) -> NomadUploadInfo:
    """
    Get the NOMAD upload arguments from the command line or config file.
    Args:
        nomad_url (str): The NOMAD API URL.
        nomad_username (str): The NOMAD username.
        nomad_password (str): The NOMAD password.
        upload_id (str): The upload ID.
    Returns:
        NomadUploadInfo: A dataclass containing the NOMAD URL, token, and upload ID.
    """
    if upload_id is None:
        config.load_plugins()
        try:
            entry_point = 'nomad_plugins.schema_packages:schema_package_entry_point'
            app_options = config.plugins.entry_points.options[entry_point]
            upload_id = app_options.upload_id
        except (KeyError, AttributeError):
            upload_id = None
            click.echo('No upload-id specified, uploading as new upload.')
    if nomad_url is None:
        if config.client.url is None:
            click.echo('NOMAD url is not provided or set in nomad.yaml, exiting.')
            sys.exit(1)
        nomad_url = f'{config.client.url}/v1'
    # Ensure nomad_url ends without trailing slash, we will use join to add paths.
    nomad_url = nomad_url.rstrip('/')
    nomad_token = get_authentication_token(
        nomad_url=nomad_url,
        username=nomad_username,
        password=nomad_password,
    )
    if not nomad_token:
        click.echo('Failed to fetch nomad authentication token')
        sys.exit(1)
    return NomadUploadInfo(nomad_url=nomad_url, token=nomad_token, upload_id=upload_id)
