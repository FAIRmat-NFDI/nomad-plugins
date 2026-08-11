from __future__ import annotations

import os
import sys
import tempfile
import time
from dataclasses import dataclass
from zipfile import ZIP_DEFLATED, ZipFile

import click
import requests

from .transform import snapshot_to_legacy_plugin_data


@dataclass
class NomadUploadInfo:
    nomad_url: str
    token: str
    upload_id: str | None = None


def get_authentication_token(
    *, nomad_url: str, username: str, password: str
) -> str | None:
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
    except Exception:
        return None

    return None


def get_upload_args(
    *,
    nomad_url: str | None,
    nomad_username: str,
    nomad_password: str,
    upload_id: str | None,
) -> NomadUploadInfo:
    if upload_id is None:
        from nomad.config import config

        config.load_plugins()
        try:
            entry_point = 'nomad_plugins.schema_packages:schema_package_entry_point'
            app_options = config.plugins.entry_points.options[entry_point]
            upload_id = app_options.upload_id
        except (KeyError, AttributeError):
            upload_id = None
            click.echo('No upload-id specified, uploading as new upload.')

    if nomad_url is None:
        from nomad.config import config

        if config.client.url is None:
            click.echo('NOMAD url is not provided or set in nomad.yaml, exiting.')
            sys.exit(1)
        nomad_url = f'{config.client.url}/v1'

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


def upload_snapshot_to_nomad(
    nomad_upload_info: NomadUploadInfo,
    snapshot: dict,
) -> str | None:
    """Compatibility path for existing saved public registry snapshots.

    New crawl/upload flows should pass the direct legacy archive records from the
    crawl report to `upload_legacy_plugin_data`.
    """
    return upload_legacy_plugin_data(
        nomad_upload_info,
        snapshot_to_legacy_plugin_data(snapshot),
    )


def upload_legacy_plugin_data(
    nomad_upload_info: NomadUploadInfo,
    plugins: list[dict],
) -> str | None:
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_file = os.path.join(temp_dir, 'plugins.zip')
        with ZipFile(zip_file, 'w', ZIP_DEFLATED, allowZip64=True) as zf:
            for plugin in plugins:
                plugin_data = plugin.get('data', {})
                zip_entry_name = f'{plugin_data.get("name", "plugin")}.archive.json'
                zf.writestr(zip_entry_name, encode_json(plugin))

        with open(zip_file, 'rb') as upload_file:
            try:
                if not nomad_upload_info.upload_id:
                    response = requests.post(
                        f'{nomad_upload_info.nomad_url}/uploads/',
                        headers=upload_headers(nomad_upload_info.token),
                        data=upload_file,
                        timeout=30,
                    )
                else:
                    response = requests.put(
                        f'{nomad_upload_info.nomad_url}/uploads/'
                        f'{nomad_upload_info.upload_id}/raw/',
                        headers=upload_headers(nomad_upload_info.token),
                        data=upload_file,
                        timeout=30,
                    )
                upload_id = response.json().get('upload_id')
                if upload_id:
                    return upload_id

                click.echo('response is missing upload_id: ')
                click.echo(response.json())
            except Exception:
                click.echo('something went wrong uploading to NOMAD')

    return None


def encode_json(data: dict) -> bytes:
    import json

    return json.dumps(strip_none(data), separators=(',', ':'), sort_keys=True).encode(
        'utf-8'
    )


def strip_none(value):
    if isinstance(value, dict):
        return {
            key: strip_none(item) for key, item in value.items() if item is not None
        }
    if isinstance(value, list):
        return [strip_none(item) for item in value]

    return value


def upload_headers(token: str) -> dict[str, str]:
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
    }


def wait_for_processing(
    nomad_upload_info: NomadUploadInfo,
    timeout: int = 1800,
    interval: int = 10,
) -> bool:
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
