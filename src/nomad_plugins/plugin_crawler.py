import asyncio
import json
import os
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

import click
import httpx
import requests
import yaml
from dotenv import load_dotenv
from nomad.config import config

# Load .env file if it exists
env_path = Path('.env')
if env_path.exists():
    load_dotenv(env_path)

GITHUB_CODE_API = 'https://api.github.com/search/code'
EXCLUDED_REPOS = {
    'nomad-coe/nomad',
    'FAIRmat-NFDI/cookiecutter-nomad-plugin',
    'FAIRmat-NFDI/pynxtools-plugin-template',
}
METADATA_FILENAMES = ('nomad_plugin_metadata.yaml', 'nomad_plugin_metadata.yml')
CANONICAL_MDEF = 'nomad_plugins_metadata.schema_packages.schema_package.PluginMetadata'


@dataclass(frozen=True)
class CandidateRepo:
    full_name: str
    html_url: str
    path: str
    ref: str


@dataclass
class PluginData:
    data: dict[str, Any]


@dataclass
class NomadUploadInfo:
    nomad_url: str
    token: str
    upload_id: str | None = None


def normalize_package_name(package_name: str) -> str:
    return package_name.lower().replace('_', '-').strip()


def _candidate_from_search_item(item: dict) -> CandidateRepo | None:
    repository = item.get('repository', {}) if isinstance(item, dict) else {}
    full_name = str(repository.get('full_name', '')).strip()
    html_url = str(repository.get('html_url', '')).strip()
    path = str(item.get('path', '')).strip()
    search_url = str(item.get('url', '')).strip()
    ref = search_url.split('ref=', maxsplit=1)[-1] if 'ref=' in search_url else ''
    if not full_name or not html_url or not path or not ref:
        return None
    return CandidateRepo(full_name=full_name, html_url=html_url, path=path, ref=ref)


def _plugin_root_from_path(pyproject_path: str) -> str:
    path = Path(pyproject_path)
    parent = str(path.parent)
    return '' if parent == '.' else parent


def _metadata_probe_paths(plugin_root: str) -> list[str]:
    paths: list[str] = []
    for name in METADATA_FILENAMES:
        if plugin_root:
            paths.append(f'{plugin_root}/{name}')
        paths.append(name)
    # preserve order but deduplicate
    seen = set()
    deduped = []
    for item in paths:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


async def fetch_page_async(
    url: str, *, headers: dict | None = None, params: dict | None = None
) -> httpx.Response | None:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response
        except Exception:
            return None


async def _fetch_text(url: str, headers: dict) -> str | None:
    response = await fetch_page_async(url=url, headers=headers)
    if response is None:
        return None
    return response.text


async def _load_repository_metadata_file(
    candidate: CandidateRepo,
    *,
    headers: dict,
    plugin_root: str,
) -> dict | None:
    for relative_path in _metadata_probe_paths(plugin_root):
        raw_url = (
            f'https://raw.githubusercontent.com/{candidate.full_name}/'
            f'{candidate.ref}/{relative_path}'
        )
        content = await _fetch_text(raw_url, headers)
        if content is None:
            continue
        try:
            payload = yaml.safe_load(content)
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload
    return None


async def _download_tarball(
    candidate: CandidateRepo, *, headers: dict, destination: Path
) -> Path | None:
    tarball_url = (
        f'https://api.github.com/repos/{candidate.full_name}/tarball/{candidate.ref}'
    )
    response = await fetch_page_async(url=tarball_url, headers=headers)
    if response is None:
        return None
    tar_path = destination / 'repo.tar.gz'
    tar_path.write_bytes(response.content)
    return tar_path


def _first_directory(path: Path) -> Path | None:
    directories = [entry for entry in path.iterdir() if entry.is_dir()]
    if len(directories) == 1:
        return directories[0]
    return None


def _fallback_extract_metadata(
    candidate: CandidateRepo,
    *,
    tarball_path: Path,
    plugin_root: str,
) -> dict | None:
    extract_dir = tarball_path.parent / 'repo_extract'
    extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(tarball_path, mode='r:gz') as archive:
            archive.extractall(path=extract_dir)
    except Exception:
        return None

    repo_root = _first_directory(extract_dir)
    if repo_root is None:
        return None

    source_path = repo_root / plugin_root if plugin_root else repo_root
    if not source_path.exists() or not source_path.is_dir():
        return None

    try:
        from nomad_plugins_metadata.extractor.extract import (
            build_generated_metadata_with_release_context,
        )

        return build_generated_metadata_with_release_context(
            repo_path=source_path,
            release_tag=None,
            release_sha=candidate.ref,
            plugins_index_path=None,
        )
    except Exception:
        return None


def _finalize_metadata(candidate: CandidateRepo, metadata: dict) -> dict:
    payload = dict(metadata)
    repo_name = candidate.full_name.rsplit('/', maxsplit=1)[-1]

    if not payload.get('id'):
        payload['id'] = payload.get('name') or repo_name
    if not payload.get('name'):
        payload['name'] = payload.get('id') or repo_name
    if not payload.get('upstream_repository'):
        payload['upstream_repository'] = candidate.html_url
    if not payload.get('metadata_schema_version'):
        payload['metadata_schema_version'] = '1.0.0'

    payload['m_def'] = CANONICAL_MDEF
    return payload


async def _process_candidate(
    candidate: CandidateRepo, headers: dict
) -> PluginData | None:
    plugin_root = _plugin_root_from_path(candidate.path)

    metadata = await _load_repository_metadata_file(
        candidate,
        headers=headers,
        plugin_root=plugin_root,
    )

    if metadata is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            tarball_path = await _download_tarball(
                candidate,
                headers=headers,
                destination=Path(temp_dir),
            )
            if tarball_path is None:
                click.echo(
                    f'Skipping {candidate.full_name}: failed to download tarball'
                )
                return None
            metadata = _fallback_extract_metadata(
                candidate,
                tarball_path=tarball_path,
                plugin_root=plugin_root,
            )
            if metadata is None:
                click.echo(
                    f'Skipping {candidate.full_name}: metadata file missing/invalid '
                    'and extractor fallback failed'
                )
                return None

    return PluginData(data=_finalize_metadata(candidate, metadata))


async def fetch_all_results_parallel_async(
    *, url: str, headers: dict, params: dict
) -> list[dict]:
    initial_response = await fetch_page_async(url=url, headers=headers, params=params)
    if initial_response is None:
        return []

    payload = initial_response.json()
    items = list(payload.get('items', []))
    total_count = int(payload.get('total_count', 0))
    per_page = int(params.get('per_page', 30))
    if per_page <= 0:
        per_page = 30

    num_pages = max(1, (total_count + per_page - 1) // per_page)
    tasks = [
        fetch_page_async(url=url, headers=headers, params={**params, 'page': page})
        for page in range(2, num_pages + 1)
    ]

    with click.progressbar(
        length=len(tasks), label='Fetching Github Search data'
    ) as bar:
        for future in asyncio.as_completed(tasks):
            response = await future
            if response is not None:
                items.extend(response.json().get('items', []))
            bar.update(1)

    return items


async def find_plugins(token: str) -> list[PluginData]:
    query = 'nomad.plugin in:file filename:pyproject.toml'
    params = {
        'q': query,
        'sort': 'stars',
        'order': 'desc',
        'per_page': 30,
    }
    headers = {'Authorization': f'token {token}'}
    search_items = await fetch_all_results_parallel_async(
        url=GITHUB_CODE_API,
        headers=headers,
        params=params,
    )

    candidates: list[CandidateRepo] = []
    for item in search_items:
        candidate = _candidate_from_search_item(item)
        if candidate is None:
            continue
        if candidate.full_name in EXCLUDED_REPOS:
            continue
        candidates.append(candidate)

    tasks = [_process_candidate(candidate, headers) for candidate in candidates]
    plugins: list[PluginData] = []
    with click.progressbar(
        length=len(tasks), label='Collecting plugin metadata'
    ) as bar:
        for future in asyncio.as_completed(tasks):
            plugin = await future
            if plugin is not None:
                plugins.append(plugin)
            bar.update(1)

    return plugins


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
        return None
    except Exception:
        return None


def upload_to_NOMAD(
    nomad_upload_info: NomadUploadInfo,
    plugins: list[PluginData],
) -> str | None:
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_file = os.path.join(temp_dir, 'plugins.zip')
        with ZipFile(zip_file, 'w', ZIP_DEFLATED, allowZip64=True) as zf:
            for plugin in plugins:
                plugin_name = str(
                    plugin.data.get('name') or plugin.data.get('id') or 'plugin'
                )
                zip_entry_name = f'{normalize_package_name(plugin_name)}.archive.json'
                zf.writestr(
                    zip_entry_name,
                    json.dumps({'data': plugin.data}, ensure_ascii=False).encode(
                        'utf-8'
                    ),
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
                return None
            except Exception:
                click.echo('something went wrong uploading to NOMAD')
                return None


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


def get_upload_args(
    *,
    nomad_url: str,
    nomad_username: str,
    nomad_password: str,
    upload_id: str,
) -> NomadUploadInfo:
    if upload_id is None:
        config.load_plugins()
        try:
            entry_point = (
                'nomad_plugins_metadata.schema_packages:schema_package_entry_point'
            )
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
    """
    nomad_upload_info = get_upload_args(
        nomad_url=nomad_url,
        nomad_username=nomad_username,
        nomad_password=nomad_password,
        upload_id=upload_id,
    )
    plugins = asyncio.run(find_plugins(github_token))
    upload_id = upload_to_NOMAD(
        nomad_upload_info=nomad_upload_info,
        plugins=plugins,
    )
    nomad_upload_info.upload_id = upload_id
    click.echo(f'Uploaded to NOMAD upload: {nomad_upload_info.upload_id}')
    click.echo(
        f'Waiting for processing of upload {nomad_upload_info.upload_id} to complete...'
    )
    if wait_for_processing(nomad_upload_info, timeout=1800):
        click.echo(
            f'First processing of upload {nomad_upload_info.upload_id} is complete.'
        )
        headers = {'Authorization': f'Bearer {nomad_upload_info.token}'}
        url = (
            f'{nomad_upload_info.nomad_url}/uploads/'
            f'{nomad_upload_info.upload_id}/action/process'
        )
        response = requests.post(url, headers=headers)
        if response.ok:
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
