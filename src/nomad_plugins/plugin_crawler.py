import asyncio
import math
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

import click
import httpx
import requests
import toml
from nomad.config import config
from pydantic import BaseModel, Field, HttpUrl, TypeAdapter, model_validator


def extract_dependency_name(dependency_string: str) -> str:
    """Extracts the core dependency name from a dependency string,
    removing version specifiers, comments, and git repository references.

    Args:
        dependency_string: A string representing a dependency, potentially
                        including version specifiers, comments, or git
                        repository references.

    Returns:
        The extracted dependency name, stripped of any extra information.
    """
    # Remove comments and markers (anything after # and ;)
    dependency_string = dependency_string.split('#')[0].strip().split(';')[0].strip()

    # Remove version specifiers (e.g., >=1.2.3, ==2.0) using regex
    dependency_string = re.sub(r'[<>=~!].*', '', dependency_string).strip()

    # Remove git repository references (e.g., @ git+https://...) using regex
    dependency_string = re.sub(r'\s*@\s*git\+.*', '', dependency_string).strip()

    # Remove extras markers eg. "requests; extra == 'security'"
    dependency_string = re.sub(r'\s*;\s*extra.*', '', dependency_string).strip()

    return dependency_string


class GitHubOwner(BaseModel):
    login: str
    id: int
    node_id: str
    avatar_url: HttpUrl
    gravatar_id: str
    url: HttpUrl
    html_url: HttpUrl
    followers_url: str
    following_url: str
    gists_url: str
    starred_url: str
    subscriptions_url: HttpUrl
    organizations_url: HttpUrl
    repos_url: HttpUrl
    events_url: str
    received_events_url: HttpUrl
    type: str
    site_admin: bool
    user_view_type: str | None


class GitHubRepository(BaseModel):
    id: int
    node_id: str
    name: str
    full_name: str
    private: bool
    owner: GitHubOwner
    html_url: HttpUrl
    description: str | None
    fork: bool
    url: HttpUrl
    forks_url: HttpUrl
    keys_url: str
    collaborators_url: str
    teams_url: HttpUrl
    hooks_url: HttpUrl
    issue_events_url: str
    events_url: HttpUrl
    assignees_url: str
    branches_url: str
    tags_url: HttpUrl
    blobs_url: str
    git_tags_url: str
    git_refs_url: str
    trees_url: str
    statuses_url: str
    languages_url: HttpUrl
    stargazers_url: HttpUrl
    contributors_url: HttpUrl
    subscribers_url: HttpUrl
    subscription_url: HttpUrl
    commits_url: str
    git_commits_url: str
    comments_url: str
    issue_comment_url: str
    contents_url: str
    compare_url: str
    merges_url: HttpUrl
    archive_url: str
    downloads_url: HttpUrl
    issues_url: str
    pulls_url: str
    milestones_url: str
    notifications_url: str
    labels_url: str
    releases_url: str
    deployments_url: HttpUrl


class License(BaseModel):
    key: str | None = None
    name: str | None = None
    spdx_id: str | None = None
    url: HttpUrl | None = None
    node_id: str | None = None


class GitHubRepositoryDetailed(BaseModel):
    id: int
    node_id: str
    name: str
    full_name: str
    private: bool
    owner: GitHubOwner
    html_url: HttpUrl
    description: str | None = None
    fork: bool
    url: HttpUrl
    forks_url: HttpUrl
    keys_url: str
    collaborators_url: str
    teams_url: HttpUrl
    hooks_url: HttpUrl
    issue_events_url: str
    events_url: HttpUrl
    assignees_url: str
    branches_url: str
    tags_url: HttpUrl
    blobs_url: str
    git_tags_url: str
    git_refs_url: str
    trees_url: str
    statuses_url: str
    languages_url: HttpUrl
    stargazers_url: HttpUrl
    contributors_url: HttpUrl
    subscribers_url: HttpUrl
    subscription_url: HttpUrl
    commits_url: str
    git_commits_url: str
    comments_url: str
    issue_comment_url: str
    contents_url: str
    compare_url: str
    merges_url: HttpUrl
    archive_url: str
    downloads_url: HttpUrl
    issues_url: str
    pulls_url: str
    milestones_url: str
    notifications_url: str
    labels_url: str
    releases_url: str
    deployments_url: HttpUrl
    created_at: str  # ISO 8601 date
    updated_at: str  # ISO 8601 date
    pushed_at: str  # ISO 8601 date
    git_url: str
    ssh_url: str
    clone_url: HttpUrl
    svn_url: HttpUrl
    homepage: str | None
    size: int
    stargazers_count: int
    watchers_count: int
    language: str | None
    has_issues: bool
    has_projects: bool
    has_downloads: bool
    has_wiki: bool
    has_pages: bool
    has_discussions: bool
    forks_count: int
    mirror_url: str | None
    archived: bool
    disabled: bool
    open_issues_count: int
    license: License | None
    allow_forking: bool
    is_template: bool
    web_commit_signoff_required: bool
    topics: list[str]
    visibility: str
    forks: int
    open_issues: int
    watchers: int
    default_branch: str
    permissions: dict
    template_repository: Any = None
    network_count: int
    subscribers_count: int


class GitHubSearchResultItem(BaseModel):
    name: str
    path: str
    sha: str
    url: HttpUrl
    git_url: HttpUrl
    html_url: HttpUrl
    repository: GitHubRepository
    score: float


class Author(BaseModel):
    name: str | None = None
    email: str | None = None


class LicenseInfo(BaseModel):
    file: str | None = None
    text: str | None = None


class URLs(BaseModel):
    Homepage: HttpUrl | None = Field(None, alias='homepage')
    Bug_Tracker: HttpUrl | None = Field(None, alias='bug_tracker')


class NomadPlugin(BaseModel):
    m_def: str = 'nomad_plugins.schema_packages.plugin.PluginEntryPoint'
    name: str
    module: str
    type: str | None


class EntryPoints(BaseModel):
    nomad_plugin: list[NomadPlugin] | None = None

    @model_validator(mode='before')
    @classmethod
    def plugin_type(cls, values):
        if nomad_plugins := values.pop('nomad.plugin', []):
            result = []
            for name, entry_point in nomad_plugins.items():
                plugin_type = None
                if 'schema' in entry_point or 'schema' in name:
                    plugin_type = 'Schema package'
                elif 'parser' in entry_point or 'parser' in name:
                    plugin_type = 'Parser'
                elif 'normalizer' in entry_point or 'normalizer' in name:
                    plugin_type = 'Normalizer'
                elif 'app' in entry_point or 'app' in name:
                    plugin_type = 'App'
                elif 'example' in entry_point or 'example' in name:
                    plugin_type = 'Example upload'
                elif 'api' in entry_point or 'api' in name:
                    plugin_type = 'API'
                result.append(
                    NomadPlugin(name=name, module=entry_point, type=plugin_type)
                )
            values['nomad_plugin'] = result
        return values


class PyProjectTOML(BaseModel):
    name: str
    dynamic: list[str] | None = None
    authors: list[Author] | None = None
    maintainers: list[Author] | None = None
    description: str | None = None
    readme: str | None = None
    license: LicenseInfo | None = None
    requires_python: str | None = None
    dependencies: list[str] | None = None
    urls: URLs | None = None
    optional_dependencies: dict[str, list[str]] | None = None
    all_dependencies: set[str] | None = (
        None  # this is a custom field that combines all of the deps (main and optional)
    )
    entry_points: EntryPoints | None = Field(None, alias='entry-points')

    @model_validator(mode='before')
    @classmethod
    def deps(cls, values):
        all_dependencies = [
            extract_dependency_name(dep) for dep in values.get('dependencies', [])
        ]
        for _, deps in values.get('optional-dependencies', {}).items():
            all_dependencies.extend([extract_dependency_name(dep) for dep in deps])

        values['all_dependencies'] = all_dependencies
        return values


class PluginReference(BaseModel):
    m_def: str = 'nomad_plugins.schema_packages.plugin.PluginReference'
    name: str
    location: str


class Plugin(BaseModel):
    m_def: str = 'nomad_plugins.schema_packages.plugin.Plugin'
    repository: HttpUrl
    stars: int
    created: str
    last_updated: str
    owner: str
    name: str
    description: str | None = None
    all_dependencies: set[str] = Field(
        set(), description='Placeholder field to store all dependencies', exclude=True
    )
    plugin_dependencies: list[PluginReference] = []
    authors: list[Author] = []
    maintainers: list[Author] = []
    on_central: bool
    on_example_oasis: bool
    on_pypi: bool
    plugin_entry_points: list[NomadPlugin] | None = None


class PluginData(BaseModel):
    data: Plugin


class OasisURLs(Enum):
    CENTRAL = (
        'https://gitlab.mpcdf.mpg.de/nomad-lab/nomad-distro/-/raw/main/requirements.txt'
    )

    EXAMPLE = 'https://gitlab.mpcdf.mpg.de/nomad-lab/nomad-distro/-/raw/test-oasis/requirements.txt'


# GitHub Code Search API URL
GITHUB_CODE_API = 'https://api.github.com/search/code'
GITHUB_REPO_API = 'https://api.github.com/repos'


# The following two repositories are not actual plugins
EXCLUDED_REPOS = set({'nomad-coe/nomad', 'FAIRmat-NFDI/cookiecutter-nomad-plugin'})


async def fetch_nomad_deployment_requirements(
    requirements_url: str,
) -> set[str]:
    """
    Fetches and parses a `requirements.txt` file from a given URL.
    Args:
        requirements_url (str): The URL of the `requirements.txt` file.
    Returns:
        set: set of dependencies
    """
    response = await fetch_page_async(requirements_url)
    if response:
        return set(
            [
                # the first two lines are preamble by uv
                extract_dependency_name(line)
                for line in response.text.splitlines()[2:]
            ]
        )
    return set()


async def get_toml_project(
    search_result: GitHubSearchResultItem,
) -> PyProjectTOML | None:
    """
    Fetches and parses the `pyproject.toml` file from a given GitHub repository.
    Args:
        search_result (GitHubSearchResultItem): The URL of the GitHub repository.
        subdirectory (str): The subdirectory within the repository where the
                            `pyproject.toml` file is located.
        headers (dict): The headers to include in the request, typically containing
                        authorization information.
    Returns:
        dict: A dictionary containing the 'project' section of the `pyproject.toml` file
              if successful, otherwise an empty dictionary.
    """
    repo_html_url = str(search_result.repository.html_url)
    commit_sha = str(search_result.url).split('ref=')[-1]

    if 'pyproject.toml' not in search_result.path or not commit_sha:
        return None

    # Ensure repo_html_url ends without trailing slash, we will use join to add paths.
    repo_html_url = repo_html_url.rstrip('/')

    raw_url = f'https://raw.githubusercontent.com/{search_result.repository.full_name}/{commit_sha}/{search_result.path}'

    response = await fetch_page_async(url=raw_url)
    if response:
        try:
            toml_content = toml.loads(response.text).get('project', {})
            return PyProjectTOML.model_validate(toml_content)
        except toml.TomlDecodeError as e:
            click.echo(f'Failed to parse pyproject.toml from {raw_url}: {e}')
    return None


async def package_exists_on_pypi(package_name: str) -> bool:
    """
    Checks if a package exists on PyPI using a HEAD request.

    Args:
        package_name: The name of the package to check.

    Returns:
        True if the package exists (HTTP status code 200), False otherwise
        (including network errors).
    """
    async with httpx.AsyncClient() as client:
        try:
            url = f'https://pypi.org/pypi/{package_name}/json'
            response = await client.head(url)
            return response.status_code == 200  # noqa: PLR2004
        except httpx.RequestError:
            return False


async def get_plugin(
    *,
    item: GitHubSearchResultItem,
    headers: dict,
    central_plugins: set[str],
    example_oasis_plugins: set[str],
) -> Plugin | None:
    """
    Extracts plugin information from a given repository item and returns it as a
    dictionary.
    Args:
        item (GitHubSearchResultItem): Item returned by Github Search
        headers (dict): A dictionary containing HTTP headers for making requests to
                        external services.
        central_plugins (set[str]): All plugins in central installation
        example_oasis_plugins (set[str]): All plugins in example oasis installation
    """

    repo_info = item.repository
    repo_contents_task = fetch_page_async(url=str(repo_info.url), headers=headers)
    project_task = get_toml_project(item)
    repo_contents, project = await asyncio.gather(*[repo_contents_task, project_task])
    if not repo_contents or not project:
        return None
    repo_details = GitHubRepositoryDetailed.model_validate(repo_contents.json())
    name = project.name
    on_pypi = await package_exists_on_pypi(name)
    on_central = name in central_plugins
    on_example_oasis = name in example_oasis_plugins
    plugin_entry_points = (
        project.entry_points.nomad_plugin if project.entry_points else []
    )
    authors = project.authors or []
    maintainers = project.maintainers or []
    all_dependencies = project.all_dependencies or set()
    plugin = Plugin(
        repository=repo_info.html_url,
        stars=repo_details.stargazers_count,
        created=repo_details.created_at,
        last_updated=repo_details.updated_at,
        owner=repo_info.owner.login,
        name=name,
        all_dependencies=all_dependencies,
        description=project.description,
        authors=authors,
        maintainers=maintainers,
        on_central=on_central,
        on_example_oasis=on_example_oasis,
        on_pypi=on_pypi,
        plugin_entry_points=plugin_entry_points,
    )
    return plugin


async def fetch_page_async(
    url: str, *, headers: dict | None = None, params: dict | None = None
) -> httpx.Response | None:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            # print(f'HTTP error: {e}')
            return None
        except httpx.RequestError as e:
            # print(f'Request error: {e}')
            return None
        except Exception as e:
            # print(f'Unexpected error: {e}')
            return None


async def fetch_all_results_parallel_async(
    *, url: str, headers: dict, params: dict
) -> list[GitHubSearchResultItem]:
    """
    Asynchronously fetches all pages of results from a paginated API in parallel.

    Args:
        url: The base URL of the API endpoint.
        headers: The headers to include in the request.
        params: The initial query parameters.

    Returns:
        A list of `GitHubSearchResultItem`, where each item represents the JSON response
        from a single page.
    """
    try:
        initial_response = await fetch_page_async(
            url=url, headers=headers, params=params
        )
        items = []
        if initial_response is None:
            return []
        initial_response = initial_response.json()

        items.extend(initial_response.get('items', []))
        total_count = initial_response['total_count']
        per_page = params.get('per_page', 30)
        num_pages = math.ceil(total_count / per_page)

        tasks = [
            fetch_page_async(url=url, headers=headers, params={**params, 'page': page})
            # start with second page since the initial_response contains
            # results for the first page
            for page in range(2, num_pages + 1)
        ]

        with click.progressbar(
            length=len(tasks), label='Fetching Github Search data'
        ) as bar:
            for future in asyncio.as_completed(tasks):
                res = await future
                if res:
                    items.extend(res.json().get('items', []))
                bar.update(1)

        search_result_item_adapter = TypeAdapter(list[GitHubSearchResultItem])
        validated_data = search_result_item_adapter.validate_python(items)
        return validated_data

    except Exception as e:
        print(f'Unexpected error: {e}')
        return []


async def find_plugins(
    token: str,
) -> list[PluginData]:
    """
    Find and retrieve Nomad plugins from GitHub repositories.
    This function searches for repositories containing Nomad plugins by querying
    the GitHub Code Search API. It retrieves the plugins from repositories that
    have 'nomad.plugin' entry points defined in their `pyproject.toml` files.
    Args:
        token (str): GitHub personal access token for authentication.
    """
    example_oasis_plugins = await fetch_nomad_deployment_requirements(
        OasisURLs.EXAMPLE.value
    )
    central_plugins = await fetch_nomad_deployment_requirements(OasisURLs.CENTRAL.value)

    query = 'nomad.plugin in:file filename:pyproject.toml'
    params = {
        'q': query,
        'sort': 'stars',
        'order': 'desc',
        'per_page': 30,
    }
    headers = {'Authorization': f'token {token}'}
    search_items = await fetch_all_results_parallel_async(
        url=GITHUB_CODE_API, headers=headers, params=params
    )

    tasks = [
        get_plugin(
            item=item,
            headers=headers,
            central_plugins=central_plugins,
            example_oasis_plugins=example_oasis_plugins,
        )
        for item in search_items
        if item.repository.full_name not in EXCLUDED_REPOS
    ]

    plugins: dict[str, Plugin] = {}
    with click.progressbar(
        length=len(tasks), label='Fetching individual plugin data'
    ) as bar:
        for future in asyncio.as_completed(tasks):
            plugin = await future
            if plugin:
                plugins[plugin.name] = plugin
            bar.update(1)

    data: list[PluginData] = []

    # Add nomad related dependencies to the plugin dependency list
    for plugin in plugins.values():
        nomad_related_deps = []
        for dep in plugin.all_dependencies:
            if plugin_dep := plugins.get(dep):
                location = str(
                    f'https://pypi.org/project/{dep}/'
                    if plugin_dep.on_pypi
                    else plugin_dep.repository
                )
                nomad_related_deps.append(PluginReference(name=dep, location=location))
        plugin.plugin_dependencies = nomad_related_deps
        data.append(PluginData(data=plugin))

    return data


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
        response = requests.get(
            f'{nomad_url}/auth/token',
            params=dict(username=username, password=password),
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
    with tempfile.TemporaryDirectory(dir=config.fs.tmp) as temp_dir:
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
    nomad_upload_info = get_upload_args(
        nomad_url=nomad_url,
        nomad_username=nomad_username,
        nomad_password=nomad_password,
        upload_id=upload_id,
    )
    plugins = asyncio.run(
        find_plugins(
            github_token,
        )
    )
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
        url = f'{nomad_upload_info.nomad_url}/uploads/{nomad_upload_info.upload_id}/action/process'  # noqa
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
