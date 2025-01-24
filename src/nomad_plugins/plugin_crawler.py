import base64
import json
import os
import re
import tempfile
import time
from enum import Enum
from zipfile import ZIP_DEFLATED, ZipFile

import click
import requests
import toml
from nomad.config import config


class OasisURLs(Enum):
    CENTRAL = (
        'https://gitlab.mpcdf.mpg.de/nomad-lab/nomad-distro/-/raw/'
        'main/pyproject.toml'
    )
    EXAMPLE = (
        'https://gitlab.mpcdf.mpg.de/nomad-lab/nomad-distro/-/raw/'
        'test-oasis/pyproject.toml'
    )


# GitHub Code Search API URL
GITHUB_CODE_API = 'https://api.github.com/search/code'
GITHUB_REPO_API = 'https://api.github.com/repos'


def fetch_file_created(repo_name: str, file_path: str, headers: dict) -> str:
    """
    Fetches the creation date of a file in a GitHub repository by retrieving the
    commit history of the file and returning the date of the earliest commit.
    Args:
        repo_name (str): The name of the GitHub repository in the format 'owner/repo'.
        file_path (str): The path to the file within the repository.
        headers (dict): The headers to include in the request, typically containing
                        the authorization token.
    Returns:
        str: The creation date of the file in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ),
             or None if the commits could not be fetched.
    """

    commits_url = f'{GITHUB_REPO_API}/{repo_name}/commits?path={file_path}'
    commits = []
    commits_page = 1

    while True:
        commits_params = {
            'path': file_path,
            'per_page': 30,
            'page': commits_page,
        }
        commits_response = requests.get(
            commits_url, headers=headers, params=commits_params
        )
        if commits_response.ok:
            commits_page_results = commits_response.json()
            commits.extend(commits_page_results)
            if 'next' in commits_response.links:
                commits_page += 1
            else:
                break
        else:
            click.echo(
                f'Failed to fetch commits for {repo_name}: '
                f'{commits_response.status_code}, {commits_response.text}'
            )
            return None
    if commits:
        file_created = commits[-1]['commit']['committer']['date']
        return file_created
    return None


def fetch_nomad_deployment_toml(toml_url: str) -> dict:
    """
    Fetches and parses a `pyproject.toml` file from a given URL.
    Args:
        toml_url (str): The URL of the `pyproject.toml` file.
    Returns:
        dict: A dictionary containing the parsed `pyproject.toml` file if successful,
              otherwise an empty dictionary.
    """
    response = requests.get(toml_url)
    if not response.ok:
        msg = f'Failed to get pyproject.toml from {toml_url}: {response.text}'
        click.echo(msg)
    try:
        return toml.loads(response.text)
    except toml.TomlDecodeError as e:
        click.echo(f'Failed to parse pyproject.toml from {toml_url}: {e}')
        return {}


def fetch_repo_details(repo_full_name: str, headers: dict) -> dict:
    """
    Fetches the details of a GitHub repository using the GitHub API.
    Args:
        repo_full_name (str): The full name of the repository (e.g., 'owner/repo').
        headers (dict): The headers to include in the request, typically containing
                        the authorization token.
    Returns:
        dict: A dictionary containing the repository details if the request is
              successful.
              Returns None if the request fails, and prints an error message with the
              status code and response text.
    """

    repo_url = f'{GITHUB_REPO_API}/{repo_full_name}'
    response = requests.get(repo_url, headers=headers)
    if response.ok:
        return response.json()
    else:
        click.echo(
            f'Failed to fetch repository details for {repo_full_name}: '
            f'{response.status_code}, {response.text}'
        )
        return None


def get_toml_project(url: str, subdirectory: str, headers: dict) -> dict:
    """
    Fetches and parses the `pyproject.toml` file from a given GitHub repository.
    Args:
        url (str): The URL of the GitHub repository.
        subdirectory (str): The subdirectory within the repository where the
                            `pyproject.toml` file is located.
        headers (dict): The headers to include in the request, typically containing
                        authorization information.
    Returns:
        dict: A dictionary containing the 'project' section of the `pyproject.toml` file
              if successful, otherwise an empty dictionary.
    """

    repo_api_url = url.replace('https://github.com', GITHUB_REPO_API)
    request_url = f'{repo_api_url}/contents/{subdirectory}pyproject.toml'
    response = requests.get(request_url, headers=headers)
    if response.ok:
        content = response.json().get('content')
        if content:
            toml_content = base64.b64decode(content).decode('utf-8')
            try:
                return toml.loads(toml_content).get('project', {})
            except toml.TomlDecodeError as e:
                click.echo(f'Failed to parse pyproject.toml from {request_url}: {e}')
    elif response.status_code == requests.codes.forbidden:
        msg = 'Too many requests to GitHub API. Please try again later.'
        click.echo(msg)
    else:
        msg = (
            f'Failed to get pyproject.toml from {request_url}: '
            f'{response.json().get("message", "No message")}'
        )
        click.echo(msg)
    return {}


def in_distribution_toml(plugin_name: str, pyproject_data: dict) -> bool:
    """
    Checks if a given plugin name is listed in the plugin dependencies of a
    pyproject.toml file.
    Args:
        plugin_name (str): The name of the plugin to check for.
        toml_data (dict): An dictionary containing the pyproject toml data.
    Returns:
        bool: True if the plugin name is found in the optional dependencies, False
              otherwise.
    """
    name_pattern = re.compile(r'^[^;>=<\s]+')
    plugin_dependencies = pyproject_data['project']['optional-dependencies']['plugins']
    return plugin_name in [name_pattern.match(d).group() for d in plugin_dependencies]


def find_dependencies(project: dict, headers: dict) -> list[dict]:
    """
    Finds and returns a list of plugin dependencies for a given project.
    This function examines the dependencies of a given project and identifies
    those that are related to 'nomad-lab'. It supports both standard PyPI
    dependencies and dependencies specified via git URLs.
    Args:
        project (dict): A dictionary representing the project, which should
                        contain a 'dependencies' key with a list of dependency
                        strings.
        headers (dict): A dictionary of HTTP headers to use when making requests
                        to external services.
    Returns:
        list[dict]: A list of dictionaries, each representing a plugin dependency.
                    Each dictionary contains the following keys:
                    - 'm_def': A string indicating the schema definition.
                    - 'name': The name of the dependency.
                    - 'location': The URL or location of the dependency.
                    - 'toml_directory': The subdirectory within the git repository
                                        where the dependency's pyproject.toml file
                                        is located (if applicable).
    """

    name_pattern = re.compile(r'^[^;>=<\s]+')
    git_pattern = re.compile(r'@ git\+(.*?)\.git(?:@[^#]+)?(?:#subdirectory=(.*))?')
    plugin_dependencies = []
    for dependency in project.get('dependencies', []):
        name = name_pattern.match(dependency).group(0)
        git_match = git_pattern.search(dependency)
        toml_directory = ''
        if git_match:
            location = git_match.group(1)
            if git_match.group(2):
                toml_directory = git_match.group(2) + '/'
            project = get_toml_project(location, toml_directory, headers)
            if not any('nomad-lab' in d for d in project.get('dependencies', [])):
                continue
        else:
            response = requests.get(f'https://pypi.org/pypi/{name}/json')
            if not response.ok:
                continue
            response_json = response.json()
            info = response_json.get('info', {})
            dependencies = info.get('requires_dist', [])
            if not dependencies or not any('nomad-lab' in d for d in dependencies):
                continue
            location = f'https://pypi.org/project/{name}/'

        plugin_dependencies.append(
            dict(
                m_def='nomad_plugins.schema_packages.plugin.PluginReference',
                name=name,
                location=location,
                toml_directory=toml_directory,
            )
        )
    return plugin_dependencies


def get_entry_points(toml_project: dict) -> dict:
    """
    Extracts and categorizes plugin entry points from a given TOML project dictionary.
    Args:
        toml_project (dict): A dictionary representation of the project from a
        pyproject.toml file.
    Returns:
        dict: A list of dictionaries, each representing a plugin entry point with the
            following keys:
            - m_def (str): The module definition for the plugin entry point.
            - name (str): The name of the entry point.
            - module (str): The module path of the entry point.
            - type (str or None): The type of the entry point, which can be one of the
              following:
                'Schema package', 'Parser', 'Normalizer', 'App', 'Example upload',
                'API', or None if no type is matched.
    """

    entry_points = toml_project.get('entry-points', {}).get('nomad.plugin', {})
    plugin_entry_points = []
    for name, entry_point in entry_points.items():
        type = None
        if 'schema' in entry_point or 'schema' in name:
            type = 'Schema package'
        elif 'parser' in entry_point or 'parser' in name:
            type = 'Parser'
        elif 'normalizer' in entry_point or 'normalizer' in name:
            type = 'Normalizer'
        elif 'app' in entry_point or 'app' in name:
            type = 'App'
        elif 'example' in entry_point or 'example' in name:
            type = 'Example upload'
        elif 'api' in entry_point or 'api' in name:
            type = 'API'
        plugin_entry_points.append(
            dict(
                m_def='nomad_plugins.schema_packages.plugin.PluginEntryPoint',
                name=name,
                module=entry_point,
                type=type,
            )
        )
    return plugin_entry_points


def get_plugin(
    item: dict, headers: dict, central_toml: dict, example_oasis_toml: dict) -> dict:
    """
    Extracts plugin information from a given repository item and returns it as a
    dictionary.
    Args:
        item (dict): A dictionary containing repository item information, including the
                     repository details and file path.
        headers (dict): A dictionary containing HTTP headers for making requests to
                        external services.
        central_toml (dict): Central distribution pyproject toml data.
        example_oasis_toml (dict): Example oasis pyproject toml data.
    Returns:
        dict: A dictionary containing the extracted plugin information, including
              repository details, project metadata, and plugin-specific attributes.
              Returns None if required information is missing or cannot be fetched.
    """

    repo_info = item['repository']
    repo_full_name = repo_info['full_name']
    repo_details = fetch_repo_details(repo_full_name, headers)
    if repo_details is None:
        return
    toml_directory = ''
    if not item['path'].startswith('pyproject.toml'):
        toml_directory = item['path'].split('/pyproject.toml')[0] + '/'
    project = get_toml_project(repo_info['url'], toml_directory, headers)
    name = project.get('name', None)
    if name is None:
        return
    plugin = dict(
        m_def='nomad_plugins.schema_packages.plugin.Plugin',
        repository='https://github.com/' + repo_full_name,
        stars=repo_details['stargazers_count'],
        created=fetch_file_created(
            repo_full_name,
            item['path'],
            headers,
        ),
        last_updated=repo_details['pushed_at'],
        owner=repo_info['owner']['login'],
        name=name,
        description=project.get('description', None),
        authors=project.get('authors', []),
        maintainers=project.get('maintainers', []),
        plugin_dependencies=find_dependencies(project, headers),
        on_central=in_distribution_toml(name, central_toml),
        on_example_oasis=in_distribution_toml(name, example_oasis_toml),
        on_pypi=requests.get(f'https://pypi.org/pypi/{name}/json').ok,
        plugin_entry_points=get_entry_points(project),
    )
    plugin['toml_directory'] = toml_directory[:-1]
    return plugin


def find_plugins(token: str, central_toml: dict, example_oasis_toml: dict) -> dict:
    """
    Find and retrieve Nomad plugins from GitHub repositories.
    This function searches for repositories containing Nomad plugins by querying
    the GitHub Code Search API. It retrieves the plugins from repositories that
    have 'nomad.plugin' entry points defined in their `pyproject.toml` files.
    Args:
        token (str): GitHub personal access token for authentication.
        central_toml (dict): Central distribution pyproject toml data.
        example_oasis_toml (dict): Example oasis pyproject toml data.
    Returns:
        dict: A dictionary where keys are plugin names (repository full names with
              slashes replaced by underscores) and values are the plugin data.
    """

    query = "project.entry-points.'nomad.plugin' in:file filename:pyproject.toml"
    params = {
        'q': query,
        'sort': 'stars',
        'order': 'desc',
        'per_page': 30,
    }
    headers = {'Authorization': f'token {token}'}

    plugins = {}
    page = 1

    # Initial request to get the total number of items
    response = requests.get(GITHUB_CODE_API, headers=headers, params=params)
    if not response.ok:
        click.echo(f'Failed to fetch data: {response.status_code}, {response.text}')
        return plugins

    search_results = response.json()
    total_items = search_results['total_count']
    click.echo(f'Found {total_items} repositories')

    with click.progressbar(length=total_items, label='Processing repositories') as bar:
        while True:
            params['page'] = page

            response = requests.get(GITHUB_CODE_API, headers=headers, params=params)

            if not response.ok:
                click.echo(
                    f'Failed to fetch data: {response.status_code}, {response.text}'
                )
                break
            search_results = response.json()
            total_items = search_results['total_count']
            for item in search_results['items']:
                plugin_name = item['repository']['full_name'].replace('/', '_')
                plugins[plugin_name] = get_plugin(
                    item=item,
                    headers=headers,
                    central_toml=central_toml,
                    example_oasis_toml=example_oasis_toml,
                )
                bar.update(1)
            if 'next' in response.links:
                page += 1
            else:
                break
    return plugins


def get_authentication_token(nomad_url: str, username: str, password: str) -> str:
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
            nomad_url + 'auth/token',
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
        click.echo('something went wrong trying to get authentication token')
        return


def upload_to_NOMAD(
        nomad_url: str, token: str, plugins: dict, upload_id: str=None) -> str:
    """
    Uploads a file to the NOMAD server.
    Args:
        nomad_url (str): The URL of the NOMAD api, 
                         e.g. http://nomad-lab.eu/prod/v1/api/v1/.
        token (str): The authorization token for accessing the NOMAD server.
        plugins (dict): A dictionary where keys are plugin names and values are plugin
                        data
        upload_id (str): The ID of the upload if pushing to and existing upload.
    Returns:
        str: The upload ID if the upload is successful, otherwise None.
    """
    with tempfile.TemporaryDirectory(dir=config.fs.tmp) as temp_dir:
        files = []
        for name, plugin in plugins.items():
            files.append(os.path.join(temp_dir, f'{name}.archive.json'))
            with open(files[-1], 'w') as f:
                json.dump({'data': plugin}, f, indent=4)

        zip_file = os.path.join(temp_dir, 'plugins.zip')
        with ZipFile(zip_file, 'w', ZIP_DEFLATED, allowZip64=True) as zf:
            for file in files:
                zf.write(file, os.path.basename(file))

        with open(zip_file, 'rb') as f:
            try:
                if not upload_id:
                    response = requests.post(
                        nomad_url + 'uploads/',
                        headers={
                            'Authorization': f'Bearer {token}',
                            'Accept': 'application/json',
                        },
                        data=f,
                        timeout=30,
                    )
                else:
                    response = requests.put(
                        nomad_url + f'uploads/{upload_id}/raw/',
                        headers={
                            'Authorization': f'Bearer {token}',
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


def wait_for_processing(nomad_url, upload_id, token, timeout=1800, interval=10):
    """
    Waits for the processing of the upload to be completed.
    Args:
        nomad_url (str): URL of the NOMAD service.
        upload_id (str): ID of the upload.
        token (str): Authentication token.
        timeout (int): Timeout in seconds.
        interval (int): Polling interval in seconds.
    Returns:
        bool: True if processing is complete, False if timeout is reached.
    """
    headers = {'Authorization': f'Bearer {token}'}
    url = f'{nomad_url}uploads/{upload_id}'
    start_time = time.time()

    while time.time() - start_time < timeout:
        response = requests.get(url, headers=headers)
        if response.ok:
            running = response.json().get('data', {}).get('process_running')
            if not running:
                return True
        time.sleep(interval)

    return False


@click.command()
def main():
    """
    Main function to find plugins and upload them to NOMAD.
    """
    from nomad.config import _plugins  # Workaround
    try:
        entry_point = 'nomad_plugins.apps:plugin_app_entry_point'
        app_options = _plugins['entry_points']['options'][entry_point]
        github_token = app_options['github_api_token']
    except KeyError:
        click.echo('Could not find github_api_token in nomad.yaml, exiting.')
        return
    try:
        upload_id = app_options['upload_id']
    except KeyError:
        upload_id = None
        click.echo('Could not find upload_id in nomad.yaml, uploading as new upload.')
    if config.client.url is None:
        click.echo('NOMAD client url is not set in nomad.yaml, exiting.')
        return
    if config.client.user is None or config.client.password is None:
        click.echo('NOMAD client user or password is not set in nomad.yaml, exiting.')
        return
    nomad_url = f'{config.client.url}/v1/'
    token = get_authentication_token(
        nomad_url, config.client.user, config.client.password)
    if not token:
        return
    example_oasis_toml = fetch_nomad_deployment_toml(OasisURLs.EXAMPLE.value)
    central_toml = fetch_nomad_deployment_toml(OasisURLs.CENTRAL.value)

    plugins = find_plugins(
        github_token,
        central_toml=central_toml,
        example_oasis_toml=example_oasis_toml,
    )
    
    upload_id = upload_to_NOMAD(nomad_url, token, plugins, upload_id)
    click.echo(f'Uploaded to NOMAD upload: {upload_id}')
    click.echo(f'Waiting for processing of upload {upload_id} to complete...')
    if wait_for_processing(nomad_url, upload_id, token, timeout=1800):
        click.echo(f'First processing of upload {upload_id} is complete.')
        headers = {'Authorization': f'Bearer {token}'}
        url = f'{nomad_url}uploads/{upload_id}/action/process'
        response = requests.post(url, headers=headers)
        if response.ok:
            click.echo(f'Second processing of upload {upload_id} has been triggered.')
    else:
        click.echo(f'Timeout reached while waiting for upload {upload_id} to process.')


if __name__ == '__main__':
    main()
