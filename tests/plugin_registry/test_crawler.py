from __future__ import annotations

import unittest

from nomad_plugins.crawler import (
    candidate_exclusions,
    crawl_pyproject_registry,
    discover_pyproject_candidates,
    discover_repository_pyproject_candidates,
    documentation_url_exclusions,
    exclude_forks,
    fairmat_owners,
    fetch_official_software_plugins,
    fetch_official_template_plugins,
    has_nomad_ecosystem_signal,
    max_repository_candidates,
    merge_pyproject_candidates,
    normalize_candidate_exclusion,
    normalize_repository_full_name,
    official_software_repositories,
    official_template_repositories,
    parse_pyproject_candidates,
    pypi_url_exclusions,
    pyproject_search_queries,
    repository_search_queries,
    root_pyproject_candidate,
    search_request_delay_seconds,
)
from nomad_plugins.github import (
    GitHubCandidateFile,
    GitHubRepositoryCandidate,
    GitHubRepositorySearchPage,
    GitHubRepositoryStatus,
    GitHubSearchPage,
)
from nomad_plugins.registry import load_config, validate_snapshot_data


class CrawlerTests(unittest.TestCase):
    def test_filters_configured_pyproject_queries(self) -> None:
        self.assertEqual(
            pyproject_search_queries(
                {
                    'github': {
                        'searchQueries': [
                            'nomad.plugin filename:pyproject.toml',
                            'nomad_plugin_metadata filename:nomad_plugin_metadata.yaml',
                        ],
                    },
                },
            ),
            ['nomad.plugin filename:pyproject.toml'],
        )

    def test_requires_configured_pyproject_query(self) -> None:
        with self.assertRaisesRegex(ValueError, 'pyproject.toml query'):
            pyproject_search_queries({'github': {'searchQueries': []}})

    def test_reads_repository_search_queries(self) -> None:
        self.assertEqual(
            repository_search_queries(
                {
                    'github': {
                        'repositorySearchQueries': [
                            'nomad plugin in:name,description,readme',
                        ],
                    },
                },
            ),
            ['nomad plugin in:name,description,readme'],
        )

    def test_default_config_discovers_north_tool_topic(self) -> None:
        self.assertIn('topic:north-tool', repository_search_queries(load_config()))

    def test_default_config_discovers_semantic_plugin_family(self) -> None:
        self.assertIn(
            'nomad-semantic in:name,description',
            repository_search_queries(load_config()),
        )

    def test_default_config_searches_known_plugin_organizations(self) -> None:
        queries = repository_search_queries(load_config())
        org_queries = [query for query in queries if query.startswith('org:')]

        self.assertEqual(len(org_queries), 23)
        self.assertIn(
            'org:FAIRmat-NFDI nomad in:name,description',
            queries,
        )
        self.assertIn(
            'org:ZBT-Tools nomad in:name,description',
            queries,
        )

    def test_rejects_invalid_repository_search_queries(self) -> None:
        with self.assertRaisesRegex(ValueError, 'repositorySearchQueries'):
            repository_search_queries(
                {'github': {'repositorySearchQueries': ['valid', '']}}
            )

    def test_configures_repository_candidate_cap(self) -> None:
        self.assertIsNone(max_repository_candidates({'github': {}}))
        self.assertEqual(
            max_repository_candidates({'github': {'maxRepositoryCandidates': 25}}),
            25,
        )

        with self.assertRaisesRegex(ValueError, 'maxRepositoryCandidates'):
            max_repository_candidates({'github': {'maxRepositoryCandidates': 0}})

    def test_configures_search_request_delay(self) -> None:
        self.assertEqual(search_request_delay_seconds({'github': {}}), 0)
        self.assertEqual(
            search_request_delay_seconds(
                {'github': {'searchRequestDelaySeconds': 1.5}},
            ),
            1.5,
        )

        with self.assertRaisesRegex(ValueError, 'searchRequestDelaySeconds'):
            search_request_delay_seconds(
                {'github': {'searchRequestDelaySeconds': -1}},
            )

    def test_reads_official_template_repositories(self) -> None:
        repositories = official_template_repositories(
            {
                'github': {
                    'officialTemplateRepositories': [
                        {
                            'repository': 'FAIRmat-NFDI/nomad-plugin-template',
                            'name': 'nomad-plugin-template',
                            'description': 'A template repository.',
                        },
                    ],
                },
            },
        )

        self.assertEqual(len(repositories), 1)
        self.assertEqual(
            repositories[0].repository, 'FAIRmat-NFDI/nomad-plugin-template'
        )
        self.assertEqual(repositories[0].name, 'nomad-plugin-template')

    def test_reads_official_software_repositories(self) -> None:
        repositories = official_software_repositories(
            {
                'github': {
                    'officialSoftwareRepositories': [
                        {
                            'repository': 'FAIRmat-NFDI/nomad-docs',
                            'name': 'nomad-docs',
                            'description': 'Official documentation.',
                        },
                    ],
                },
            },
        )

        self.assertEqual(len(repositories), 1)
        self.assertEqual(repositories[0].repository, 'FAIRmat-NFDI/nomad-docs')
        self.assertEqual(repositories[0].name, 'nomad-docs')

    def test_reads_documentation_url_exclusions(self) -> None:
        self.assertEqual(
            documentation_url_exclusions(
                {
                    'github': {
                        'excludeDocumentationUrls': [
                            'https://example.github.io/missing-docs/',
                        ],
                    },
                },
            ),
            {'https://example.github.io/missing-docs'},
        )

    def test_reads_pypi_url_exclusions(self) -> None:
        self.assertEqual(
            pypi_url_exclusions(
                {
                    'github': {
                        'excludePypiUrls': [
                            'https://pypi.org/project/missing-package/',
                        ],
                    },
                },
            ),
            {'https://pypi.org/project/missing-package'},
        )

    def test_rejects_invalid_official_template_repositories(self) -> None:
        with self.assertRaisesRegex(ValueError, 'officialTemplateRepositories'):
            official_template_repositories(
                {'github': {'officialTemplateRepositories': ['bad']}}
            )

    def test_normalizes_repository_full_name(self) -> None:
        self.assertEqual(
            normalize_repository_full_name(
                'https://github.com/FAIRmat-NFDI/nomad-plugin-template.git',
            ),
            'fairmat-nfdi/nomad-plugin-template',
        )
        self.assertEqual(
            normalize_repository_full_name('FAIRmat-NFDI/nomad-plugin-template'),
            'fairmat-nfdi/nomad-plugin-template',
        )

    def test_discovers_paginated_pyproject_candidates_once(self) -> None:
        first_candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        duplicate_candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        nested_candidate = candidate_file(
            repository='example/beta',
            file_path='packages/beta/pyproject.toml',
        )
        ignored_candidate = candidate_file(
            repository='example/gamma',
            file_path='nomad_plugin_metadata.yaml',
        )
        client = FakeGitHubClient(
            search_pages={
                ('query', 1): search_page(
                    [first_candidate, duplicate_candidate, ignored_candidate],
                    next_url='https://api.github.com/search/code?page=2',
                ),
                ('query', 2): search_page([nested_candidate]),
            },
        )

        candidates = discover_pyproject_candidates(client, ['query'])

        self.assertEqual(candidates, [first_candidate, nested_candidate])
        self.assertEqual(client.search_calls, [('query', 1, 100), ('query', 2, 100)])

    def test_excludes_configured_candidates_before_fetching(self) -> None:
        kept_candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        excluded_candidate = candidate_file(
            repository='example/beta',
            file_path='packages/beta/pyproject.toml',
        )
        client = FakeGitHubClient(
            search_pages={
                ('query', 1): search_page([kept_candidate, excluded_candidate]),
            },
        )

        candidates = discover_pyproject_candidates(
            client,
            ['query'],
            excluded_candidates={'github.com/example/beta#packages/beta'},
        )

        self.assertEqual(candidates, [kept_candidate])

    def test_discovers_root_pyprojects_from_repository_search(self) -> None:
        root_repository = repository_candidate(
            repository='glaidedata/nomad-measurements-afm',
            fork=False,
        )
        fork_repository = repository_candidate(repository='example/fork', fork=True)
        archived_repository = repository_candidate(
            repository='example/archived',
            archived=True,
        )
        client = FakeGitHubClient(
            repository_search_pages={
                ('repo-query', 1): repository_search_page(
                    [root_repository, fork_repository, archived_repository],
                ),
            },
        )

        candidates = discover_repository_pyproject_candidates(
            client,
            ['repo-query'],
            exclude_forks=True,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            candidates[0].repository_full_name, 'glaidedata/nomad-measurements-afm'
        )
        self.assertEqual(candidates[0].file_path, 'pyproject.toml')
        self.assertEqual(
            candidates[0].raw_url,
            'https://raw.githubusercontent.com/glaidedata/nomad-measurements-afm/main/pyproject.toml',
        )
        self.assertEqual(client.repository_search_calls, [('repo-query', 1, 100)])

    def test_caps_repository_pyproject_discovery(self) -> None:
        client = FakeGitHubClient(
            repository_search_pages={
                ('repo-query', 1): repository_search_page(
                    [
                        repository_candidate(repository='example/first'),
                        repository_candidate(repository='example/second'),
                        repository_candidate(repository='example/third'),
                    ],
                ),
            },
        )

        candidates = discover_repository_pyproject_candidates(
            client,
            ['repo-query'],
            exclude_forks=True,
            max_candidates=2,
        )

        self.assertEqual(
            [candidate.repository_full_name for candidate in candidates],
            ['example/first', 'example/second'],
        )

    def test_caps_repository_pyproject_discovery_per_query(self) -> None:
        client = FakeGitHubClient(
            repository_search_pages={
                ('broad-query', 1): repository_search_page(
                    [
                        repository_candidate(repository='example/broad-first'),
                        repository_candidate(repository='example/broad-second'),
                    ],
                ),
                ('targeted-query', 1): repository_search_page(
                    [
                        repository_candidate(repository='glaidedata/targeted-first'),
                        repository_candidate(repository='glaidedata/targeted-second'),
                    ],
                ),
            },
        )

        candidates = discover_repository_pyproject_candidates(
            client,
            ['broad-query', 'targeted-query'],
            exclude_forks=True,
            max_candidates=1,
        )

        self.assertEqual(
            [candidate.repository_full_name for candidate in candidates],
            ['example/broad-first', 'glaidedata/targeted-first'],
        )
        self.assertEqual(
            client.repository_search_calls,
            [('broad-query', 1, 100), ('targeted-query', 1, 100)],
        )

    def test_merges_repository_pyproject_candidates(self) -> None:
        discovered_candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        repository_candidate_file = root_pyproject_candidate(
            repository_candidate(repository='glaidedata/example-plugin'),
        )

        candidates = merge_pyproject_candidates(
            [discovered_candidate],
            [repository_candidate_file],
        )

        self.assertEqual(
            [candidate.repository_full_name for candidate in candidates],
            ['example/alpha', 'glaidedata/example-plugin'],
        )

    def test_excludes_configured_repository_candidates(self) -> None:
        repository_candidate_file = root_pyproject_candidate(
            repository_candidate(repository='glaidedata/example-plugin'),
        )

        candidates = merge_pyproject_candidates(
            [],
            [repository_candidate_file],
            excluded_candidates={'github.com/glaidedata/example-plugin'},
        )

        self.assertEqual(candidates, [])

    def test_normalizes_candidate_exclusions(self) -> None:
        self.assertEqual(
            normalize_candidate_exclusion(
                'GitHub.com/Example/Beta.git#./packages/beta/'
            ),
            'github.com/example/beta#packages/beta',
        )
        self.assertEqual(
            candidate_exclusions(
                {
                    'github': {
                        'excludeCandidates': [
                            'github.com/example/alpha',
                            'https://github.com/example/beta#packages/beta',
                        ],
                    },
                },
            ),
            {
                'github.com/example/alpha',
                'github.com/example/beta#packages/beta',
            },
        )

    def test_rejects_invalid_candidate_exclusions(self) -> None:
        with self.assertRaisesRegex(ValueError, 'excludeCandidates'):
            candidate_exclusions({'github': {'excludeCandidates': ['valid', 5]}})

    def test_configures_fork_exclusion(self) -> None:
        self.assertFalse(exclude_forks({'github': {}}))
        self.assertTrue(exclude_forks({'github': {'excludeForks': True}}))

        with self.assertRaisesRegex(ValueError, 'excludeForks'):
            exclude_forks({'github': {'excludeForks': 'true'}})

    def test_parses_candidates_and_reports_skips(self) -> None:
        valid_candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        invalid_candidate = candidate_file(
            repository='example/beta',
            file_path='pyproject.toml',
        )
        missing_raw_candidate = candidate_file(
            repository='example/gamma',
            file_path='pyproject.toml',
            raw_url=None,
        )
        duplicate_candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        no_entrypoint_candidate = candidate_file(
            repository='example/delta',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                valid_candidate.raw_url: pyproject_text(
                    'Alpha Plugin',
                    repository='example/alpha',
                ),
                invalid_candidate.raw_url: '[project',
                missing_raw_candidate.api_url: pyproject_text(
                    'Gamma Plugin',
                    repository='example/gamma',
                ),
                duplicate_candidate.raw_url: pyproject_text(
                    'Alpha Plugin',
                    repository='example/alpha',
                ),
                no_entrypoint_candidate.raw_url: """
[project]
name = "Delta Package"
description = "Not a plugin."
""",
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [
                valid_candidate,
                invalid_candidate,
                missing_raw_candidate,
                duplicate_candidate,
                no_entrypoint_candidate,
            ],
        )

        self.assertEqual(len(plugins), 3)
        self.assertEqual(fetched_count, 5)
        self.assertEqual(
            plugins[0].discovery_warnings,
            ['Duplicate pyproject candidate skipped: pyproject.toml'],
        )
        plugins_by_name = {plugin.name: plugin for plugin in plugins}
        self.assertEqual(plugins_by_name['Gamma Plugin'].plugin_types, ['parser'])
        self.assertEqual(plugins_by_name['Gamma Plugin'].owner_group, 'community')
        self.assertEqual(plugins_by_name['Delta Package'].plugin_types, [])
        self.assertEqual(
            plugins_by_name['Delta Package'].project_kind, 'ecosystem_package'
        )
        self.assertFalse(plugins_by_name['Delta Package'].registry_visible)
        self.assertEqual(
            plugins_by_name['Delta Package'].discovery_warnings,
            ['No nomad.plugin entry points found in pyproject.toml.'],
        )
        self.assertEqual(len(skipped), 1)
        self.assertIn('example/beta:pyproject.toml: Unable to parse', skipped[0])
        self.assertEqual(
            client.repository_status_calls,
            ['example/alpha', 'example/gamma', 'example/delta'],
        )

    def test_skips_fork_candidates_when_configured(self) -> None:
        fork_candidate = candidate_file(
            repository='example/fork',
            file_path='pyproject.toml',
        )
        non_fork_candidate = candidate_file(
            repository='example/non-fork',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                fork_candidate.raw_url: pyproject_text(
                    'Fork Plugin',
                    repository='example/fork',
                ),
                non_fork_candidate.raw_url: pyproject_text(
                    'Non Fork Plugin',
                    repository='example/non-fork',
                ),
            },
            repository_statuses={
                'example/fork': repository_status('example/fork', fork=True),
                'example/non-fork': repository_status('example/non-fork', fork=False),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [fork_candidate, non_fork_candidate],
            exclude_forks=True,
        )

        self.assertEqual(fetched_count, 2)
        self.assertEqual([plugin.name for plugin in plugins], ['Non Fork Plugin'])
        self.assertEqual(
            skipped, ['example/fork:pyproject.toml: skipped fork repository']
        )

    def test_keeps_archived_candidates_hidden_from_registry(self) -> None:
        archived_candidate = candidate_file(
            repository='example/archived-plugin',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                archived_candidate.raw_url: pyproject_text(
                    'Archived Plugin',
                    repository='example/archived-plugin',
                ),
            },
            repository_statuses={
                'example/archived-plugin': repository_status(
                    'example/archived-plugin',
                    archived=True,
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [archived_candidate],
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].name, 'Archived Plugin')
        self.assertTrue(plugins[0].status.archived)
        self.assertFalse(plugins[0].registry_visible)

    def test_repository_search_candidates_require_nomad_ecosystem_signal(self) -> None:
        ignored_candidate = root_pyproject_candidate(
            repository_candidate(repository='hashicorp/nomad-driver-example'),
        )
        kept_candidate = root_pyproject_candidate(
            repository_candidate(repository='glaidedata/nomad-measurements-afm'),
        )
        client = FakeGitHubClient(
            fetch_texts={
                ignored_candidate.raw_url: """
[project]
name = "nomad-driver-example"
description = "A HashiCorp Nomad driver example."
""",
                kept_candidate.raw_url: pyproject_text(
                    'Glaide AFM Plugin',
                    repository='glaidedata/nomad-measurements-afm',
                ),
            },
            repository_statuses={
                'glaidedata/nomad-measurements-afm': repository_status(
                    'glaidedata/nomad-measurements-afm',
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [ignored_candidate, kept_candidate],
        )

        self.assertEqual([plugin.name for plugin in plugins], ['Glaide AFM Plugin'])
        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)

    def test_repository_search_missing_root_pyproject_is_silent(self) -> None:
        missing_candidate = root_pyproject_candidate(
            repository_candidate(repository='hashicorp/nomad-driver-example'),
        )
        client = FakeGitHubClient(
            fetch_errors={missing_candidate.raw_url: RuntimeError('HTTP 404')}
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [missing_candidate],
        )

        self.assertEqual(plugins, [])
        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 0)

    def test_detects_nomad_ecosystem_pyproject_signals(self) -> None:
        self.assertTrue(
            has_nomad_ecosystem_signal('[project.entry-points."nomad.plugin"]')
        )
        self.assertTrue(has_nomad_ecosystem_signal('dependencies = ["nomad-lab"]'))
        self.assertFalse(
            has_nomad_ecosystem_signal('description = "HashiCorp Nomad plugin"')
        )

    def test_fetches_configured_official_template_plugins(self) -> None:
        repositories = official_template_repositories(
            {
                'github': {
                    'officialTemplateRepositories': [
                        {
                            'repository': 'https://github.com/FAIRmat-NFDI/nomad-plugin-template',
                            'name': 'nomad-plugin-template',
                            'description': 'A template repository.',
                        },
                    ],
                },
            },
        )
        client = FakeGitHubClient(
            repository_statuses={
                'fairmat-nfdi/nomad-plugin-template': repository_status(
                    'fairmat-nfdi/nomad-plugin-template',
                    fork=False,
                ),
            },
        )

        plugins, skipped = fetch_official_template_plugins(
            client,
            repositories,
            exclude_forks=True,
            fairmat_owner_names={'fairmat-nfdi'},
        )

        self.assertEqual(skipped, [])
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].name, 'nomad-plugin-template')
        self.assertEqual(plugins[0].project_kind, 'official_template')
        self.assertEqual(plugins[0].metadata_source, 'crawler-config')
        self.assertTrue(plugins[0].registry_visible)
        self.assertEqual(plugins[0].owner_group, 'fairmat')

    def test_fetches_configured_official_software_plugins(self) -> None:
        repositories = official_software_repositories(
            {
                'github': {
                    'officialSoftwareRepositories': [
                        {
                            'repository': 'FAIRmat-NFDI/nomad-docs',
                            'name': 'nomad-docs',
                            'description': 'Official documentation.',
                        },
                    ],
                },
            },
        )
        client = FakeGitHubClient(
            repository_statuses={
                'fairmat-nfdi/nomad-docs': repository_status(
                    'fairmat-nfdi/nomad-docs',
                    fork=False,
                ),
            },
        )

        plugins, skipped = fetch_official_software_plugins(
            client,
            repositories,
            exclude_forks=True,
            fairmat_owner_names={'fairmat-nfdi'},
        )

        self.assertEqual(skipped, [])
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].name, 'nomad-docs')
        self.assertEqual(plugins[0].project_kind, 'official_software')
        self.assertEqual(plugins[0].metadata_source, 'crawler-config')
        self.assertEqual(plugins[0].plugin_types, [])
        self.assertTrue(plugins[0].registry_visible)

    def test_crawl_adds_configured_official_template_repository(self) -> None:
        client = FakeGitHubClient(
            repository_statuses={
                'fairmat-nfdi/nomad-plugin-template': repository_status(
                    'fairmat-nfdi/nomad-plugin-template',
                    fork=False,
                ),
            },
        )

        report = crawl_pyproject_registry(
            {
                'github': {
                    'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                    'officialTemplateRepositories': [
                        {
                            'repository': 'FAIRmat-NFDI/nomad-plugin-template',
                            'name': 'nomad-plugin-template',
                            'description': 'A template repository.',
                        },
                    ],
                },
                'ownerGroups': {
                    'fairmat': ['fairmat-nfdi'],
                },
            },
            client=client,
            data_updated_at='2026-07-21T00:00:00Z',
        )

        validate_snapshot_data(report.snapshot)
        self.assertEqual(report.parsed_count, 1)
        self.assertEqual(report.skipped, [])
        self.assertEqual(report.snapshot['sourceSummary']['pluginCount'], 1)
        self.assertEqual(report.snapshot['sourceSummary']['registryVisibleCount'], 1)
        self.assertEqual(
            report.snapshot['plugins'][0]['id'],
            'github.com/fairmat-nfdi/nomad-plugin-template',
        )
        self.assertEqual(
            report.snapshot['plugins'][0]['projectKind'], 'official_template'
        )
        self.assertEqual(
            report.snapshot['plugins'][0]['metadataSource'], 'crawler-config'
        )
        self.assertEqual(report.snapshot['plugins'][0]['ownerType'], 'Organization')
        self.assertEqual(report.snapshot['plugins'][0]['ownerGroup'], 'fairmat')

    def test_configured_template_metadata_overrides_discovered_pyproject_name(
        self,
    ) -> None:
        candidate = candidate_file(
            repository='fairmat-nfdi/nomad-distro-template',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            search_pages={
                ('nomad-lab filename:pyproject.toml', 1): search_page([candidate])
            },
            fetch_texts={
                candidate.raw_url: """
[project]
name = "nomad-distribution"
description = "nomad distribution template"
dependencies = ["nomad-lab"]
""",
            },
            repository_statuses={
                'fairmat-nfdi/nomad-distro-template': repository_status(
                    'fairmat-nfdi/nomad-distro-template',
                    fork=False,
                ),
            },
        )

        report = crawl_pyproject_registry(
            {
                'github': {
                    'searchQueries': ['nomad-lab filename:pyproject.toml'],
                    'officialTemplateRepositories': [
                        {
                            'repository': 'FAIRmat-NFDI/nomad-distro-template',
                            'name': 'nomad-distro-template',
                            'description': 'A template repository.',
                        },
                    ],
                },
                'ownerGroups': {
                    'fairmat': ['fairmat-nfdi'],
                },
            },
            client=client,
            data_updated_at='2026-07-21T00:00:00Z',
        )

        validate_snapshot_data(report.snapshot)
        self.assertEqual(report.snapshot['plugins'][0]['name'], 'nomad-distro-template')
        self.assertEqual(
            report.snapshot['plugins'][0]['projectKind'], 'official_template'
        )
        self.assertEqual(
            report.snapshot['plugins'][0]['metadataSource'], 'crawler-config'
        )
        self.assertTrue(report.snapshot['plugins'][0]['registryVisible'])

    def test_crawls_pyproject_registry_snapshot(self) -> None:
        candidate = candidate_file(
            repository='example/alpha',
            file_path='packages/alpha/pyproject.toml',
        )
        client = FakeGitHubClient(
            search_pages={
                ('nomad.plugin filename:pyproject.toml', 1): search_page([candidate])
            },
            repository_search_pages={
                ('nomad plugin in:name,description,readme', 1): repository_search_page(
                    [
                        repository_candidate(
                            repository='glaidedata/nomad-measurements-afm',
                            fork=False,
                        ),
                    ],
                ),
            },
            fetch_texts={
                candidate.raw_url: pyproject_text(
                    'Alpha Plugin',
                    repository='example/alpha',
                ),
                (
                    'https://raw.githubusercontent.com/'
                    'glaidedata/nomad-measurements-afm/main/pyproject.toml'
                ): pyproject_text(
                    'Glaide AFM Plugin',
                    repository='glaidedata/nomad-measurements-afm',
                ),
            },
            repository_statuses={
                'glaidedata/nomad-measurements-afm': repository_status(
                    'glaidedata/nomad-measurements-afm',
                    fork=False,
                ),
            },
        )

        report = crawl_pyproject_registry(
            {
                'github': {
                    'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                    'repositorySearchQueries': [
                        'nomad plugin in:name,description,readme'
                    ],
                },
            },
            client=client,
            data_updated_at='2026-07-21T00:00:00Z',
        )
        snapshot = report.snapshot

        validate_snapshot_data(snapshot)
        self.assertEqual(
            snapshot['sourceSummary']['discovery'], 'github-code-search-pyproject'
        )
        self.assertEqual(snapshot['sourceSummary']['pluginCount'], 2)
        self.assertEqual(
            snapshot['plugins'][0]['id'],
            'github.com/example/alpha#packages/alpha',
        )
        self.assertEqual(snapshot['plugins'][0]['name'], 'Alpha Plugin')
        self.assertEqual(
            snapshot['plugins'][1]['id'],
            'github.com/glaidedata/nomad-measurements-afm',
        )
        self.assertEqual(snapshot['plugins'][0]['ownerGroup'], 'community')
        self.assertEqual(
            snapshot['plugins'][0]['status'],
            {
                'archived': False,
                'fork': True,
                'stars': 7,
                'createdAt': '2025-01-01T00:00:00Z',
                'lastPushedAt': '2026-07-01T00:00:00Z',
                'parentRepositoryUrl': 'https://github.com/example/parent-plugin',
                'sourceRepositoryUrl': 'https://github.com/example/source-plugin',
            },
        )
        self.assertEqual(report.fetched_count, 2)
        self.assertEqual(report.parsed_count, 2)
        self.assertEqual(report.skipped, [])

    def test_crawl_enriches_legacy_upload_metadata(self) -> None:
        candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        central_url = 'https://example.org/central-requirements.txt'
        example_oasis_url = 'https://example.org/example-requirements.txt'
        client = FakeGitHubClient(
            search_pages={
                ('nomad.plugin filename:pyproject.toml', 1): search_page([candidate])
            },
            fetch_texts={
                candidate.raw_url: pyproject_text(
                    'alpha-plugin',
                    repository='example/alpha',
                ),
                central_url: 'alpha-plugin==1.0.0\n',
                example_oasis_url: 'other-plugin==1.0.0\n',
                'https://pypi.org/pypi/alpha-plugin/json': '{}',
            },
            repository_statuses={
                'example/alpha': repository_status('example/alpha', fork=False),
            },
        )

        report = crawl_pyproject_registry(
            {
                'github': {
                    'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                },
                'deploymentSources': {
                    'centralRequirementsUrl': central_url,
                    'exampleOasisRequirementsUrl': example_oasis_url,
                },
            },
            client=client,
            data_updated_at='2026-07-21T00:00:00Z',
        )

        legacy_plugin = report.legacy_plugin_data[0]['data']

        self.assertTrue(legacy_plugin['on_central'])
        self.assertFalse(legacy_plugin['on_example_oasis'])
        self.assertTrue(legacy_plugin['on_pypi'])

    def test_crawl_excludes_configured_documentation_urls(self) -> None:
        candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            search_pages={
                ('nomad.plugin filename:pyproject.toml', 1): search_page([candidate])
            },
            fetch_texts={
                candidate.raw_url: pyproject_text(
                    'Alpha Plugin',
                    repository='example/alpha',
                    documentation_url='https://example.github.io/missing-docs/',
                ),
            },
            repository_statuses={
                'example/alpha': repository_status('example/alpha', fork=False),
            },
        )

        report = crawl_pyproject_registry(
            {
                'github': {
                    'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                    'excludeDocumentationUrls': [
                        'https://example.github.io/missing-docs'
                    ],
                },
            },
            client=client,
            data_updated_at='2026-07-21T00:00:00Z',
        )

        validate_snapshot_data(report.snapshot)
        self.assertNotIn('documentationUrl', report.snapshot['plugins'][0])

    def test_crawl_excludes_configured_pypi_urls(self) -> None:
        candidate = candidate_file(
            repository='example/alpha',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            search_pages={
                ('nomad.plugin filename:pyproject.toml', 1): search_page([candidate])
            },
            fetch_texts={
                candidate.raw_url: pyproject_text(
                    'alpha-plugin',
                    repository='example/alpha',
                ),
            },
            repository_statuses={
                'example/alpha': repository_status('example/alpha', fork=False),
            },
        )

        report = crawl_pyproject_registry(
            {
                'github': {
                    'searchQueries': ['nomad.plugin filename:pyproject.toml'],
                    'excludePypiUrls': ['https://pypi.org/project/alpha-plugin'],
                },
            },
            client=client,
            data_updated_at='2026-07-21T00:00:00Z',
        )

        validate_snapshot_data(report.snapshot)
        self.assertNotIn('pypiUrl', report.snapshot['plugins'][0])

    def test_marks_nomad_distributions_hidden_from_registry(self) -> None:
        candidate = candidate_file(
            repository='example/example-oasis',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                candidate.raw_url: """
[project]
name = "nomad-distribution"
description = "An Oasis distribution."
dependencies = ["nomad-lab"]
""",
            },
            repository_statuses={
                'example/example-oasis': repository_status(
                    'example/example-oasis',
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client, [candidate]
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].project_kind, 'distribution')
        self.assertFalse(plugins[0].registry_visible)

    def test_marks_official_plugin_template_repositories_visible(self) -> None:
        candidate = candidate_file(
            repository='fairmat-nfdi/nomad-plugin-template',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                candidate.raw_url: """
[project]
name = "nomad-plugin-template"
description = "NOMAD plugin template"
dependencies = ["nomad-lab"]
""",
            },
            repository_statuses={
                'fairmat-nfdi/nomad-plugin-template': repository_status(
                    'fairmat-nfdi/nomad-plugin-template',
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client, [candidate]
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].project_kind, 'official_template')
        self.assertTrue(plugins[0].registry_visible)

    def test_marks_official_distro_templates_visible_as_templates(self) -> None:
        candidate = candidate_file(
            repository='fairmat-nfdi/nomad-distro-template',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                candidate.raw_url: """
[project]
name = "nomad-distribution"
description = "nomad distribution template"
dependencies = ["nomad-lab"]
""",
            },
            repository_statuses={
                'fairmat-nfdi/nomad-distro-template': repository_status(
                    'fairmat-nfdi/nomad-distro-template',
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client, [candidate]
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].project_kind, 'official_template')
        self.assertTrue(plugins[0].registry_visible)

    def test_marks_unmodified_example_template_instances_hidden_from_registry(
        self,
    ) -> None:
        candidate = candidate_file(
            repository='example/copied-template-plugin',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                candidate.raw_url: pyproject_text(
                    'Copied Template Plugin',
                    repository='example/copied-template-plugin',
                    description='Nomad example template',
                ),
            },
            repository_statuses={
                'example/copied-template-plugin': repository_status(
                    'example/copied-template-plugin',
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client, [candidate]
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].project_kind, 'template_or_example')
        self.assertFalse(plugins[0].registry_visible)

    def test_marks_nomad_lab_dependents_without_entrypoints(self) -> None:
        candidate = candidate_file(
            repository='example/materials-course',
            file_path='HW/HW1/pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                candidate.raw_url: """
[project]
name = "HW1"
description = "Course material that uses NOMAD."
dependencies = ["nomad-lab", "numpy"]
""",
            },
            repository_statuses={
                'example/materials-course': repository_status(
                    'example/materials-course',
                    fork=False,
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client, [candidate]
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].project_kind, 'nomad_dependent_package')
        self.assertTrue(plugins[0].registry_visible)

    def test_reuses_repository_status_for_multiple_candidates_in_same_repo(
        self,
    ) -> None:
        first_candidate = candidate_file(
            repository='example/monorepo',
            file_path='packages/alpha/pyproject.toml',
        )
        second_candidate = candidate_file(
            repository='example/monorepo',
            file_path='packages/beta/pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                first_candidate.raw_url: pyproject_text(
                    'Alpha Plugin',
                    repository='example/monorepo',
                ),
                second_candidate.raw_url: pyproject_text(
                    'Beta Plugin',
                    repository='example/monorepo',
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [first_candidate, second_candidate],
        )

        self.assertEqual(len(plugins), 2)
        self.assertEqual(fetched_count, 2)
        self.assertEqual(skipped, [])
        self.assertEqual(client.repository_status_calls, ['example/monorepo'])

    def test_configures_fairmat_owners(self) -> None:
        self.assertEqual(
            fairmat_owners({'ownerGroups': {'fairmat': ['FAIRmat-NFDI']}}),
            {'fairmat-nfdi'},
        )
        self.assertEqual(fairmat_owners({'ownerGroups': {'fairmat': []}}), set())

    def test_rejects_invalid_fairmat_owner_config(self) -> None:
        with self.assertRaisesRegex(ValueError, 'ownerGroups.fairmat'):
            fairmat_owners({'ownerGroups': {'fairmat': ['fairmat-nfdi', '']}})

    def test_marks_configured_fairmat_owned_plugins(self) -> None:
        candidate = candidate_file(
            repository='FAIRmat-NFDI/alpha',
            file_path='pyproject.toml',
        )
        client = FakeGitHubClient(
            fetch_texts={
                candidate.raw_url: pyproject_text(
                    'Alpha Plugin',
                    repository='FAIRmat-NFDI/alpha',
                ),
            },
        )

        plugins, skipped, fetched_count = parse_pyproject_candidates(
            client,
            [candidate],
            fairmat_owners={'fairmat-nfdi'},
        )

        self.assertEqual(skipped, [])
        self.assertEqual(fetched_count, 1)
        self.assertEqual(plugins[0].owner_group, 'fairmat')


class FakeGitHubClient:
    def __init__(
        self,
        *,
        search_pages: dict[tuple[str, int], GitHubSearchPage] | None = None,
        repository_search_pages: (
            dict[tuple[str, int], GitHubRepositorySearchPage] | None
        ) = None,
        fetch_texts: dict[str | None, str] | None = None,
        fetch_errors: dict[str | None, Exception] | None = None,
        repository_statuses: dict[str, GitHubRepositoryStatus] | None = None,
    ) -> None:
        self.search_pages = search_pages or {}
        self.repository_search_pages = repository_search_pages or {}
        self.fetch_texts = fetch_texts or {}
        self.fetch_errors = fetch_errors or {}
        self.repository_statuses = repository_statuses or {}
        self.search_calls: list[tuple[str, int, int]] = []
        self.repository_search_calls: list[tuple[str, int, int]] = []
        self.fetch_calls: list[str] = []
        self.repository_status_calls: list[str] = []

    def search_code(
        self,
        query: str,
        *,
        page: int,
        per_page: int,
    ) -> GitHubSearchPage:
        self.search_calls.append((query, page, per_page))

        return self.search_pages.get((query, page), search_page([]))

    def search_repositories(
        self,
        query: str,
        *,
        page: int,
        per_page: int,
    ) -> GitHubRepositorySearchPage:
        self.repository_search_calls.append((query, page, per_page))

        return self.repository_search_pages.get(
            (query, page), repository_search_page([])
        )

    def fetch_text(self, url: str) -> str:
        self.fetch_calls.append(url)
        if url in self.fetch_errors:
            raise self.fetch_errors[url]

        return self.fetch_texts[url]

    def fetch_repository_status(
        self, repository_full_name: str
    ) -> GitHubRepositoryStatus:
        self.repository_status_calls.append(repository_full_name)

        return self.repository_statuses.get(
            repository_full_name,
            repository_status(repository_full_name, fork=True),
        )


def search_page(
    candidates: list[GitHubCandidateFile],
    *,
    next_url: str | None = None,
) -> GitHubSearchPage:
    return GitHubSearchPage(
        candidates=candidates,
        total_count=len(candidates),
        incomplete_results=False,
        next_url=next_url,
    )


def repository_search_page(
    candidates: list[GitHubRepositoryCandidate],
    *,
    next_url: str | None = None,
) -> GitHubRepositorySearchPage:
    return GitHubRepositorySearchPage(
        candidates=candidates,
        total_count=len(candidates),
        incomplete_results=False,
        next_url=next_url,
    )


def repository_candidate(
    *,
    repository: str,
    default_branch: str | None = 'main',
    archived: bool = False,
    fork: bool = False,
) -> GitHubRepositoryCandidate:
    return GitHubRepositoryCandidate(
        full_name=repository,
        repository_url=f'https://github.com/{repository}',
        default_branch=default_branch,
        archived=archived,
        fork=fork,
    )


def candidate_file(
    *,
    repository: str,
    file_path: str,
    raw_url: str | None = 'auto',
) -> GitHubCandidateFile:
    repository_url = f'https://github.com/{repository}'
    resolved_raw_url = raw_url
    if raw_url == 'auto':
        resolved_raw_url = (
            f'https://raw.githubusercontent.com/{repository}/main/{file_path}'
        )

    return GitHubCandidateFile(
        repository_full_name=repository,
        repository_url=repository_url,
        file_path=file_path,
        api_url=f'https://api.github.com/repos/{repository}/contents/{file_path}',
        html_url=f'{repository_url}/blob/main/{file_path}',
        raw_url=resolved_raw_url,
        default_branch='main',
    )


def pyproject_text(
    name: str,
    *,
    repository: str,
    description: str = 'A test NOMAD plugin.',
    documentation_url: str = 'https://example.github.io/example-plugin/',
) -> str:
    return f"""
[project]
name = "{name}"
description = "{description}"
dependencies = ["nomad-lab>=1.3"]

[project.urls]
Documentation = "{documentation_url}"
Repository = "https://github.com/{repository}"

[project.entry-points."nomad.plugin"]
example_parser = "example.parsers:parser_entrypoint"
"""


def repository_status(
    repository: str,
    *,
    archived: bool = False,
    fork: bool,
    owner_type: str | None = 'Organization',
) -> GitHubRepositoryStatus:
    return GitHubRepositoryStatus(
        full_name=repository,
        repository_url=f'https://github.com/{repository}',
        owner_type=owner_type,
        archived=archived,
        fork=fork,
        stars=7,
        created_at='2025-01-01T00:00:00Z',
        last_pushed_at='2026-07-01T00:00:00Z',
        parent_repository_url='https://github.com/example/parent-plugin'
        if fork
        else None,
        source_repository_url='https://github.com/example/source-plugin'
        if fork
        else None,
    )


if __name__ == '__main__':
    unittest.main()
