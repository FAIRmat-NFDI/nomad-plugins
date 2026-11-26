"""Bounded, read-only live smoke check of the repository-activity query."""

import argparse
import asyncio
import json
import os
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from nomad_plugins.activity import ActivityWindow
from nomad_plugins.github import GitHubClient, GitHubError


async def check(repositories: list[str], token: str) -> None:
    window = ActivityWindow.ending_at(datetime.now(timezone.utc).replace(microsecond=0))
    print(json.dumps({'activityWindow': window.model_dump(mode='json')}), flush=True)
    async with GitHubClient(token) as client:
        for repository in repositories:
            started = time.monotonic()
            sample = await client.fetch_repository_activity(repository, window=window)
            print(
                json.dumps(
                    {
                        'repository': repository,
                        'seconds': round(time.monotonic() - started, 2),
                        'defaultBranch': sample.default_branch,
                        'headSha': sample.head_sha,
                        'queryCost': sample.query_cost,
                        'activity': sample.activity.model_dump(
                            mode='json', by_alias=True
                        ),
                    }
                ),
                flush=True,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        'repositories',
        nargs='*',
        default=[
            'FAIRmat-NFDI/nomad-plugins',
            'FAIRmat-NFDI/nomad-measurements',
            'nomad-coe/nomad',
        ],
    )
    args = parser.parse_args()
    if any(
        name.count('/') != 1 or not all(name.split('/')) for name in args.repositories
    ):
        parser.error('Repositories must use owner/name form.')
    load_dotenv()
    token = os.environ.get('GITHUB_TOKEN', '').strip()
    if not token:
        parser.error('Set GITHUB_TOKEN in this shell before running the live check.')
    try:
        asyncio.run(check(args.repositories, token))
    except GitHubError as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
