"""Repository-level activity facts and their shared measurement window."""

from datetime import datetime, timedelta, timezone
from typing import Final

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

ACTIVITY_WINDOW_DAYS: Final = 180


class ActivityWindow(BaseModel):
    start: AwareDatetime = Field(description='Start of the shared 180-day UTC window.')
    end: AwareDatetime = Field(description='Shared UTC cutoff, equal to dataUpdatedAt.')

    @field_validator('start', 'end')
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def validate_window(self) -> 'ActivityWindow':
        if self.end - self.start != timedelta(days=ACTIVITY_WINDOW_DAYS):
            raise ValueError('The activity window must span exactly 180 days.')
        return self

    @classmethod
    def ending_at(cls, end: datetime) -> 'ActivityWindow':
        # Subtract elapsed UTC days, not local wall-clock days across a DST change.
        if end.tzinfo is not None:
            end = end.astimezone(timezone.utc)
        return cls(start=end - timedelta(days=ACTIVITY_WINDOW_DAYS), end=end)


class RepositoryActivity(BaseModel):
    """Default-branch history, not a quality score or project-specific count."""

    model_config = ConfigDict(populate_by_name=True)

    total_commits: int = Field(
        alias='totalCommits',
        ge=0,
        strict=True,
        description='Commits reachable from the sampled default-branch head.',
    )
    recent_commits: int = Field(
        alias='recentCommits',
        ge=0,
        strict=True,
        description='GitHub history count within the snapshot activityWindow.',
    )
    last_commit_at: AwareDatetime | None = Field(
        default=None,
        alias='lastCommitAt',
        description='Committer timestamp of the sampled default-branch head.',
    )

    @model_validator(mode='after')
    def validate_history(self) -> 'RepositoryActivity':
        if self.recent_commits > self.total_commits:
            raise ValueError('recentCommits must not exceed totalCommits.')
        if (self.total_commits == 0) != (self.last_commit_at is None):
            raise ValueError('Only an empty history may omit lastCommitAt.')
        return self
