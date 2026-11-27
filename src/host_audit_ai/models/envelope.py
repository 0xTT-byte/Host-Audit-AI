"""Raw collector envelope models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RawSection(BaseModel):
    """Raw command execution output captured during collection."""

    model_config = ConfigDict(extra="forbid")

    name: str
    command: str | None = None
    exit_code: int
    stdout: str
    stderr: str = ""
    truncated: bool = False


class RawCollectorEnvelope(BaseModel):
    """Envelope wrapping all raw command outputs gathered by host collector."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    collector_version: str
    collected_at: datetime
    hostname: str
    target_uri: str
    euid: int
    degraded_mode: bool
    sections: dict[str, RawSection] = Field(default_factory=dict)

    @field_validator("collected_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness in UTC."""
        if v.tzinfo is None:
            raise ValueError("collected_at must be a timezone-aware datetime")
        return v.astimezone(UTC)
