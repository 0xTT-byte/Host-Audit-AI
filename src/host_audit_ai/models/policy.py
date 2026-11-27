"""Baseline policy and waiver contracts."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from host_audit_ai.models.finding import Severity


class BaselineRuleOverride(BaseModel):
    """Rule override configuration within a baseline policy."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    enabled: bool = True
    severity_override: Severity | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class BaselinePolicy(BaseModel):
    """Auditing baseline specification."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    name: str
    description: str = ""
    rules: dict[str, BaselineRuleOverride] = Field(default_factory=dict)


class WaiverRule(BaseModel):
    """Security waiver exception rule."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    reason: str
    owner: str
    expires_at: date

    def is_expired(self, as_of: date | None = None) -> bool:
        """Check if waiver is expired as of a given date (defaults to UTC today)."""
        if as_of is None:
            as_of = datetime.now(UTC).date()
        return as_of > self.expires_at
