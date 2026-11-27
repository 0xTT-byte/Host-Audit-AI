"""Triage and LLM collaboration contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LLMConfig(BaseModel):
    """Configuration options for local LLM inference."""

    model_config = ConfigDict(extra="forbid")

    model: str = (
        "ollama/hf.co/mradermacher/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic-GGUF:Q4_K_M"
    )
    base_url: str = "http://127.0.0.1:11434"
    api_key: str | None = None
    temperature: float = 0.1
    stream: bool = False
    max_iter: int = 3
    allow_delegation: bool = False


class SanitizedQueryItem(BaseModel):
    """Sanitized query item for upstream vulnerability/advisory lookup."""

    model_config = ConfigDict(extra="forbid")

    service_name: str
    package_version: str
    os_distro: str
    kernel_version: str
    rule_id: str
    cwe_id: str | None = None


class VerifiedEvidence(BaseModel):
    """Active verification observation confirming or refuting finding reachability."""

    model_config = ConfigDict(extra="forbid")

    finding_fingerprint: str
    verified: bool
    live_observation: str
    confidence: Literal["high", "medium", "low"]


class AdvisoryMatch(BaseModel):
    """External vulnerability advisory match."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str | None
    reference_url: str
    summary: str
    fixed_version: str | None = None


class RemediationArtifact(BaseModel):
    """Generated script or documentation artifact for vulnerability remediation."""

    model_config = ConfigDict(extra="forbid")

    filename: str
    language: Literal["bash", "python", "ansible", "markdown"]
    summary: str
    approved: bool = False
    sha256: str | None = None


class TriageReport(BaseModel):
    """Automated AI triage and correlation report."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    run_id: str
    llm_model: str
    created_at: datetime
    executive_summary: str
    verified_evidence: list[VerifiedEvidence] = Field(default_factory=list)
    advisories: list[AdvisoryMatch] = Field(default_factory=list)
    artifacts: list[RemediationArtifact] = Field(default_factory=list)

    @field_validator("created_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness in UTC."""
        if v.tzinfo is None:
            raise ValueError("created_at must be a timezone-aware datetime")
        return v.astimezone(UTC)
