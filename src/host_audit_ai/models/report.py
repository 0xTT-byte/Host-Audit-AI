"""Audit report, run metadata, AI bundle, and diff models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from host_audit_ai.models.finding import (
    DriftStatus,
    ExposureChain,
    ExposureNode,
    Finding,
    Severity,
)


class AuditSummary(BaseModel):
    """Aggregated finding metrics for an audit report."""

    model_config = ConfigDict(extra="forbid")

    counts_by_severity: dict[Severity, int]
    total_findings: int
    exposure_chain_count: int
    waived_count: int
    expired_waiver_count: int


class AuditReport(BaseModel):
    """Complete audit run result report."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    run_id: str
    host_id: str
    hostname: str
    created_at: datetime
    baseline_name: str
    degraded_mode: bool
    snapshot_hash: str
    findings: list[Finding]
    exposure_chains: list[ExposureChain]
    summary: AuditSummary

    @field_validator("created_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness in UTC."""
        if v.tzinfo is None:
            raise ValueError("created_at must be a timezone-aware datetime")
        return v.astimezone(UTC)


class RunRecord(BaseModel):
    """Lightweight metadata record for a persisted audit run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    host_id: str
    hostname: str
    created_at: datetime
    baseline_name: str
    degraded_mode: bool
    snapshot_hash: str
    total_findings: int
    exposure_chain_count: int

    @field_validator("created_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness in UTC."""
        if v.tzinfo is None:
            raise ValueError("created_at must be a timezone-aware datetime")
        return v.astimezone(UTC)


class RunDiff(BaseModel):
    """Drift differential comparison between two audit runs."""

    model_config = ConfigDict(extra="forbid")

    base_run_id: str
    target_run_id: str
    new: list[Finding] = Field(default_factory=list)
    persistent: list[Finding] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)
    regressed: list[Finding] = Field(default_factory=list)
    waived: list[Finding] = Field(default_factory=list)


class AIBundlePackage(BaseModel):
    """Relevant installed package context included in an AI bundle."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    architecture: str = ""


class AIBundleChain(BaseModel):
    """Compact exposure chain representation for token-budgeted LLM context."""

    model_config = ConfigDict(extra="forbid")

    chain_id: str
    title: str
    severity: Severity
    path_summary: str
    nodes: list[ExposureNode]
    related_finding_fingerprints: list[str]


class AIBundleFinding(BaseModel):
    """Evidence-capped finding representation for token-budgeted LLM context."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    severity: Severity
    category: str
    target: str
    expected: str
    actual: str
    evidence_snippets: list[str] = Field(default_factory=list)
    cis_ref: str | None = None
    mitre_attack: list[str] = Field(default_factory=list)
    fingerprint: str
    drift_status: DriftStatus | None = None
    waiver_reason: str | None = None


class AIBundle(BaseModel):
    """Token-budgeted, redaction-capable context bundle for local AI triage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    run_id: str
    host_id: str
    hostname: str
    created_at: datetime
    baseline_name: str
    degraded_mode: bool
    redacted: bool = False
    summary: AuditSummary
    total_active_findings: int
    included_findings_count: int
    truncated_findings_count: int
    exposure_chains: list[AIBundleChain] = Field(default_factory=list)
    findings: list[AIBundleFinding] = Field(default_factory=list)
    relevant_packages: list[AIBundlePackage] = Field(default_factory=list)

    @field_validator("created_at")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        """Enforce timezone awareness in UTC."""
        if v.tzinfo is None:
            raise ValueError("created_at must be a timezone-aware datetime")
        return v.astimezone(UTC)
