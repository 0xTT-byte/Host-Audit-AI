"""Audit finding, evidence, and exposure chain contracts."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Standardized finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Numerical weight for sorting and ranking."""
        weights = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight < other.weight

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight <= other.weight

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight > other.weight

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight >= other.weight


class DriftStatus(StrEnum):
    """Lifecycle and regression status of a finding across audit runs."""

    NEW = "NEW"
    PERSISTENT = "PERSISTENT"
    RESOLVED = "RESOLVED"
    REGRESSED = "REGRESSED"
    WAIVED = "WAIVED"
    WAIVER_EXPIRED = "WAIVER_EXPIRED"


class Evidence(BaseModel):
    """Traceable evidence snippet supporting a finding."""

    model_config = ConfigDict(extra="forbid")

    source_section: str
    snippet: str
    path: str | None = None
    line: int | None = None


def compute_fingerprint(rule_id: str, normalized_target: str, key_attribute: str) -> str:
    """Compute a deterministic SHA-256 hex digest for a finding.

    Strictly excludes volatile runtime attributes like PIDs or timestamps.
    """
    payload = f"{rule_id.strip()}|{normalized_target.strip()}|{key_attribute.strip()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Finding(BaseModel):
    """Standardized audit finding representing a policy violation."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    severity: Severity
    category: str
    target: str
    key_attribute: str
    expected: str
    actual: str
    evidence: list[Evidence]
    cis_ref: str | None = None
    mitre_attack: list[str] = Field(default_factory=list)
    fingerprint: str
    drift_status: DriftStatus | None = None
    waiver_reason: str | None = None


class ExposureNode(BaseModel):
    """Graph node in an exposure or attack pathway."""

    model_config = ConfigDict(extra="forbid")

    node_type: Literal["listener", "process", "binary", "service", "user", "privilege", "path"]
    label: str
    metadata: dict[str, str] = Field(default_factory=dict)


class ExposureChain(BaseModel):
    """Correlated multi-step exposure path formed by findings and host attributes."""

    model_config = ConfigDict(extra="forbid")

    chain_id: str
    title: str
    severity: Severity
    nodes: list[ExposureNode]
    related_finding_fingerprints: list[str]
