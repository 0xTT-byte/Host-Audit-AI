"""Deterministic evaluation engine executing rules against host snapshots."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime

from host_audit_ai.engine.correlator import correlate_exposures
from host_audit_ai.engine.registry import RuleRegistry
from host_audit_ai.engine.rules import *  # noqa: F403 Ensure all rules are loaded
from host_audit_ai.models.finding import DriftStatus, Finding, Severity
from host_audit_ai.models.policy import BaselinePolicy, WaiverRule
from host_audit_ai.models.report import AuditReport, AuditSummary
from host_audit_ai.models.snapshot import HostSnapshot


def evaluate(
    snapshot: HostSnapshot,
    baseline: BaselinePolicy,
    waivers: list[WaiverRule] | None = None,
    as_of: date | None = None,
) -> AuditReport:
    """Evaluate a HostSnapshot against a BaselinePolicy and active waivers.

    Deterministic purity: All rules execute purely against snapshot data.
    Waivers are matched by exact fingerprint.
    Findings are sorted deterministically by (severity desc, rule_id asc, target, fingerprint).
    """
    if as_of is None:
        as_of = datetime.now(UTC).date()

    all_findings: list[Finding] = []

    # Map rules in baseline overrides
    baseline_overrides = baseline.rules

    for meta, rule_fn in RuleRegistry.all_rules():
        override = baseline_overrides.get(meta.rule_id)
        if override is not None and not override.enabled:
            # Rule disabled by policy override
            continue

        params = dict(override.params) if override else {}
        rule_findings = rule_fn(snapshot, params)

        if override is not None and override.severity_override is not None:
            for f in rule_findings:
                f.severity = override.severity_override

        all_findings.extend(rule_findings)

    # Process waiver rules
    waiver_map: dict[str, WaiverRule] = {w.fingerprint: w for w in (waivers or [])}

    for finding in all_findings:
        if finding.fingerprint in waiver_map:
            waiver = waiver_map[finding.fingerprint]
            if not waiver.is_expired(as_of):
                finding.drift_status = DriftStatus.WAIVED
                finding.waiver_reason = waiver.reason
            else:
                finding.drift_status = DriftStatus.WAIVER_EXPIRED
                finding.waiver_reason = f"EXPIRED on {waiver.expires_at}: {waiver.reason}"
        else:
            finding.drift_status = DriftStatus.NEW

    # Sort deterministically
    all_findings.sort(key=lambda f: (-f.severity.weight, f.rule_id, f.target, f.fingerprint))

    # Compute summary
    counts_by_severity = {s: 0 for s in Severity}
    active_findings: list[Finding] = []
    waived_count = 0
    expired_waiver_count = 0

    for f in all_findings:
        if f.drift_status == DriftStatus.WAIVED:
            waived_count += 1
        elif f.drift_status == DriftStatus.WAIVER_EXPIRED:
            expired_waiver_count += 1
            active_findings.append(f)
            counts_by_severity[f.severity] += 1
        else:
            active_findings.append(f)
            counts_by_severity[f.severity] += 1

    exposure_chains = correlate_exposures(snapshot, all_findings)

    summary = AuditSummary(
        counts_by_severity=counts_by_severity,
        total_findings=len(active_findings),
        exposure_chain_count=len(exposure_chains),
        waived_count=waived_count,
        expired_waiver_count=expired_waiver_count,
    )

    # Compute snapshot hash (excluding collected_at timestamp)
    snapshot_data = snapshot.model_dump(mode="json", exclude={"collected_at"})
    canonical_snapshot_json = json.dumps(snapshot_data, sort_keys=True)
    snapshot_hash = hashlib.sha256(canonical_snapshot_json.encode("utf-8")).hexdigest()

    run_id = f"run-{snapshot_hash[:16]}"
    hostname = snapshot.metadata.hostname or "unknown"

    return AuditReport(
        schema_version="1.0.0",
        run_id=run_id,
        host_id=hostname,
        hostname=hostname,
        created_at=datetime.now(UTC),
        baseline_name=baseline.name,
        degraded_mode=snapshot.degraded_mode,
        snapshot_hash=snapshot_hash,
        findings=all_findings,
        exposure_chains=exposure_chains,
        summary=summary,
    )
