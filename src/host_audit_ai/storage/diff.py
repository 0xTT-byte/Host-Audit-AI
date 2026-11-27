"""Deterministic run-to-run drift diffing engine."""

from __future__ import annotations

from host_audit_ai.models.finding import DriftStatus, Finding
from host_audit_ai.models.report import AuditReport, RunDiff
from host_audit_ai.storage.db import AuditStore


def _is_waived(finding: Finding) -> bool:
    return finding.drift_status == DriftStatus.WAIVED


def _is_active(finding: Finding) -> bool:
    return finding.drift_status != DriftStatus.WAIVED


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-f.severity.weight, f.rule_id, f.target, f.fingerprint),
    )


def diff_runs(
    base: AuditReport,
    target: AuditReport,
    historical_fingerprints: set[str] | None = None,
) -> RunDiff:
    """Compare two AuditReports strictly by deterministic fingerprint.

    Classification rules:
      - WAIVED: drift_status == WAIVED in target.
      - PERSISTENT: active in both base and target.
      - RESOLVED: active in base, and absent from target active findings
        (either gone or newly WAIVED in target).
      - REGRESSED: active in target, NOT active in base, and either present in
        historical_fingerprints or WAIVED in base.
      - NEW: active in target, NOT active in base, and not in historical_fingerprints.
    """
    hist = historical_fingerprints or set()
    base_by_fp: dict[str, Finding] = {f.fingerprint: f for f in base.findings}
    target_by_fp: dict[str, Finding] = {f.fingerprint: f for f in target.findings}

    new_findings: list[Finding] = []
    persistent_findings: list[Finding] = []
    resolved_findings: list[Finding] = []
    regressed_findings: list[Finding] = []
    waived_findings: list[Finding] = []

    for tf in target_by_fp.values():
        if _is_waived(tf):
            waived_findings.append(tf.model_copy(update={"drift_status": DriftStatus.WAIVED}))
            continue

        bf = base_by_fp.get(tf.fingerprint)
        if bf is not None and _is_active(bf):
            persistent_findings.append(
                tf.model_copy(update={"drift_status": DriftStatus.PERSISTENT})
            )
        elif (bf is not None and _is_waived(bf)) or (tf.fingerprint in hist):
            regressed_findings.append(tf.model_copy(update={"drift_status": DriftStatus.REGRESSED}))
        else:
            new_findings.append(tf.model_copy(update={"drift_status": DriftStatus.NEW}))

    for bf in base_by_fp.values():
        if not _is_active(bf):
            continue
        target_match = target_by_fp.get(bf.fingerprint)
        if target_match is None or _is_waived(target_match):
            resolved_findings.append(bf.model_copy(update={"drift_status": DriftStatus.RESOLVED}))

    return RunDiff(
        base_run_id=base.run_id,
        target_run_id=target.run_id,
        new=_sort_findings(new_findings),
        persistent=_sort_findings(persistent_findings),
        resolved=_sort_findings(resolved_findings),
        regressed=_sort_findings(regressed_findings),
        waived=_sort_findings(waived_findings),
    )


def diff_from_store(store: AuditStore, base_run_id: str, target_run_id: str) -> RunDiff:
    """Load two runs from AuditStore and compute 3-run regression-aware drift diff."""
    base = store.get_run(base_run_id)
    if base is None:
        raise ValueError(f"Base run '{base_run_id}' not found in audit store.")

    target = store.get_run(target_run_id)
    if target is None:
        raise ValueError(f"Target run '{target_run_id}' not found in audit store.")

    historical = store.get_historical_fingerprints(
        host_id=target.host_id,
        before_created_at=base.created_at,
        exclude_run_id=base.run_id,
    )
    return diff_runs(base, target, historical_fingerprints=historical)
