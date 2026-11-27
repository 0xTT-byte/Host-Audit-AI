"""Tests for SQLite AuditStore persistence and 3-run drift diff lifecycle."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.engine import evaluate, load_default_baseline
from host_audit_ai.models.finding import DriftStatus, Evidence, Finding, Severity
from host_audit_ai.models.report import AuditReport, AuditSummary
from host_audit_ai.models.triage import TriageReport
from host_audit_ai.parsers import parse_envelope
from host_audit_ai.storage import AuditStore, diff_from_store, diff_runs, resolve_db_path

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def _make_finding(
    rule_id: str,
    target: str,
    severity: Severity = Severity.HIGH,
    drift_status: DriftStatus | None = DriftStatus.NEW,
    waiver_reason: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Finding {rule_id} on {target}",
        severity=severity,
        category="test",
        target=target,
        key_attribute="attr",
        expected="secure",
        actual="insecure",
        evidence=[Evidence(source_section="test", snippet=f"{rule_id} {target}")],
        fingerprint=f"fp-{rule_id}-{target}",
        drift_status=drift_status,
        waiver_reason=waiver_reason,
    )


def _make_report(
    run_id: str,
    created_at: datetime,
    findings: list[Finding],
    host_id: str = "host-01",
    hostname: str = "srv-test-01",
) -> AuditReport:
    counts = {s: 0 for s in Severity}
    waived = 0
    expired = 0
    active = 0
    for f in findings:
        if f.drift_status == DriftStatus.WAIVED:
            waived += 1
        else:
            active += 1
            counts[f.severity] += 1
            if f.drift_status == DriftStatus.WAIVER_EXPIRED:
                expired += 1
    return AuditReport(
        run_id=run_id,
        host_id=host_id,
        hostname=hostname,
        created_at=created_at,
        baseline_name="default-hardening",
        degraded_mode=False,
        snapshot_hash=f"hash-{run_id}",
        findings=findings,
        exposure_chains=[],
        summary=AuditSummary(
            counts_by_severity=counts,
            total_findings=active,
            exposure_chain_count=0,
            waived_count=waived,
            expired_waiver_count=expired,
        ),
    )


def test_db_path_resolution_precedence(monkeypatch: object, tmp_path: Path) -> None:
    import pytest

    mp = pytest.MonkeyPatch()
    mp.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    mp.setenv("HOST_AUDIT_DB", str(tmp_path / "env.db"))

    assert resolve_db_path(tmp_path / "explicit.db") == tmp_path / "explicit.db"
    assert resolve_db_path() == tmp_path / "env.db"

    mp.delenv("HOST_AUDIT_DB")
    assert resolve_db_path() == tmp_path / "xdg" / "host-audit-ai" / "audit.db"
    mp.undo()


def test_audit_store_roundtrip_and_permissions(tmp_path: Path) -> None:
    db_file = tmp_path / "secure" / "audit.db"
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    report = evaluate(snap, load_default_baseline())

    with AuditStore(db_path=db_file) as store:
        saved_id = store.save_run(report, snapshot=snap)
        assert saved_id == report.run_id

        loaded_report = store.get_run(saved_id)
        assert loaded_report is not None
        assert loaded_report == report

        loaded_snap = store.get_snapshot(saved_id)
        assert loaded_snap is not None
        assert loaded_snap == snap

        runs = store.list_runs(limit=10)
        assert len(runs) == 1
        assert runs[0].run_id == saved_id
        assert runs[0].exposure_chain_count == report.summary.exposure_chain_count

        latest = store.get_latest_runs_for_host(report.hostname, limit=2)
        assert len(latest) == 1
        assert latest[0].run_id == saved_id

        triage = TriageReport(
            run_id=saved_id,
            llm_model="test-model",
            created_at=datetime.now(UTC),
            executive_summary="Summary text",
        )
        triage_id = store.save_triage(triage)
        assert triage_id.startswith("triage-")
        triages = store.get_triage_runs(saved_id)
        assert len(triages) == 1
        assert triages[0] == triage

    if os.name == "posix":
        db_mode = stat.S_IMODE(db_file.stat().st_mode)
        dir_mode = stat.S_IMODE(db_file.parent.stat().st_mode)
        assert db_mode == 0o600
        assert dir_mode == 0o700


def test_three_run_drift_lifecycle(tmp_path: Path) -> None:
    db_file = tmp_path / "drift.db"
    t0 = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    t1 = t0 + timedelta(days=1)
    t2 = t0 + timedelta(days=2)

    fx = _make_finding("SSH-001", "sshd:PermitRootLogin", Severity.HIGH)
    fy = _make_finding("EXP-001", "0.0.0.0:9000", Severity.MEDIUM)
    fz_active = _make_finding("SYS-002", "kernel.kptr_restrict", Severity.MEDIUM)
    fz_waived = _make_finding(
        "SYS-002",
        "kernel.kptr_restrict",
        Severity.MEDIUM,
        drift_status=DriftStatus.WAIVED,
        waiver_reason="Accepted risk",
    )
    fw_waived = _make_finding(
        "IOC-002",
        "/etc/ld.so.preload",
        Severity.CRITICAL,
        drift_status=DriftStatus.WAIVED,
        waiver_reason="Temporary waiver",
    )
    fw_expired = _make_finding(
        "IOC-002",
        "/etc/ld.so.preload",
        Severity.CRITICAL,
        drift_status=DriftStatus.WAIVER_EXPIRED,
        waiver_reason="EXPIRED on 2026-11-21: Temporary waiver",
    )

    # Run 1: X present, W waived
    r1 = _make_report("run-1", t0, [fx, fw_waived])
    # Run 2: X fixed, Y added, Z active, W still waived
    r2 = _make_report("run-2", t1, [fy, fz_active, fw_waived])
    # Run 3: X re-introduced, Y still present, Z waived, W waiver expired
    r3 = _make_report("run-3", t2, [fx, fy, fz_waived, fw_expired])

    with AuditStore(db_path=db_file) as store:
        store.save_run(r1)
        store.save_run(r2)
        store.save_run(r3)

        # Run 1 -> Run 2: X RESOLVED, Y NEW, Z NEW, W WAIVED
        d12 = diff_from_store(store, "run-1", "run-2")
        assert [f.fingerprint for f in d12.resolved] == [fx.fingerprint]
        assert d12.resolved[0].drift_status == DriftStatus.RESOLVED
        assert {f.fingerprint for f in d12.new} == {fy.fingerprint, fz_active.fingerprint}
        assert all(f.drift_status == DriftStatus.NEW for f in d12.new)
        assert [f.fingerprint for f in d12.waived] == [fw_waived.fingerprint]

        # Run 2 -> Run 3: X REGRESSED (via historical fingerprint from Run 1),
        # W REGRESSED (was WAIVED in Run 2, now WAIVER_EXPIRED),
        # Y PERSISTENT, Z RESOLVED (newly WAIVED) & in WAIVED bucket
        d23 = diff_from_store(store, "run-2", "run-3")
        regressed_fps = {f.fingerprint for f in d23.regressed}
        assert regressed_fps == {fx.fingerprint, fw_expired.fingerprint}
        assert all(f.drift_status == DriftStatus.REGRESSED for f in d23.regressed)

        assert [f.fingerprint for f in d23.persistent] == [fy.fingerprint]
        assert d23.persistent[0].drift_status == DriftStatus.PERSISTENT

        assert [f.fingerprint for f in d23.waived] == [fz_waived.fingerprint]
        assert d23.waived[0].drift_status == DriftStatus.WAIVED

        assert [f.fingerprint for f in d23.resolved] == [fz_active.fingerprint]
        assert d23.resolved[0].drift_status == DriftStatus.RESOLVED
        assert d23.new == []


def test_diff_runs_direct_sorting() -> None:
    t0 = datetime(2026, 11, 20, tzinfo=UTC)
    f_low = _make_finding("SSH-005", "sshd:X11Forwarding", Severity.LOW)
    f_crit = _make_finding("PRV-001", "sudoers:victim", Severity.CRITICAL)
    r1 = _make_report("r1", t0, [])
    r2 = _make_report("r2", t0 + timedelta(hours=1), [f_low, f_crit])

    d = diff_runs(r1, r2)
    assert [f.rule_id for f in d.new] == ["PRV-001", "SSH-005"]


def test_vulnerable_findings_have_unique_fingerprints_and_exact_diff_count() -> None:
    hard_raw = (FIXTURES_DIR / "ubuntu_hardened.raw").read_bytes()
    vuln_raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    hard_snap = parse_envelope(decode_envelope(hard_raw))
    vuln_snap = parse_envelope(decode_envelope(vuln_raw))
    baseline = load_default_baseline()

    hard_report = evaluate(hard_snap, baseline)
    vuln_report = evaluate(vuln_snap, baseline)

    fingerprints = [f.fingerprint for f in vuln_report.findings]
    assert len(set(fingerprints)) == len(vuln_report.findings)

    delta = diff_runs(hard_report, vuln_report)
    assert len(delta.new) == len(vuln_report.findings)
