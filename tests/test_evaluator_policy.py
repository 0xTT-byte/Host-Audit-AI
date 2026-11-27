"""Tests for evaluator determinism, baseline policy overrides, and waiver expiry."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.engine import (
    evaluate,
    load_baseline,
    load_default_baseline,
    load_waivers,
)
from host_audit_ai.models.finding import DriftStatus, Severity
from host_audit_ai.parsers import parse_envelope

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def test_load_default_baseline() -> None:
    baseline = load_default_baseline()
    assert baseline.name == "default-hardening"
    assert "SSH-001" in baseline.rules
    assert baseline.rules["SSH-004"].params["max_auth_tries_threshold"] == 4


def test_custom_baseline_overrides_and_params(tmp_path: Path) -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    vuln_snap = parse_envelope(decode_envelope(raw))
    default_report = evaluate(vuln_snap, load_default_baseline())
    assert any(f.rule_id == "SSH-001" for f in default_report.findings)
    assert any(f.rule_id == "EXP-001" and "9000" in f.target for f in default_report.findings)

    custom_yaml = tmp_path / "custom.yaml"
    custom_yaml.write_text(
        """
schema_version: "1.0.0"
name: "lab-override"
rules:
  SSH-001:
    enabled: false
  SSH-002:
    enabled: true
    severity_override: low
  EXP-001:
    enabled: true
    params:
      allowed_public_ports: [22, 80, 443, 9000]
""",
        encoding="utf-8",
    )

    custom_baseline = load_baseline(custom_yaml, merge_with_default=True)
    assert custom_baseline.name == "lab-override"
    report = evaluate(vuln_snap, custom_baseline)

    rule_ids = {f.rule_id for f in report.findings}
    assert "SSH-001" not in rule_ids
    assert not any(f.rule_id == "EXP-001" and "9000" in f.target for f in report.findings)
    ssh002 = [f for f in report.findings if f.rule_id == "SSH-002"]
    assert len(ssh002) == 1
    assert ssh002[0].severity == Severity.LOW


def test_non_merged_baseline_and_missing_files(tmp_path: Path) -> None:
    minimal_yaml = tmp_path / "minimal.yaml"
    minimal_yaml.write_text(
        """
schema_version: "1.0.0"
name: "minimal"
rules:
  SSH-001:
    enabled: false
""",
        encoding="utf-8",
    )
    policy = load_baseline(minimal_yaml, merge_with_default=False)
    assert list(policy.rules.keys()) == ["SSH-001"]

    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "missing_baseline.yaml")

    with pytest.raises(FileNotFoundError):
        load_waivers(tmp_path / "missing_waivers.yaml")


def test_waivers_active_and_expired(tmp_path: Path) -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    vuln_snap = parse_envelope(decode_envelope(raw))
    baseline = load_default_baseline()
    initial = evaluate(vuln_snap, baseline)

    ssh001 = next(f for f in initial.findings if f.rule_id == "SSH-001")
    ioc002 = next(f for f in initial.findings if f.rule_id == "IOC-002")

    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        f"""
waivers:
  - fingerprint: "{ssh001.fingerprint}"
    reason: "Bastion exception until Q2"
    owner: "secops"
    expires_at: "2026-12-31"
  - fingerprint: "{ioc002.fingerprint}"
    reason: "Legacy preload exception"
    owner: "secops"
    expires_at: "2026-01-01"
""",
        encoding="utf-8",
    )

    waivers = load_waivers(waiver_file)
    report = evaluate(vuln_snap, baseline, waivers=waivers, as_of=date(2026, 6, 15))

    by_fp = {f.fingerprint: f for f in report.findings}
    assert by_fp[ssh001.fingerprint].drift_status == DriftStatus.WAIVED
    assert by_fp[ssh001.fingerprint].waiver_reason == "Bastion exception until Q2"
    assert by_fp[ioc002.fingerprint].drift_status == DriftStatus.WAIVER_EXPIRED
    assert "EXPIRED" in (by_fp[ioc002.fingerprint].waiver_reason or "")

    assert report.summary.waived_count == 1
    assert report.summary.expired_waiver_count == 1
    assert report.summary.total_findings == initial.summary.total_findings - 1


def test_evaluator_determinism() -> None:
    raw_bytes = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    env1 = decode_envelope(raw_bytes)
    env2 = decode_envelope(raw_bytes)
    env2 = env2.model_copy(update={"collected_at": datetime.now(UTC) + timedelta(hours=5)})

    snap1 = parse_envelope(env1)
    snap2 = parse_envelope(env2)
    baseline = load_default_baseline()

    rep1 = evaluate(snap1, baseline, as_of=date(2026, 11, 24))
    rep2 = evaluate(snap2, baseline, as_of=date(2026, 11, 24))

    assert rep1.snapshot_hash == rep2.snapshot_hash
    assert rep1.run_id == rep2.run_id
    assert rep1.summary == rep2.summary
    assert [f.model_dump() for f in rep1.findings] == [f.model_dump() for f in rep2.findings]
