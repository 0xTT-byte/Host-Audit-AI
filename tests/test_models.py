"""Unit tests for Pydantic v2 frozen contracts."""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from host_audit_ai.models import (
    AdvisoryMatch,
    AuditReport,
    AuditSummary,
    BaselinePolicy,
    BaselineRuleOverride,
    DriftStatus,
    Evidence,
    ExposureChain,
    ExposureNode,
    Finding,
    HostMetadata,
    HostSnapshot,
    LLMConfig,
    RawCollectorEnvelope,
    RawSection,
    RemediationArtifact,
    RunDiff,
    Severity,
    TriageReport,
    VerifiedEvidence,
    WaiverRule,
    compute_fingerprint,
)


def test_raw_collector_envelope_roundtrip() -> None:
    now = datetime.now(UTC)
    section = RawSection(
        name="net-listen",
        command="ss -tulpnH",
        exit_code=0,
        stdout="tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
        stderr="",
        truncated=False,
    )
    envelope = RawCollectorEnvelope(
        collector_version="1.0.0",
        collected_at=now,
        hostname="audit-target-01",
        target_uri="ssh://user@audit-target-01",
        euid=0,
        degraded_mode=False,
        sections={"net-listen": section},
    )
    json_data = envelope.model_dump_json()
    restored = RawCollectorEnvelope.model_validate_json(json_data)
    assert restored == envelope
    assert restored.sections["net-listen"].exit_code == 0


def test_host_snapshot_roundtrip() -> None:
    now = datetime.now(UTC)
    meta = HostMetadata(
        hostname="srv-prod-01",
        os_name="Ubuntu",
        os_version="24.04",
        kernel_release="6.8.0-generic",
        architecture="x86_64",
        uptime_seconds=3600.0,
    )
    snapshot = HostSnapshot(
        collected_at=now,
        degraded_mode=False,
        metadata=meta,
    )
    json_data = snapshot.model_dump_json()
    restored = HostSnapshot.model_validate_json(json_data)
    assert restored == snapshot
    assert restored.metadata.hostname == "srv-prod-01"


def test_baseline_policy_roundtrip() -> None:
    policy = BaselinePolicy(
        name="strict-prod",
        description="Production host baseline",
        rules={
            "SSH-001": BaselineRuleOverride(
                rule_id="SSH-001",
                enabled=True,
                severity_override=Severity.CRITICAL,
                params={"permit_root_login": "no"},
            )
        },
    )
    json_data = policy.model_dump_json()
    restored = BaselinePolicy.model_validate_json(json_data)
    assert restored == policy
    assert restored.rules["SSH-001"].severity_override == Severity.CRITICAL


def test_waiver_rule_roundtrip_and_expiry() -> None:
    waiver = WaiverRule(
        fingerprint="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        reason="Legacy bastion migration in progress",
        owner="secops@example.com",
        expires_at=date(2026, 6, 15),
    )
    json_data = waiver.model_dump_json()
    restored = WaiverRule.model_validate_json(json_data)
    assert restored == waiver

    # Test is_expired across past, present, and future dates
    assert waiver.is_expired(as_of=date(2026, 6, 14)) is False  # Before expiry date -> active
    assert waiver.is_expired(as_of=date(2026, 6, 15)) is False  # On expiry date -> still active
    assert waiver.is_expired(as_of=date(2026, 6, 16)) is True  # After expiry date -> expired


def test_finding_and_fingerprint_stability() -> None:
    rule_id = "EXP-001"
    target = "0.0.0.0:9000"
    key_attr = "listener"
    fp1 = compute_fingerprint(rule_id, target, key_attr)
    fp2 = compute_fingerprint(" EXP-001 ", "0.0.0.0:9000\n", " listener ")
    assert fp1 == fp2
    assert len(fp1) == 64

    finding = Finding(
        rule_id=rule_id,
        title="Unauthenticated debug port listening",
        severity=Severity.HIGH,
        category="exposure",
        target=target,
        key_attribute=key_attr,
        expected="Bound to 127.0.0.1 or closed",
        actual="Bound to 0.0.0.0",
        evidence=[Evidence(source_section="net-listen", snippet="tcp LISTEN 0 128 0.0.0.0:9000")],
        fingerprint=fp1,
        drift_status=DriftStatus.NEW,
    )
    json_data = finding.model_dump_json()
    restored = Finding.model_validate_json(json_data)
    assert restored == finding


def test_exposure_chain_roundtrip() -> None:
    node1 = ExposureNode(node_type="listener", label="Port 9000", metadata={"port": "9000"})
    node2 = ExposureNode(node_type="process", label="debug-agent", metadata={"user": "root"})
    chain = ExposureChain(
        chain_id="CHN-001",
        title="Exposed debug listener running as root",
        severity=Severity.CRITICAL,
        nodes=[node1, node2],
        related_finding_fingerprints=["fp123456"],
    )
    json_data = chain.model_dump_json()
    restored = ExposureChain.model_validate_json(json_data)
    assert restored == chain


def test_audit_report_and_run_diff_roundtrip() -> None:
    now = datetime.now(UTC)
    summary = AuditSummary(
        counts_by_severity={
            Severity.CRITICAL: 1,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        },
        total_findings=1,
        exposure_chain_count=0,
        waived_count=0,
        expired_waiver_count=0,
    )
    finding = Finding(
        rule_id="SSH-001",
        title="Root login allowed",
        severity=Severity.CRITICAL,
        category="ssh",
        target="sshd_config",
        key_attribute="PermitRootLogin",
        expected="no",
        actual="yes",
        evidence=[Evidence(source_section="sshd", snippet="PermitRootLogin yes")],
        fingerprint="fp-ssh-001",
    )
    report = AuditReport(
        run_id="run-20261124-001",
        host_id="host-001",
        hostname="srv-prod-01",
        created_at=now,
        baseline_name="strict-prod",
        degraded_mode=False,
        snapshot_hash="hash-123456",
        findings=[finding],
        exposure_chains=[],
        summary=summary,
    )
    json_data = report.model_dump_json()
    restored = AuditReport.model_validate_json(json_data)
    assert restored == report

    diff = RunDiff(
        base_run_id="run-20261124-000",
        target_run_id="run-20261124-001",
        new=[finding],
        persistent=[],
        resolved=[],
        regressed=[],
        waived=[],
    )
    diff_json = diff.model_dump_json()
    restored_diff = RunDiff.model_validate_json(diff_json)
    assert restored_diff == diff


def test_llm_config_and_triage_report_roundtrip() -> None:
    now = datetime.now(UTC)
    config = LLMConfig()
    json_data = config.model_dump_json()
    restored_cfg = LLMConfig.model_validate_json(json_data)
    assert restored_cfg == config

    triage = TriageReport(
        run_id="run-20261124-001",
        llm_model="DeepSeek-V4-Pro",
        created_at=now,
        executive_summary="Critical findings require prompt remediation.",
        verified_evidence=[
            VerifiedEvidence(
                finding_fingerprint="fp-ssh-001",
                verified=True,
                live_observation="PermitRootLogin confirmed active in sshd -T",
                confidence="high",
            )
        ],
        advisories=[
            AdvisoryMatch(
                cve_id="CVE-2024-6387",
                reference_url="https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                summary="regreSSHion vulnerability in OpenSSH server",
                fixed_version="1:9.6p1-3ubuntu13.3",
            )
        ],
        artifacts=[
            RemediationArtifact(
                filename="fix_ssh.sh",
                language="bash",
                summary="Disable PermitRootLogin and restart sshd",
                approved=False,
            )
        ],
    )
    triage_json = triage.model_dump_json()
    restored_triage = TriageReport.model_validate_json(triage_json)
    assert restored_triage == triage


def test_extra_fields_forbidden() -> None:
    """Ensure extra='forbid' rejects unknown fields across models."""
    with pytest.raises(ValidationError):
        RawSection(
            name="test",
            exit_code=0,
            stdout="",
            unknown_extra_field="rejected",  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError):
        Finding(
            rule_id="TST-001",
            title="Test",
            severity=Severity.LOW,
            category="test",
            target="test",
            key_attribute="attr",
            expected="exp",
            actual="act",
            evidence=[],
            fingerprint="fp",
            bogus_key=123,  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError):
        BaselinePolicy(
            name="test",
            unrecognized="bad",  # type: ignore[call-arg]
        )


def test_severity_comparison() -> None:
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO
    assert Severity.INFO < Severity.CRITICAL
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.MEDIUM
