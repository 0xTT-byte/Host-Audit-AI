"""Tests for Phase 2 deterministic security rule registry and all 31 rules."""

from __future__ import annotations

from pathlib import Path

import pytest

import host_audit_ai.engine.rules  # noqa: F401
from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.engine import RuleRegistry, evaluate, load_default_baseline
from host_audit_ai.models.finding import Severity
from host_audit_ai.parsers import parse_envelope

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"

EXPECTED_RULE_IDS = {
    "SSH-001",
    "SSH-002",
    "SSH-003",
    "SSH-004",
    "SSH-005",
    "SSH-006",
    "USR-001",
    "USR-002",
    "EXP-001",
    "EXP-002",
    "FW-001",
    "FW-002",
    "SYS-001",
    "SYS-002",
    "SYS-003",
    "SYS-004",
    "PRV-001",
    "PRV-002",
    "PRV-003",
    "PRV-004",
    "FS-001",
    "FS-002",
    "FS-003",
    "CRN-001",
    "CNT-001",
    "CNT-002",
    "CNT-003",
    "CNT-004",
    "IOC-001",
    "IOC-002",
    "IOC-003",
}


def test_rule_registry_count_and_metadata() -> None:
    assert RuleRegistry.count() >= 25
    assert RuleRegistry.count() == len(EXPECTED_RULE_IDS)
    registered_ids = {meta.rule_id for meta, _ in RuleRegistry.all_rules()}
    assert registered_ids == EXPECTED_RULE_IDS


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULE_IDS))
def test_each_rule_triggers_on_vulnerable_and_is_clean_on_hardened(rule_id: str) -> None:
    baseline = load_default_baseline()

    hardened_env = decode_envelope((FIXTURES_DIR / "ubuntu_hardened.raw").read_bytes())
    hardened_snap = parse_envelope(hardened_env)
    hardened_report = evaluate(hardened_snap, baseline)
    hardened_ids = {f.rule_id for f in hardened_report.findings}
    assert rule_id not in hardened_ids

    vuln_env = decode_envelope((FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes())
    vuln_snap = parse_envelope(vuln_env)
    vuln_report = evaluate(vuln_snap, baseline)
    matching = [f for f in vuln_report.findings if f.rule_id == rule_id]
    assert len(matching) >= 1, f"Expected rule {rule_id} to trigger on ubuntu_vulnerable.raw"

    for f in matching:
        assert len(f.fingerprint) >= 16
        assert isinstance(f.severity, Severity)
        assert f.evidence
        assert f.target


def test_hardened_ubuntu_produces_zero_findings() -> None:
    baseline = load_default_baseline()
    env = decode_envelope((FIXTURES_DIR / "ubuntu_hardened.raw").read_bytes())
    snap = parse_envelope(env)
    report = evaluate(snap, baseline)
    assert report.findings == []
    assert report.summary.total_findings == 0


def test_rule_metadata_validity() -> None:
    for meta, _ in RuleRegistry.all_rules():
        assert meta.title
        assert meta.category in {
            "ssh",
            "identity",
            "exposure",
            "firewall",
            "kernel",
            "privesc",
            "filesystem",
            "cron",
            "containers",
            "ioc",
        }
        assert meta.cis_ref or meta.mitre_attack
