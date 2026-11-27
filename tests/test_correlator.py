"""Tests for the deterministic pre-LLM exposure chain correlator."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.engine import correlate_exposures, evaluate, load_default_baseline
from host_audit_ai.models.finding import DriftStatus, Severity
from host_audit_ai.models.policy import WaiverRule
from host_audit_ai.parsers import parse_envelope

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def test_vulnerable_host_generates_all_four_chain_classes() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    report = evaluate(snap, load_default_baseline())

    chains = report.exposure_chains
    assert len(chains) >= 4
    assert report.summary.exposure_chain_count == len(chains)

    titles_lower = [c.title.lower() for c in chains]
    assert any("ssh" in t for t in titles_lower)
    assert any("5432" in t or "9000" in t for t in titles_lower)
    assert any("container" in t or "docker" in t for t in titles_lower)
    assert any("deleted binary" in t or "ld_preload" in t or "cron" in t for t in titles_lower)

    # Every chain must have non-empty nodes and fingerprints and no PIDs in labels
    for chain in chains:
        assert len(chain.chain_id) == 64
        assert len(chain.nodes) >= 2
        assert len(chain.related_finding_fingerprints) >= 1
        for node in chain.nodes:
            assert "pid=" not in node.label.lower()
            assert "6666" not in node.label


def test_hardened_host_generates_zero_chains() -> None:
    raw = (FIXTURES_DIR / "ubuntu_hardened.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    report = evaluate(snap, load_default_baseline())

    assert report.exposure_chains == []
    assert report.summary.exposure_chain_count == 0


def test_correlator_determinism_and_sorting() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap1 = parse_envelope(decode_envelope(raw))
    snap2 = parse_envelope(decode_envelope(raw)).model_copy(
        update={"collected_at": datetime(2027, 1, 1, tzinfo=UTC)}
    )

    rep1 = evaluate(snap1, load_default_baseline(), as_of=date(2026, 11, 24))
    rep2 = evaluate(snap2, load_default_baseline(), as_of=date(2026, 11, 24))

    assert [c.model_dump() for c in rep1.exposure_chains] == [
        c.model_dump() for c in rep2.exposure_chains
    ]
    # Verify deterministic ordering: (-severity.weight, chain_id)
    sort_keys = [(-c.severity.weight, c.chain_id) for c in rep1.exposure_chains]
    assert sort_keys == sorted(sort_keys)


def test_waived_findings_excluded_and_expired_included() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    baseline = load_default_baseline()
    initial = evaluate(snap, baseline, as_of=date(2026, 6, 15))

    # Waive all SSH findings and CNT-001 socket finding; expire IOC-002 waiver
    ssh_and_socket_fps = {
        f.fingerprint
        for f in initial.findings
        if f.rule_id in ("SSH-001", "SSH-002", "SSH-003", "SSH-006", "CNT-001")
    }
    ioc002 = next(f for f in initial.findings if f.rule_id == "IOC-002")

    waivers = [
        WaiverRule(
            fingerprint=fp,
            reason="Approved test waiver",
            owner="secops",
            expires_at=date(2026, 12, 31),
        )
        for fp in ssh_and_socket_fps
    ]
    waivers.append(
        WaiverRule(
            fingerprint=ioc002.fingerprint,
            reason="Expired preload waiver",
            owner="secops",
            expires_at=date(2026, 1, 1),
        )
    )

    waived_report = evaluate(snap, baseline, waivers=waivers, as_of=date(2026, 6, 15))
    # SSH auth escalation chain and docker.sock CNT-001 chain must disappear
    assert not any("weak authentication" in c.title.lower() for c in waived_report.exposure_chains)
    assert not any("docker.sock" in c.title.lower() for c in waived_report.exposure_chains)
    # Expired waiver IOC-002 must still appear as active in chains
    assert any("ld_preload" in c.title.lower() for c in waived_report.exposure_chains)

    # Also test direct correlate_exposures call when all findings are WAIVED
    all_waived = [
        f.model_copy(update={"drift_status": DriftStatus.WAIVED}) for f in initial.findings
    ]
    assert correlate_exposures(snap, all_waived) == []


def test_severity_escalation_on_public_listener_to_root() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    baseline = load_default_baseline()
    rep = evaluate(snap, baseline)

    # Pick only EXP-001 (MEDIUM) and re-assign to a root-owned socket on 0.0.0.0:9000
    exp001 = next(f for f in rep.findings if f.rule_id == "EXP-001")
    assert exp001.severity == Severity.MEDIUM

    # Modify process 1000 user to root so public listener 0.0.0.0:9000 chains directly to root
    root_procs = [
        p.model_copy(update={"user": "root"}) if p.pid == 1000 else p for p in snap.processes
    ]
    snap_root = snap.model_copy(update={"processes": root_procs})
    chains = correlate_exposures(snap_root, [exp001])

    assert len(chains) == 1
    assert chains[0].severity == Severity.HIGH
