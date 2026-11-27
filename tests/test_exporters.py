"""Tests for JSON, SARIF 2.1.0, Markdown, and AI Bundle exporters."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.engine import evaluate, load_default_baseline
from host_audit_ai.exporters import export_report
from host_audit_ai.models.finding import DriftStatus, Evidence, Finding, Severity
from host_audit_ai.models.policy import WaiverRule
from host_audit_ai.models.report import AIBundle, AuditReport
from host_audit_ai.parsers import parse_envelope
from host_audit_ai.storage.diff import diff_runs

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def test_json_exporter_roundtrip() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    report = evaluate(snap, load_default_baseline())

    raw_json = export_report(report, "json")
    restored = AuditReport.model_validate_json(raw_json)
    assert restored == report


def test_sarif_210_exporter_compliance_and_suppressions() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    baseline = load_default_baseline()
    initial = evaluate(snap, baseline, as_of=date(2026, 6, 15))

    ssh001 = next(f for f in initial.findings if f.rule_id == "SSH-001")
    waiver = WaiverRule(
        fingerprint=ssh001.fingerprint,
        reason="Bastion exception",
        owner="secops",
        expires_at=date(2026, 12, 31),
    )
    report = evaluate(snap, baseline, waivers=[waiver], as_of=date(2026, 6, 15))

    sarif_str = export_report(report, "sarif")
    sarif = json.loads(sarif_str)

    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "host-audit-ai"
    driver_rule_ids = {r["id"] for r in driver["rules"]}

    results = run["results"]
    assert len(results) == len(report.findings)

    valid_levels = {"error", "warning", "note"}
    suppressed_count = 0
    for res in results:
        assert res["ruleId"] in driver_rule_ids
        assert res["level"] in valid_levels
        assert res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert len(res["partialFingerprints"]["primaryLocationLineHash"]) == 64
        if res["ruleId"] == "SSH-001":
            assert res["suppressions"][0]["kind"] == "inSource"
            assert res["suppressions"][0]["justification"] == "Bastion exception"
            suppressed_count += 1
        else:
            assert "suppressions" not in res
    assert suppressed_count == 1


def test_markdown_exporter_sections_and_diff() -> None:
    hard_raw = (FIXTURES_DIR / "ubuntu_hardened.raw").read_bytes()
    vuln_raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    hard_snap = parse_envelope(decode_envelope(hard_raw))
    vuln_snap = parse_envelope(decode_envelope(vuln_raw))
    baseline = load_default_baseline()

    hard_rep = evaluate(hard_snap, baseline)
    vuln_rep = evaluate(vuln_snap, baseline)
    delta = diff_runs(hard_rep, vuln_rep)

    md = export_report(vuln_rep, "markdown", diff=delta)
    assert f"# Host Security Audit Report: `{vuln_rep.hostname}`" in md
    assert "## Severity Summary" in md
    assert "## Exposure Chains" in md
    assert "->" in md
    assert "## Active Findings" in md
    assert "## Drift Delta" in md
    assert "SSH-001" in md


def test_ai_bundle_budget_and_redaction() -> None:
    raw = (FIXTURES_DIR / "ubuntu_vulnerable.raw").read_bytes()
    snap = parse_envelope(decode_envelope(raw))
    report = evaluate(snap, load_default_baseline())

    # Inject a finding containing IP, IPv6, /home path, and long evidence to test caps/redaction
    extra_finding = Finding(
        rule_id="TST-999",
        title="Connection from 10.20.30.40 and fe80::abcd to vuln-ubuntu-lab-02",
        severity=Severity.HIGH,
        category="test",
        target="user:victim",
        key_attribute="test_attr",
        expected="blocked",
        actual="allowed from 10.20.30.40 for /home/victim/.ssh/id_rsa",
        evidence=[
            Evidence(source_section="test", snippet="A" * 400),
            Evidence(source_section="test", snippet="user victim from 10.20.30.40"),
            Evidence(source_section="test", snippet="third evidence should be dropped"),
        ],
        fingerprint="f" * 64,
        drift_status=DriftStatus.NEW,
    )
    report_with_extra = report.model_copy(update={"findings": [*report.findings, extra_finding]})

    bundle_json = export_report(
        report_with_extra,
        "ai-bundle",
        snapshot=snap,
        redact=True,
        max_findings=10,
    )
    bundle = AIBundle.model_validate_json(bundle_json)

    assert bundle.redacted is True
    assert bundle.total_active_findings == len(report_with_extra.findings)
    assert bundle.included_findings_count == 10
    assert bundle.truncated_findings_count == bundle.total_active_findings - 10

    for f in bundle.findings:
        assert len(f.evidence_snippets) <= 2
        for snip in f.evidence_snippets:
            assert len(snip) <= 240

    # Relevant packages only (openssh-server, docker-ce), not bulk unrelated logs
    pkg_names = {p.name for p in bundle.relevant_packages}
    assert "openssh-server" in pkg_names or "docker-ce" in pkg_names

    # Redaction assertions: real hostname, private/public IPs, non-root user victim stripped
    assert "vuln-ubuntu-lab-02" not in bundle_json
    assert "10.20.30.40" not in bundle_json
    assert "fe80::abcd" not in bundle_json
    assert "/home/victim" not in bundle_json
    assert "[HOST_1]" in bundle_json
    assert "[USER_" in bundle_json
    # Wildcard and root preserved
    assert "0.0.0.0" in bundle_json  # noqa: S104
    assert "root" in bundle_json
