"""CLI integration tests for `host-audit scan` and `host-audit rules`."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from host_audit_ai.cli import app
from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.engine import evaluate, load_default_baseline
from host_audit_ai.parsers import parse_envelope

runner = CliRunner()
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def test_cli_rules_table_and_json() -> None:
    res = runner.invoke(app, ["rules"])
    assert res.exit_code == 0
    assert "SSH-001" in res.stdout
    assert "CNT-001" in res.stdout
    assert "IOC-002" in res.stdout

    res_ssh = runner.invoke(app, ["rules", "--category", "ssh", "--json"])
    assert res_ssh.exit_code == 0
    ssh_rules = json.loads(res_ssh.stdout)
    assert len(ssh_rules) == 6
    assert all(r["category"] == "ssh" for r in ssh_rules)

    res_crit = runner.invoke(app, ["rules", "--severity", "critical", "--json"])
    assert res_crit.exit_code == 0
    crit_rules = json.loads(res_crit.stdout)
    assert len(crit_rules) >= 5
    assert all(r["default_severity"] == "CRITICAL" for r in crit_rules)


def test_cli_scan_hardened_exits_zero() -> None:
    target = f"file://{FIXTURES_DIR / 'ubuntu_hardened.raw'}"
    res = runner.invoke(app, ["scan", "--target", target, "--fail-on", "high", "--no-save"])
    assert res.exit_code == 0
    assert "0 active" in res.stdout


def test_cli_scan_vulnerable_exits_two_and_writes_json(tmp_path: Path) -> None:
    target = f"file://{FIXTURES_DIR / 'ubuntu_vulnerable.raw'}"
    out_file = tmp_path / "audit_report.json"

    res = runner.invoke(
        app,
        [
            "scan",
            "--target",
            target,
            "--fail-on",
            "high",
            "--json",
            "--out",
            str(out_file),
            "--no-save",
        ],
    )
    assert res.exit_code == 2
    assert out_file.is_file()

    report_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert report_data["hostname"] == "vuln-ubuntu-lab-02"
    assert report_data["summary"]["total_findings"] >= 31


def test_cli_scan_with_waiver_gate(tmp_path: Path) -> None:
    # Check that waiving all findings above --fail-on threshold makes exit code 0
    vuln_path = FIXTURES_DIR / "ubuntu_vulnerable.raw"
    snap = parse_envelope(decode_envelope(vuln_path.read_bytes()))
    rep = evaluate(snap, load_default_baseline())

    waivers_entries = [
        {
            "fingerprint": f.fingerprint,
            "reason": "Temporary exception",
            "owner": "test",
            "expires_at": "2099-12-31",
        }
        for f in rep.findings
        if f.severity.weight >= 4  # high and critical
    ]
    waiver_file = tmp_path / "waivers.yaml"
    import yaml

    waiver_file.write_text(yaml.safe_dump({"waivers": waivers_entries}), encoding="utf-8")

    res = runner.invoke(
        app,
        [
            "scan",
            "--target",
            f"file://{vuln_path}",
            "--waivers",
            str(waiver_file),
            "--fail-on",
            "high",
            "--no-save",
        ],
    )
    assert res.exit_code == 0


def test_cli_scan_degraded_rhel() -> None:
    target = f"file://{FIXTURES_DIR / 'rhel_degraded.raw'}"
    res = runner.invoke(app, ["scan", "--target", target, "--fail-on", "high", "--no-save"])
    assert res.exit_code == 0
    assert "degraded mode" in res.stdout.lower()


def test_cli_scan_invalid_target_exits_one() -> None:
    res = runner.invoke(app, ["scan", "--target", "file:///nonexistent/capture.raw", "--no-save"])
    assert res.exit_code == 1
