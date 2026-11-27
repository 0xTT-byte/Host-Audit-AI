"""End-to-end Phase 3 CLI tests (scan, runs, diff, export) using tmp_path DB isolation."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from host_audit_ai.cli import app

runner = CliRunner()
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def test_cli_phase3_end_to_end_workflow(tmp_path: Path) -> None:
    db_file = tmp_path / "phase3_e2e.db"
    hard_target = f"file://{FIXTURES_DIR / 'ubuntu_hardened.raw'}"
    vuln_target = f"file://{FIXTURES_DIR / 'ubuntu_vulnerable.raw'}"

    # 1. Scan hardened -> saved run 1 (exit 0)
    res_hard = runner.invoke(
        app,
        ["scan", "--target", hard_target, "--db", str(db_file), "--json"],
    )
    assert res_hard.exit_code == 0
    hard_report = json.loads(res_hard.stdout)
    run1_id = hard_report["run_id"]
    assert hard_report["summary"]["exposure_chain_count"] == 0

    # 2. Scan vulnerable -> saved run 2 (exit 2)
    res_vuln = runner.invoke(
        app,
        ["scan", "--target", vuln_target, "--db", str(db_file), "--json"],
    )
    assert res_vuln.exit_code == 2
    vuln_report = json.loads(res_vuln.stdout)
    run2_id = vuln_report["run_id"]
    assert vuln_report["summary"]["exposure_chain_count"] >= 4

    # 3. `host-audit runs --db <tmp> --json` lists both runs
    res_runs = runner.invoke(app, ["runs", "--db", str(db_file), "--json"])
    assert res_runs.exit_code == 0
    runs_list = json.loads(res_runs.stdout)
    assert len(runs_list) == 2
    assert {r["run_id"] for r in runs_list} == {run1_id, run2_id}

    # 4. `host-audit diff --base <run1> --target <run2> --db <tmp> --fail-on-new high` -> exit 2
    res_diff = runner.invoke(
        app,
        [
            "diff",
            "--base",
            run1_id,
            "--target",
            run2_id,
            "--db",
            str(db_file),
            "--fail-on-new",
            "high",
            "--json",
        ],
    )
    assert res_diff.exit_code == 2
    diff_data = json.loads(res_diff.stdout)
    assert len(diff_data["new"]) >= 20
    assert diff_data["resolved"] == []

    # 5. `host-audit export <run2> --db <tmp> --format sarif --out <tmp>/out.sarif`
    sarif_out = tmp_path / "out.sarif"
    res_sarif = runner.invoke(
        app,
        [
            "export",
            run2_id,
            "--db",
            str(db_file),
            "--format",
            "sarif",
            "--out",
            str(sarif_out),
        ],
    )
    assert res_sarif.exit_code == 0
    assert sarif_out.is_file()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == len(vuln_report["findings"])

    # 6. `host-audit export <run2> --db <tmp> --format ai-bundle --redact`
    res_bundle = runner.invoke(
        app,
        [
            "export",
            run2_id,
            "--db",
            str(db_file),
            "--format",
            "ai-bundle",
            "--redact",
        ],
    )
    assert res_bundle.exit_code == 0
    bundle_data = json.loads(res_bundle.stdout)
    assert bundle_data["redacted"] is True
    assert "vuln-ubuntu-lab-02" not in res_bundle.stdout
    assert "[HOST_1]" in res_bundle.stdout


def test_cli_diff_host_and_offline_files(tmp_path: Path) -> None:
    db_file = tmp_path / "host_diff.db"
    hard_target = f"file://{FIXTURES_DIR / 'ubuntu_hardened.raw'}"
    vuln_target = f"file://{FIXTURES_DIR / 'ubuntu_vulnerable.raw'}"

    # Save two runs for same host (using identical fixture twice tests run_id disambiguation too)
    r1 = runner.invoke(app, ["scan", "--target", hard_target, "--db", str(db_file), "--json"])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["scan", "--target", hard_target, "--db", str(db_file), "--json"])
    assert r2.exit_code == 0

    res_host_diff = runner.invoke(
        app,
        ["diff", "--host", "prod-ubuntu-hardened-01", "--db", str(db_file), "--fail-on-new", "low"],
    )
    assert res_host_diff.exit_code == 0

    # Offline diff with --base-file and --target-file
    base_json = tmp_path / "base.json"
    target_json = tmp_path / "target.json"
    r_vuln = runner.invoke(
        app,
        [
            "scan",
            "--target",
            vuln_target,
            "--no-save",
            "--format",
            "json",
            "--out",
            str(target_json),
        ],
    )
    assert r_vuln.exit_code == 2
    base_json.write_text(r1.stdout, encoding="utf-8")

    res_offline = runner.invoke(
        app,
        [
            "diff",
            "--base-file",
            str(base_json),
            "--target-file",
            str(target_json),
            "--fail-on-new",
            "critical",
        ],
    )
    assert res_offline.exit_code == 2

    # Export markdown from --input file
    res_md = runner.invoke(
        app,
        ["export", "--input", str(target_json), "--format", "markdown"],
    )
    assert res_md.exit_code == 0
    assert "# Host Security Audit Report" in res_md.stdout
