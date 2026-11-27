"""CLI tests for host-audit triage (missing-extra error, dry-run sanitizer, and mocked run)."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from host_audit_ai.cli import app
from host_audit_ai.models.triage import TriageReport
from host_audit_ai.storage import AuditStore

runner = CliRunner()
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def _seed_vulnerable_run(db_file: Path) -> str:
    vuln_target = f"file://{FIXTURES_DIR / 'ubuntu_vulnerable.raw'}"
    res = runner.invoke(app, ["scan", "--target", vuln_target, "--db", str(db_file), "--json"])
    assert res.exit_code == 2
    payload = json.loads(res.stdout)
    return str(payload["run_id"])


def test_cli_triage_missing_crew_extra_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "missing_crew.db"
    run_id = _seed_vulnerable_run(db_file)

    orig_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str, package: str | None = None) -> Any:
        if name == "crewai":
            return None
        return orig_find_spec(name, package)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    res = runner.invoke(app, ["triage", run_id, "--db", str(db_file)])
    assert res.exit_code == 1
    assert 'uv pip install "host-audit-ai[crew]"' in res.stderr


def test_cli_triage_dry_run_sanitizer_works_without_crew(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "dry_run.db"
    run_id = _seed_vulnerable_run(db_file)

    # Even if crewai is absent, --dry-run-sanitizer works cleanly in core mode
    orig_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str, package: str | None = None) -> Any:
        if name == "crewai":
            return None
        return orig_find_spec(name, package)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    res = runner.invoke(app, ["triage", run_id, "--db", str(db_file), "--dry-run-sanitizer"])
    assert res.exit_code == 0
    sanitized = json.loads(res.stdout)
    assert isinstance(sanitized, list)
    assert len(sanitized) >= 1
    for item in sanitized:
        assert set(item.keys()) == {
            "service_name",
            "package_version",
            "os_distro",
            "kernel_version",
            "rule_id",
            "cwe_id",
        }
        assert "vulnhost" not in json.dumps(item).lower()


def test_cli_triage_executes_pipeline_and_persists_to_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("CREWAI_STORAGE_DIR", "host-audit-ai-test")
    pytest.importorskip("crewai")

    from host_audit_ai.crew import pipeline as pipeline_mod

    db_file = tmp_path / "cli_triage.db"
    run_id = _seed_vulnerable_run(db_file)

    def fake_run_pipeline(report: Any, snapshot: Any, options: Any) -> TriageReport:
        assert snapshot is not None
        assert options.human_input is False
        assert options.enable_web_research is False
        return TriageReport(
            run_id=report.run_id,
            llm_model=options.llm_config.model,
            created_at=datetime.now(UTC),
            executive_summary="CLI mocked triage summary.",
        )

    monkeypatch.setattr(pipeline_mod, "run_triage_pipeline", fake_run_pipeline)

    res = runner.invoke(
        app,
        [
            "triage",
            run_id,
            "--db",
            str(db_file),
            "--no-web",
            "--no-human-input",
            "--json",
        ],
    )
    assert res.exit_code == 0, f"stderr={res.stderr}"
    assert "[host-audit] Saved triage run: triage-" in res.stderr
    parsed = TriageReport.model_validate_json(res.stdout)
    assert parsed.run_id == run_id
    assert parsed.executive_summary == "CLI mocked triage summary."

    with AuditStore(db_path=db_file) as store:
        stored = store.get_triage_runs(run_id)
        assert len(stored) == 1
        assert stored[0].executive_summary == "CLI mocked triage summary."
