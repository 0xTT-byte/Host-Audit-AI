"""Tests for the host-audit collect CLI command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from host_audit_ai.cli import app

runner = CliRunner()


def test_cli_collect_local_to_envelope_file(tmp_path: Path) -> None:
    out_file = tmp_path / "local_envelope.json"
    result = runner.invoke(
        app,
        ["collect", "--target", "local", "--out", str(out_file), "--format", "envelope"],
    )
    assert result.exit_code == 0
    assert out_file.is_file()
    assert "[host-audit] Host:" in result.stderr

    content = out_file.read_text(encoding="utf-8")
    assert '"schema_version": "1.0.0"' in content
    assert '"os_release"' in content


def test_cli_collect_local_to_raw_file(tmp_path: Path) -> None:
    raw_file = tmp_path / "local_capture.raw"
    result = runner.invoke(app, ["collect", "-t", "local", "-o", str(raw_file), "-f", "raw"])
    assert result.exit_code == 0
    assert raw_file.is_file()

    content = raw_file.read_text(encoding="utf-8")
    assert "HOST_AUDIT_FORMAT=1.0.0" in content
    assert "HOST_AUDIT_BOUNDARY=" in content


def test_cli_collect_replay_offline(tmp_path: Path) -> None:
    raw_file = tmp_path / "sample.raw"
    raw_file.write_text(
        "HOST_AUDIT_FORMAT=1.0.0\n"
        "HOST_AUDIT_COLLECTOR_VERSION=0.2.0\n"
        "HOST_AUDIT_BOUNDARY=testbound1234567890abcdef12345678\n"
        "HOST_AUDIT_COLLECTED_AT=2026-11-24T18:00:00Z\n"
        "HOST_AUDIT_HOSTNAME=replay-host\n"
        "HOST_AUDIT_EUID=0\n"
        "===testbound1234567890abcdef12345678:BEGIN:sample:CMD=echo===\n"
        "replay ok\n"
        "===testbound1234567890abcdef12345678:STDERR:sample===\n"
        "===testbound1234567890abcdef12345678:END:sample:EXIT=0:TRUNCATED=0===\n",
        encoding="utf-8",
    )

    out_json = tmp_path / "replayed.json"
    result = runner.invoke(app, ["collect", "-t", f"file://{raw_file}", "-o", str(out_json)])
    assert result.exit_code == 0
    assert out_json.is_file()
    assert "Host: replay-host" in result.stderr


def test_cli_collect_invalid_format() -> None:
    result = runner.invoke(app, ["collect", "--format", "invalid_fmt"])
    assert result.exit_code == 1
    assert "Error: Invalid format" in result.stderr


def test_cli_collect_invalid_target() -> None:
    result = runner.invoke(app, ["collect", "--target", "invalid://bad_target"])
    assert result.exit_code == 1
    assert "Error: Unsupported or non-existent target" in result.stderr
