"""Tests for `host-audit init-target` key generation and wrapper provisioning."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from typer.testing import CliRunner

from host_audit_ai.cli import app

runner = CliRunner()


def test_cli_init_target_creates_bundle_and_protects_private_key(tmp_path: Path) -> None:
    key_path = tmp_path / "ssh" / "audit_ed25519"
    bundle_dir = tmp_path / "bundle"

    res = runner.invoke(
        app,
        [
            "init-target",
            "--key-path",
            str(key_path),
            "--out-dir",
            str(bundle_dir),
            "--from-cidr",
            "10.0.0.0/24",
            "--json",
        ],
    )
    assert res.exit_code == 0, res.stderr

    priv_contents = key_path.read_text(encoding="utf-8")
    assert "PRIVATE KEY" in priv_contents
    assert "PRIVATE KEY" not in res.stdout
    assert "PRIVATE KEY" not in (res.stderr or "")

    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    entry_file = bundle_dir / "authorized_keys.entry"
    wrapper_file = bundle_dir / "host-audit-wrapper.sh"
    assert entry_file.is_file()
    assert wrapper_file.is_file()

    entry_text = entry_file.read_text(encoding="utf-8").strip()
    expected_prefix = 'command="/usr/local/bin/host-audit-wrapper",restrict,from="10.0.0.0/24" '
    assert entry_text.startswith(expected_prefix)

    payload = json.loads(res.stdout)
    assert payload["wrapper_path"] == "/usr/local/bin/host-audit-wrapper"
    assert payload["authorized_keys_entry"] == entry_text

    # Refuses overwrite without --force
    res_dup = runner.invoke(
        app,
        ["init-target", "--key-path", str(key_path), "--json"],
    )
    assert res_dup.exit_code == 1

    # Succeeds with --force
    res_force = runner.invoke(
        app,
        ["init-target", "--key-path", str(key_path), "--force", "--json"],
    )
    assert res_force.exit_code == 0
