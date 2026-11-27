"""Isolation tests for scoped SSH and Web MCP server parameter builders."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from host_audit_ai.crew.mcp_tools import (
    SSHServerConfig,
    build_ssh_server_params,
    build_web_server_params,
)


def test_mcp_server_params_are_strictly_separated(tmp_path: Path) -> None:
    pytest.importorskip("mcp")

    key = tmp_path / "audit_ed25519"
    key.write_text("dummy", encoding="utf-8")
    cfg = SSHServerConfig(
        target="ssh://audit@192.0.2.10:22",
        identity_file=key,
        known_hosts_policy="strict",
    )

    ssh_params = build_ssh_server_params(cfg)
    assert ssh_params.command == sys.executable
    assert ssh_params.args == ["-m", "host_audit_ai.mcp_servers.audit_ssh"]
    assert ssh_params.env["HOST_AUDIT_SSH_TARGET"] == "ssh://audit@192.0.2.10:22"
    assert ssh_params.env["HOST_AUDIT_SSH_IDENTITY"] == str(key)
    assert ssh_params.env["HOST_AUDIT_SSH_HOST_KEY_POLICY"] == "strict"

    web_params = build_web_server_params()
    assert len(web_params) == 2
    assert web_params[0].command == "uvx"
    assert "duckduckgo-mcp-server" in web_params[0].args
    assert web_params[1].command == "uvx"
    assert web_params[1].args == ["mcp-server-fetch"]

    # Zero SSH credentials or target env vars leak into web server params
    for wp in web_params:
        env = wp.env or {}
        assert "HOST_AUDIT_SSH_TARGET" not in env
        assert "HOST_AUDIT_SSH_IDENTITY" not in env
        assert "host_audit_ai.mcp_servers.audit_ssh" not in wp.args
