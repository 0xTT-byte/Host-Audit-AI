"""Security and protocol tests for audit_ssh_core and audit_ssh MCP server."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from host_audit_ai.collectors.transport import SSHTarget
from host_audit_ai.mcp_servers.audit_ssh import READ_ONLY_TOOL_NAMES, create_audit_ssh_server
from host_audit_ai.mcp_servers.audit_ssh_core import (
    AuditSSHClient,
    validate_binary_path,
    validate_config_path,
    validate_package_name,
    validate_port,
    validate_unit_name,
)


@pytest.mark.parametrize(
    "unit",
    ["ssh.service", "sshd", "postgresql@16-main.service", "docker.socket"],
)
def test_validate_unit_name_accepts_valid(unit: str) -> None:
    assert validate_unit_name(unit) == unit


@pytest.mark.parametrize(
    "bad_unit",
    [
        "",
        "sshd; id",
        "sshd && whoami",
        "$(id)",
        "`id`",
        "sshd\nid",
        "sshd\x00",
        "../sshd",
        "sshd --help",
    ],
)
def test_validate_unit_name_rejects_injection(bad_unit: str) -> None:
    with pytest.raises(ValueError):
        validate_unit_name(bad_unit)


@pytest.mark.parametrize(
    "cfg_path",
    [
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d/99-hardening.conf",
        "/etc/crontab",
        "/etc/cron.d/daily-backup",
        "/etc/sysctl.conf",
        "/etc/sysctl.d/99-security.conf",
        "/etc/systemd/system/custom-app.service",
        "/etc/systemd/system/backup.timer",
        "/etc/ld.so.preload",
        "/etc/nftables.conf",
        "/etc/ufw/ufw.conf",
        "/etc/ufw/before.rules",
        "/etc/ufw/after.rules",
    ],
)
def test_validate_config_path_accepts_allowlist(cfg_path: str) -> None:
    assert validate_config_path(cfg_path) == cfg_path


@pytest.mark.parametrize(
    "bad_path",
    [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d/admin",
        "/etc/passwd",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssl/private/app.pem",
        "/root/.ssh/id_ed25519",
        "/etc/ssh/../shadow",
        "/etc/ssh//sshd_config",
        "/proc/1/environ",
        "/etc/ssh/sshd_config;id",
        "/etc/ssh/sshd_config\x00",
        "relative/path.conf",
    ],
)
def test_validate_config_path_rejects_sensitive_and_traversal(bad_path: str) -> None:
    with pytest.raises(ValueError):
        validate_config_path(bad_path)


@pytest.mark.parametrize(
    ("port", "proto"),
    [(22, "tcp"), (5353, "udp"), (65535, "TCP")],
)
def test_validate_port_valid(port: int, proto: str) -> None:
    norm_proto, norm_port = validate_port(port, proto)
    assert norm_proto in ("tcp", "udp")
    assert norm_port == port


@pytest.mark.parametrize(
    ("port", "proto"),
    [(0, "tcp"), (-1, "tcp"), (65536, "tcp"), (True, "tcp"), (22, "icmp"), (22, "tcp;id")],
)
def test_validate_port_invalid(port: int, proto: str) -> None:
    with pytest.raises(ValueError):
        validate_port(port, proto)


def test_validate_binary_and_package_paths() -> None:
    assert validate_binary_path("/usr/sbin/sshd") == "/usr/sbin/sshd"
    assert validate_package_name("openssh-server") == "openssh-server"

    with pytest.raises(ValueError):
        validate_binary_path("/usr/bin/../bin/sh")
    with pytest.raises(ValueError):
        validate_package_name("openssh-server;rm -rf /")


def test_audit_ssh_client_argv_and_truncation(tmp_path: Path) -> None:
    key = tmp_path / "audit_ed25519"
    key.write_text("dummy", encoding="utf-8")
    target = SSHTarget.from_uri("ssh://audit@10.0.0.5:2222")
    client = AuditSSHClient(
        target=target,
        identity_file=key,
        known_hosts_policy="strict",
        timeout_seconds=15,
        max_output_bytes=64,
    )

    argv = client.build_ssh_argv("inspect-unit ssh.service")
    assert "BatchMode=yes" in argv
    assert "IdentitiesOnly=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "-i" in argv and str(key) in argv
    assert "-p" in argv and "2222" in argv
    assert argv[-3:] == ["--", "audit@10.0.0.5", "inspect-unit ssh.service"]

    huge_output = "A" * 200
    fake_proc = subprocess.CompletedProcess(args=argv, returncode=0, stdout=huge_output, stderr="")
    with patch(
        "host_audit_ai.mcp_servers.audit_ssh_core.subprocess.run", return_value=fake_proc
    ) as m:
        res = client.read_config_snippet("/etc/ssh/sshd_config", start_line=1, max_lines=20)
        assert m.call_args.kwargs.get("shell", False) is False
        assert m.call_args.args[0][-1] == "read-config /etc/ssh/sshd_config 1 20"

    assert res.ok is True
    assert res.truncated is True
    assert len(res.stdout.encode("utf-8")) <= 64


def test_fastmcp_server_registers_only_six_readonly_tools(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    key = tmp_path / "audit_ed25519"
    key.write_text("dummy", encoding="utf-8")
    client = AuditSSHClient(target=SSHTarget.from_uri("ssh://audit@127.0.0.1"), identity_file=key)

    server = create_audit_ssh_server(client=client)
    tools = asyncio.run(server.list_tools())
    tool_names = [t.name for t in tools]
    assert set(tool_names) == set(READ_ONLY_TOOL_NAMES)
    assert len(tool_names) == 6
    assert "run_shell" not in tool_names
    assert "exec_command" not in tool_names
