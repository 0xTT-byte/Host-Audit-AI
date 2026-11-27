"""Tests for Local, SSH, and Offline collector transports."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from host_audit_ai.collectors.transport import (
    CollectorTransportError,
    LocalTransport,
    OfflineTransport,
    SSHTarget,
    SSHTransport,
    get_collector_script_bytes,
    save_capture,
)


def test_get_collector_script_bytes() -> None:
    script_bytes = get_collector_script_bytes()
    assert len(script_bytes) > 500
    assert b"HOST_AUDIT_BOUNDARY" in script_bytes
    assert b"#!/usr/bin/env bash" in script_bytes


def test_local_transport_execution() -> None:
    """Verify LocalTransport executes bundled script and captures local system state."""
    transport = LocalTransport(timeout_seconds=60)
    raw_bytes, envelope = transport.collect()

    assert len(raw_bytes) > 0
    assert envelope.schema_version == "1.0.0"
    assert envelope.collector_version == "0.2.0"
    assert envelope.hostname != ""
    assert envelope.target_uri == "local"

    # Core sections must be present
    required_sections = [
        "os_release",
        "users_passwd",
        "listening_sockets",
        "processes",
        "sysctl",
        "critical_perms",
        "packages",
        "shadow_meta",
    ]
    for sec_name in required_sections:
        assert sec_name in envelope.sections, f"Missing expected section: {sec_name}"

    # Critical security assertion: shadow_meta must NEVER leak password hashes ($6$, $y$, $2b$)
    shadow_meta_sec = envelope.sections["shadow_meta"]
    for forbidden_hash in ("$6$", "$y$", "$2b$", "$1$", "$5$"):
        assert forbidden_hash not in shadow_meta_sec.stdout
        assert forbidden_hash not in shadow_meta_sec.stderr


def test_ssh_target_parsing_and_security() -> None:
    # Valid targets
    t1 = SSHTarget.from_uri("ssh://user@audit.corp.net:2222")
    assert t1.hostname == "audit.corp.net"
    assert t1.username == "user"
    assert t1.port == 2222

    t2 = SSHTarget.from_uri("ssh://192.168.1.100")
    assert t2.hostname == "192.168.1.100"
    assert t2.username is None
    assert t2.port is None

    # Invalid schemes
    with pytest.raises(ValueError, match="Invalid SSH URI scheme"):
        SSHTarget.from_uri("http://target.com")

    # Anti-flag-injection validation
    with pytest.raises(ValueError, match="Invalid or unsafe SSH hostname"):
        SSHTarget.from_uri("ssh://-oProxyCommand=calc.exe")

    with pytest.raises(ValueError, match="Invalid or unsafe SSH hostname"):
        SSHTarget.from_uri("ssh://host name with spaces")

    with pytest.raises(ValueError, match="Invalid or unsafe SSH username"):
        SSHTarget.from_uri("ssh://-oProxy@hostname")


def test_ssh_transport_command_builder() -> None:
    target = SSHTarget(hostname="bastion.example.com", username="auditor", port=2200)
    identity = Path("/home/user/.ssh/id_ed25519")

    transport = SSHTransport(
        target=target,
        identity_file=identity,
        known_hosts_policy="accept-new",
        extra_ssh_options=["-o", "ForwardAgent=no"],
    )
    cmd = transport.build_ssh_command()

    assert cmd[0].endswith("ssh")
    assert "-T" in cmd
    assert "-o" in cmd and "BatchMode=yes" in cmd
    assert "-o" in cmd and "ConnectTimeout=15" in cmd
    assert "-o" in cmd and "StrictHostKeyChecking=accept-new" in cmd
    assert "-i" in cmd and str(identity) in cmd
    assert "-p" in cmd and "2200" in cmd
    assert "ForwardAgent=no" in cmd

    # Must terminate with '--', target, 'bash', '-s'
    dash_dash_idx = cmd.index("--")
    assert cmd[dash_dash_idx + 1] == "auditor@bastion.example.com"
    assert cmd[dash_dash_idx + 2] == "bash"
    assert cmd[dash_dash_idx + 3] == "-s"


def test_ssh_transport_mocked_execution() -> None:
    boundary = "11112222333344445555666677778888"
    mock_stdout = (
        f"HOST_AUDIT_FORMAT=1.0.0\n"
        f"HOST_AUDIT_COLLECTOR_VERSION=0.2.0\n"
        f"HOST_AUDIT_BOUNDARY={boundary}\n"
        f"HOST_AUDIT_COLLECTED_AT=2026-11-24T18:00:00Z\n"
        f"HOST_AUDIT_HOSTNAME=remote-srv\n"
        f"HOST_AUDIT_EUID=0\n"
        f"==={boundary}:BEGIN:os_release:CMD=cat===\n"
        f"Linux\n"
        f"==={boundary}:STDERR:os_release===\n"
        f"==={boundary}:END:os_release:EXIT=0:TRUNCATED=0===\n"
    ).encode()

    target = SSHTarget(hostname="remote-srv", username="admin")
    transport = SSHTransport(target=target)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout, stderr=b"")
        raw, envelope = transport.collect()

        assert envelope.hostname == "remote-srv"
        assert envelope.target_uri == "ssh://admin@remote-srv"
        assert "os_release" in envelope.sections


def test_ssh_transport_failure() -> None:
    target = SSHTarget(hostname="unreachable.test")
    transport = SSHTransport(target=target)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=255, stdout=b"", stderr=b"Connection refused")
        with pytest.raises(CollectorTransportError, match="SSH collection failed"):
            transport.collect()


def test_offline_transport_roundtrip(tmp_path: Path) -> None:
    boundary = "99998888777766665555444433332222"
    raw_content = (
        f"HOST_AUDIT_FORMAT=1.0.0\n"
        f"HOST_AUDIT_COLLECTOR_VERSION=0.2.0\n"
        f"HOST_AUDIT_BOUNDARY={boundary}\n"
        f"HOST_AUDIT_COLLECTED_AT=2026-11-24T18:00:00Z\n"
        f"HOST_AUDIT_HOSTNAME=offline-host\n"
        f"HOST_AUDIT_EUID=1000\n"
        f"==={boundary}:BEGIN:test:CMD=echo===\n"
        f"test output\n"
        f"==={boundary}:STDERR:test===\n"
        f"==={boundary}:END:test:EXIT=0:TRUNCATED=0===\n"
    ).encode()

    # Test raw format replay
    raw_file = tmp_path / "capture.raw"
    raw_file.write_bytes(raw_content)

    t_raw = OfflineTransport(input_path=raw_file)
    raw_bytes, envelope = t_raw.collect()
    assert envelope.hostname == "offline-host"
    assert envelope.degraded_mode is True
    assert "test" in envelope.sections

    # Test JSON envelope replay
    json_file = tmp_path / "capture.json"
    save_capture(raw_bytes, envelope, json_file, fmt="envelope")

    t_json = OfflineTransport(input_path=json_file)
    _, restored_envelope = t_json.collect()
    assert restored_envelope.hostname == "offline-host"
    assert restored_envelope.sections["test"].stdout == "test output"
