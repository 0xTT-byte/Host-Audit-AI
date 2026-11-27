"""Security execution tests for target-side host-audit-wrapper.sh via real bash."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

WRAPPER_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "host_audit_ai"
    / "collectors"
    / "scripts"
    / "host-audit-wrapper.sh"
)


def _run_wrapper(ssh_original_command: str) -> subprocess.CompletedProcess[str]:
    bash_bin = shutil.which("bash") or "/bin/bash"
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LC_ALL": "C",
        "SSH_ORIGINAL_COMMAND": ssh_original_command,
    }
    return subprocess.run(  # noqa: S603
        [bash_bin, str(WRAPPER_PATH)],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_wrapper_ping_succeeds() -> None:
    proc = _run_wrapper("ping")
    assert proc.returncode == 0
    assert proc.stdout.strip() == "host-audit-wrapper:ok"


def test_wrapper_check_binary_succeeds_on_real_binary() -> None:
    proc = _run_wrapper("check-binary /bin/sh")
    assert proc.returncode == 0
    assert "realpath:" in proc.stdout
    assert "stat:" in proc.stdout


@pytest.mark.parametrize(
    "malicious_cmd",
    [
        "",
        "inspect-unit sshd; id",
        "inspect-unit $(whoami)",
        "inspect-unit `id`",
        "inspect-unit sshd\nid",
        "read-config /etc/shadow 1 10",
        "read-config /etc/gshadow 1 10",
        "read-config /etc/sudoers 1 10",
        "read-config /etc/ssh/../shadow 1 10",
        "read-config /root/.ssh/id_ed25519 1 10",
        "read-config /etc/ssl/private/server.key 1 10",
        "read-config /etc/passwd 1 10",
        "read-config /etc/ssh/sshd_config 1 999",
        "read-config /etc/ssh/sshd_config 0 10",
        "bash",
        "cat /etc/passwd",
        "sh -c id",
        "check-port tcp 0",
        "check-port tcp 70000",
        "check-port tcp 22;id",
        "check-port icmp 22",
        "check-pkg bash|id",
        "check-binary /etc/../etc/passwd",
    ],
)
def test_wrapper_rejects_injection_and_disallowed_paths(malicious_cmd: str) -> None:
    proc = _run_wrapper(malicious_cmd)
    assert proc.returncode == 126
    assert "rejected" in proc.stderr.lower()


def test_wrapper_rejects_symlink_outside_allowlist(tmp_path: Path) -> None:
    # A symlink in tmp_path pointing to /etc/ssh/sshd_config has raw path outside allowlist,
    # and a symlink pointing to /etc/passwd resolves outside allowlist too.
    secret = tmp_path / "secret.txt"
    secret.write_text("top-secret", encoding="utf-8")
    link = tmp_path / "sshd.conf"
    link.symlink_to(secret)

    proc = _run_wrapper(f"read-config {link} 1 10")
    assert proc.returncode == 126
