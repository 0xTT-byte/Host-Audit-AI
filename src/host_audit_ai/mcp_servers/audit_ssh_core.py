"""Pure argument validators, allowlists, and SSH runner for the audit-ssh MCP server.

This module uses only Python stdlib, Pydantic, and core collector models so that
all security validation and SSH command-construction tests run without `mcp` or `crewai`.
"""

from __future__ import annotations

import posixpath
import re
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from host_audit_ai.collectors.transport import SSHTarget

_SHELL_META_RE = re.compile(r"[;|&$`()<>\\'\"*{}\[\]~!]")
_UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")
_ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9._/+@-]{1,256}$")
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9.+_-]{1,128}$")

_EXACT_ALLOWED_CONFIG_PATHS = frozenset(
    {
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/sysctl.conf",
        "/etc/ld.so.preload",
        "/etc/nftables.conf",
        "/etc/ufw/ufw.conf",
        "/etc/ufw/before.rules",
        "/etc/ufw/after.rules",
    }
)

_ALLOWED_CONFIG_REGEXES = (
    re.compile(r"^/etc/ssh/sshd_config\.d/[A-Za-z0-9._-]+\.conf$"),
    re.compile(r"^/etc/cron\.d/[A-Za-z0-9._-]+$"),
    re.compile(r"^/etc/sysctl\.d/[A-Za-z0-9._-]+\.conf$"),
    re.compile(r"^/etc/systemd/system/[A-Za-z0-9@._-]+\.(service|timer)$"),
)

_DENIED_PREFIXES = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/proc/",
    "/sys/",
    "/dev/",
)


class ToolInspectionResult(BaseModel):
    """Structured output returned by read-only audit-ssh inspection verbs."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    verb: str
    stdout: str
    stderr: str
    exit_code: int
    truncated: bool = False


def _assert_safe_token(value: str, field_name: str) -> str:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{field_name} contains disallowed control or newline characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{field_name} contains disallowed control characters")
    if any(ch.isspace() for ch in value):
        raise ValueError(f"{field_name} must not contain whitespace")
    if ".." in value:
        raise ValueError(f"{field_name} must not contain '..'")
    if _SHELL_META_RE.search(value):
        raise ValueError(f"{field_name} contains disallowed shell metacharacters")
    return value


def validate_unit_name(unit_name: str) -> str:
    """Validate a systemd unit name strictly against allowlist characters."""
    clean = _assert_safe_token(unit_name, "unit_name")
    if not _UNIT_NAME_RE.fullmatch(clean):
        raise ValueError(f"Invalid systemd unit name: '{unit_name}'")
    return clean


def validate_config_path(path: str) -> str:
    """Validate a read-only config path against explicit allowlist and denylist."""
    clean = _assert_safe_token(path, "path")
    if not _ABS_PATH_RE.fullmatch(clean):
        raise ValueError(f"Invalid config path syntax: '{path}'")

    normalized = posixpath.normpath(clean)
    if normalized != clean or ".." in normalized:
        raise ValueError(f"Non-canonical config path rejected: '{path}'")

    for prefix in _DENIED_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix):
            raise ValueError(f"Access denied to sensitive path: '{normalized}'")

    if normalized.endswith((".key", ".pem")) or re.search(r"/id_[^/]+$", normalized):
        raise ValueError(f"Access denied to private key path: '{normalized}'")

    if normalized in _EXACT_ALLOWED_CONFIG_PATHS:
        return normalized
    if any(pattern.fullmatch(normalized) for pattern in _ALLOWED_CONFIG_REGEXES):
        return normalized

    raise ValueError(f"Config path is outside the read-only allowlist: '{normalized}'")


def validate_binary_path(path: str) -> str:
    """Validate an absolute filesystem path for binary permission/capability inspection."""
    clean = _assert_safe_token(path, "path")
    if not _ABS_PATH_RE.fullmatch(clean):
        raise ValueError(f"Invalid binary path syntax: '{path}'")
    normalized = posixpath.normpath(clean)
    if normalized != clean or ".." in normalized:
        raise ValueError(f"Non-canonical binary path rejected: '{path}'")
    return normalized


def validate_port(port: int, proto: str = "tcp") -> tuple[str, int]:
    """Validate protocol (tcp|udp) and port number (1..65535)."""
    clean_proto = _assert_safe_token(proto.lower(), "proto")
    if clean_proto not in ("tcp", "udp"):
        raise ValueError(f"Protocol must be 'tcp' or 'udp', got '{proto}'")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Port must be an integer between 1 and 65535, got '{port}'")
    return clean_proto, port


def validate_package_name(package_name: str) -> str:
    """Validate a distro package name for read-only version inspection."""
    clean = _assert_safe_token(package_name, "package_name")
    if not _PKG_NAME_RE.fullmatch(clean):
        raise ValueError(f"Invalid package name: '{package_name}'")
    return clean


def _truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return text, False
    sliced = raw[:max_bytes].decode("utf-8", errors="ignore")
    return sliced, True


class AuditSSHClient:
    """Hardened read-only SSH client invoking only forced-command wrapper verbs."""

    def __init__(
        self,
        target: SSHTarget,
        identity_file: Path,
        known_hosts_policy: Literal["strict", "accept-new"] = "strict",
        timeout_seconds: int = 20,
        max_output_bytes: int = 32768,
    ) -> None:
        self.target = target
        self.identity_file = identity_file.expanduser()
        self.known_hosts_policy = known_hosts_policy
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def build_ssh_argv(self, remote_command: str) -> list[str]:
        """Construct OpenSSH argv with BatchMode, IdentitiesOnly, and strict host-key policy."""
        ssh_bin = shutil.which("ssh") or "/usr/bin/ssh"
        host_key_mode = "yes" if self.known_hosts_policy == "strict" else "accept-new"
        argv = [
            ssh_bin,
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"StrictHostKeyChecking={host_key_mode}",
            "-i",
            str(self.identity_file),
        ]
        if self.target.port is not None:
            argv.extend(["-p", str(self.target.port)])

        dest = (
            f"{self.target.username}@{self.target.hostname}"
            if self.target.username
            else self.target.hostname
        )
        argv.extend(["--", dest, remote_command])
        return argv

    def _run_verb(self, verb: str, remote_command: str) -> ToolInspectionResult:
        argv = self.build_ssh_argv(remote_command)
        try:
            proc = subprocess.run(  # noqa: S603
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolInspectionResult(
                ok=False,
                verb=verb,
                stdout="",
                stderr=f"SSH inspection timed out after {self.timeout_seconds}s",
                exit_code=124,
                truncated=False,
            )
        except OSError as e:
            return ToolInspectionResult(
                ok=False,
                verb=verb,
                stdout="",
                stderr=f"SSH execution error: {e}",
                exit_code=1,
                truncated=False,
            )

        stdout_capped, trunc_out = _truncate_utf8(proc.stdout or "", self.max_output_bytes)
        stderr_capped, trunc_err = _truncate_utf8(proc.stderr or "", self.max_output_bytes)
        return ToolInspectionResult(
            ok=proc.returncode == 0,
            verb=verb,
            stdout=stdout_capped,
            stderr=stderr_capped,
            exit_code=proc.returncode,
            truncated=trunc_out or trunc_err,
        )

    def ping(self) -> ToolInspectionResult:
        """Check connectivity to the target-side host-audit-wrapper."""
        return self._run_verb("ping", "ping")

    def inspect_unit(self, unit_name: str) -> ToolInspectionResult:
        """Inspect status and unit definition of a systemd unit."""
        clean_unit = validate_unit_name(unit_name)
        return self._run_verb("inspect-unit", f"inspect-unit {clean_unit}")

    def read_config_snippet(
        self, path: str, start_line: int = 1, max_lines: int = 80
    ) -> ToolInspectionResult:
        """Read a bounded line slice from an allowlisted configuration file."""
        clean_path = validate_config_path(path)
        if isinstance(start_line, bool) or not isinstance(start_line, int) or start_line < 1:
            raise ValueError("start_line must be an integer >= 1")
        if (
            isinstance(max_lines, bool)
            or not isinstance(max_lines, int)
            or not (1 <= max_lines <= 120)
        ):
            raise ValueError("max_lines must be an integer between 1 and 120")
        return self._run_verb("read-config", f"read-config {clean_path} {start_line} {max_lines}")

    def check_binary_perms(self, path: str) -> ToolInspectionResult:
        """Inspect realpath, stat permissions, and Linux capabilities of a binary."""
        clean_path = validate_binary_path(path)
        return self._run_verb("check-binary", f"check-binary {clean_path}")

    def check_listening_process(self, port: int, proto: str = "tcp") -> ToolInspectionResult:
        """Inspect local listener sockets bound to a specific port and protocol."""
        clean_proto, clean_port = validate_port(port, proto=proto)
        return self._run_verb("check-port", f"check-port {clean_proto} {clean_port}")

    def check_package_version(self, package_name: str) -> ToolInspectionResult:
        """Query installed package version using target package manager."""
        clean_pkg = validate_package_name(package_name)
        return self._run_verb("check-pkg", f"check-pkg {clean_pkg}")
