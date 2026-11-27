"""Transport layer for local, SSH, and offline collector execution."""

from __future__ import annotations

import importlib.resources
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import ValidationError

from host_audit_ai.collectors.framing import decode_envelope
from host_audit_ai.models.envelope import RawCollectorEnvelope


class CollectorTransportError(Exception):
    """Raised when transport execution or connection fails."""


def get_collector_script_bytes() -> bytes:
    """Retrieve bundled collect.sh script bytes via importlib.resources."""
    ref = importlib.resources.files("host_audit_ai.collectors.scripts").joinpath("collect.sh")
    return ref.read_bytes()


class CollectorTransport(Protocol):
    """Protocol defining the collector transport interface."""

    def collect(self) -> tuple[bytes, RawCollectorEnvelope]:
        """Execute or replay collector and return raw output plus decoded envelope."""
        ...


class LocalTransport:
    """Executes bundled collect.sh on the local host without writing temp files."""

    def __init__(self, timeout_seconds: int = 120) -> None:
        self.timeout_seconds = timeout_seconds

    def collect(self) -> tuple[bytes, RawCollectorEnvelope]:
        script_bytes = get_collector_script_bytes()
        bash_bin = shutil.which("bash") or "/bin/bash"
        try:
            proc = subprocess.run(  # noqa: S603
                [bash_bin, "-s"],
                input=script_bytes,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise CollectorTransportError(
                f"Local collection timed out after {self.timeout_seconds}s"
            ) from e
        except Exception as e:
            raise CollectorTransportError(f"Local collection execution failed: {e}") from e

        if proc.returncode != 0 and not proc.stdout:
            err_msg = proc.stderr.decode("utf-8", errors="replace")
            raise CollectorTransportError(
                f"Local collector failed with exit code {proc.returncode}: {err_msg}"
            )

        envelope = decode_envelope(proc.stdout, target_uri="local")
        return proc.stdout, envelope


@dataclass(frozen=True)
class SSHTarget:
    """Parsed and validated SSH connection target."""

    hostname: str
    username: str | None = None
    port: int | None = None

    @classmethod
    def from_uri(cls, uri: str) -> SSHTarget:
        """Parse ssh://[user@]host[:port] URI with strict security validation."""
        if not uri.startswith("ssh://"):
            raise ValueError(f"Invalid SSH URI scheme: '{uri}' (expected 'ssh://')")

        raw = uri[6:]
        username: str | None = None
        port: int | None = None

        if "@" in raw:
            username, raw = raw.split("@", 1)

        if ":" in raw:
            raw, port_str = raw.rsplit(":", 1)
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                raise ValueError(f"Invalid SSH port: '{port_str}'") from None

        hostname = raw
        if not hostname:
            raise ValueError("Missing hostname in SSH URI")

        # Anti-flag-injection validation
        is_bad_host = (
            hostname.startswith("-")
            or any(c.isspace() for c in hostname)
            or any(ord(c) < 32 for c in hostname)
        )
        if is_bad_host:
            raise ValueError(f"Invalid or unsafe SSH hostname: '{hostname}'")

        if username:
            is_bad_user = (
                username.startswith("-")
                or any(c.isspace() for c in username)
                or any(ord(c) < 32 for c in username)
            )
            if is_bad_user:
                raise ValueError(f"Invalid or unsafe SSH username: '{username}'")

        return cls(hostname=hostname, username=username, port=port)


class SSHTransport:
    """Streams collect.sh over SSH stdin (bash -s) to remote target host."""

    def __init__(
        self,
        target: SSHTarget,
        identity_file: Path | None = None,
        known_hosts_policy: Literal["strict", "accept-new"] = "strict",
        timeout_seconds: int = 120,
        extra_ssh_options: list[str] | None = None,
    ) -> None:
        self.target = target
        self.identity_file = identity_file
        self.known_hosts_policy = known_hosts_policy
        self.timeout_seconds = timeout_seconds
        self.extra_ssh_options = extra_ssh_options or []

    def build_ssh_command(self) -> list[str]:
        """Construct native OpenSSH command argument list."""
        ssh_bin = shutil.which("ssh") or "/usr/bin/ssh"
        cmd = [
            ssh_bin,
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
        ]
        if self.known_hosts_policy == "strict":
            cmd.extend(["-o", "StrictHostKeyChecking=yes"])
        else:
            cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])

        if self.identity_file is not None:
            cmd.extend(["-i", str(self.identity_file)])

        if self.target.port is not None:
            cmd.extend(["-p", str(self.target.port)])

        if self.extra_ssh_options:
            cmd.extend(self.extra_ssh_options)

        dest = (
            f"{self.target.username}@{self.target.hostname}"
            if self.target.username
            else self.target.hostname
        )
        cmd.extend(["--", dest, "bash", "-s"])
        return cmd

    def collect(self) -> tuple[bytes, RawCollectorEnvelope]:
        cmd = self.build_ssh_command()
        script_bytes = get_collector_script_bytes()
        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                input=script_bytes,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise CollectorTransportError(
                f"SSH collection timed out after {self.timeout_seconds}s for {self.target.hostname}"
            ) from e
        except Exception as e:
            raise CollectorTransportError(
                f"SSH command execution failed for {self.target.hostname}: {e}"
            ) from e

        if proc.returncode != 0 and not proc.stdout:
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
            raise CollectorTransportError(
                f"SSH collection failed (exit code {proc.returncode}): {err_msg}"
            )

        user_prefix = f"{self.target.username}@" if self.target.username else ""
        dest_uri = f"ssh://{user_prefix}{self.target.hostname}"
        if self.target.port:
            dest_uri += f":{self.target.port}"

        envelope = decode_envelope(proc.stdout, target_uri=dest_uri)
        return proc.stdout, envelope


class OfflineTransport:
    """Replays previously captured raw stream or serialized JSON envelope."""

    def __init__(self, input_path: Path) -> None:
        self.input_path = input_path

    def collect(self) -> tuple[bytes, RawCollectorEnvelope]:
        if not self.input_path.is_file():
            raise CollectorTransportError(f"Offline capture file not found: {self.input_path}")

        raw_bytes = self.input_path.read_bytes()
        target_uri = f"file://{self.input_path.resolve()}"

        stripped = raw_bytes.strip()
        if stripped.startswith(b"{"):
            try:
                envelope = RawCollectorEnvelope.model_validate_json(raw_bytes)
                return raw_bytes, envelope
            except (ValueError, ValidationError):
                # Fall back to stream decoder if json parsing fails
                pass

        envelope = decode_envelope(raw_bytes, target_uri=target_uri)
        return raw_bytes, envelope


def save_capture(
    raw_bytes: bytes,
    envelope: RawCollectorEnvelope,
    out_path: Path,
    fmt: Literal["envelope", "raw"] = "envelope",
) -> Path:
    """Save captured collector output to disk in either JSON envelope or raw format."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "envelope":
        out_path.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
    else:
        out_path.write_bytes(raw_bytes)
    return out_path
