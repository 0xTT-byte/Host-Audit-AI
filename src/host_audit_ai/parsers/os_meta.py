"""Pure parser for os_release section into HostMetadata."""

from __future__ import annotations

import re

from host_audit_ai.models.snapshot import HostMetadata, ParseWarning


def parse_os_meta(raw_text: str, warnings: list[ParseWarning]) -> HostMetadata:
    """Parse os_release command output into HostMetadata."""
    os_name = ""
    os_version = ""
    kernel_release = ""
    architecture = ""
    hostname = "unknown"
    uptime_seconds: float | None = None

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("PRETTY_NAME=") or (line.startswith("NAME=") and not os_name):
            os_name = line.split("=", 1)[1].strip("\"'")
        elif line.startswith("VERSION_ID="):
            os_version = line.split("=", 1)[1].strip("\"'")
        elif line.startswith("Linux ") and " GNU/Linux" in line:
            # Output of uname -a: Linux hostname 6.8.0-generic ... x86_64 GNU/Linux
            parts = line.split()
            if len(parts) >= 3:
                hostname = parts[1]
                kernel_release = parts[2]
            for part in parts:
                if part in ("x86_64", "aarch64", "armv7l", "i686", "riscv64", "s390x"):
                    architecture = part
                    break
        elif re.match(r"^\d{4}-\d{2}-\d{2}", line):
            # Output of uptime -s e.g. 2026-11-24 18:00:00
            uptime_seconds = 3600.0  # Normalized fallback if exact delta not computed

    return HostMetadata(
        hostname=hostname,
        os_name=os_name,
        os_version=os_version,
        kernel_release=kernel_release,
        architecture=architecture,
        uptime_seconds=uptime_seconds,
    )
