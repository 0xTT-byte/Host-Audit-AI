"""Defensive framing decoder for raw collector output."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from host_audit_ai.models.envelope import RawCollectorEnvelope, RawSection


class CollectorFramingError(Exception):
    """Raised when collector stream framing or header validation fails."""


def decode_envelope(raw_bytes: bytes, target_uri: str = "local") -> RawCollectorEnvelope:
    """Parse raw framed collector stdout into a validated RawCollectorEnvelope.

    Uses strict boundary-token parsing to prevent section delimiter injection.
    Non-UTF8 byte sequences are replaced to prevent ingestion crashes.
    """
    text = raw_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()

    headers: dict[str, str] = {}
    line_idx = 0

    # 1. Parse header block lines
    while line_idx < len(lines):
        line = lines[line_idx].strip()
        if not line:
            line_idx += 1
            continue
        if line.startswith("==="):
            break
        if "=" in line:
            k, v = line.split("=", 1)
            headers[k.strip()] = v.strip()
        line_idx += 1

    format_ver = headers.get("HOST_AUDIT_FORMAT")
    if format_ver != "1.0.0":
        raise CollectorFramingError(
            f"Unsupported or missing HOST_AUDIT_FORMAT: '{format_ver}' (expected '1.0.0')"
        )

    boundary = headers.get("HOST_AUDIT_BOUNDARY")
    if not boundary or any(c.isspace() for c in boundary):
        raise CollectorFramingError("Missing or invalid HOST_AUDIT_BOUNDARY in collector header")

    collector_version = headers.get("HOST_AUDIT_COLLECTOR_VERSION", "0.2.0")
    hostname = headers.get("HOST_AUDIT_HOSTNAME", "unknown")

    try:
        euid = int(headers.get("HOST_AUDIT_EUID", "1000"))
    except ValueError:
        euid = 1000

    degraded_mode = euid != 0

    collected_at_raw = headers.get("HOST_AUDIT_COLLECTED_AT")
    if collected_at_raw:
        try:
            collected_at = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
            if collected_at.tzinfo is None:
                collected_at = collected_at.replace(tzinfo=UTC)
            else:
                collected_at = collected_at.astimezone(UTC)
        except Exception:
            collected_at = datetime.now(UTC)
    else:
        collected_at = datetime.now(UTC)

    # 2. Strict section parsing using the exact per-run boundary token
    escaped_boundary = re.escape(boundary)
    begin_pattern = re.compile(rf"^==={escaped_boundary}:BEGIN:([^:\r\n]+):CMD=(.*?)===$")
    stderr_pattern = re.compile(rf"^==={escaped_boundary}:STDERR:([^:\r\n]+)===$")
    end_pattern = re.compile(
        rf"^==={escaped_boundary}:END:([^:\r\n]+):EXIT=([0-9]+):TRUNCATED=([01])===$"
    )

    sections: dict[str, RawSection] = {}
    current_sec: str | None = None
    current_cmd: str | None = None
    state: str = "OUTSIDE"
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    while line_idx < len(lines):
        line = lines[line_idx]

        begin_match = begin_pattern.match(line)
        stderr_match = stderr_pattern.match(line)
        end_match = end_pattern.match(line)

        if state == "OUTSIDE":
            if begin_match:
                current_sec = begin_match.group(1)
                current_cmd = begin_match.group(2)
                state = "IN_STDOUT"
                stdout_lines = []
                stderr_lines = []
        elif state == "IN_STDOUT":
            if stderr_match and stderr_match.group(1) == current_sec:
                state = "IN_STDERR"
            elif end_match and end_match.group(1) == current_sec:
                # Handle direct END if STDERR block was empty/skipped
                exit_code = int(end_match.group(2))
                truncated = end_match.group(3) == "1"
                if current_sec is not None:
                    sections[current_sec] = RawSection(
                        name=current_sec,
                        command=current_cmd,
                        exit_code=exit_code,
                        stdout="\n".join(stdout_lines),
                        stderr="",
                        truncated=truncated,
                    )
                state = "OUTSIDE"
                current_sec = None
                current_cmd = None
            elif begin_match:
                msg = (
                    f"Malformed stream: unclosed section '{current_sec}' "
                    f"before new BEGIN '{begin_match.group(1)}'"
                )
                raise CollectorFramingError(msg)
            else:
                stdout_lines.append(line)
        elif state == "IN_STDERR":
            if end_match and end_match.group(1) == current_sec:
                exit_code = int(end_match.group(2))
                truncated = end_match.group(3) == "1"
                if current_sec is not None:
                    sections[current_sec] = RawSection(
                        name=current_sec,
                        command=current_cmd,
                        exit_code=exit_code,
                        stdout="\n".join(stdout_lines),
                        stderr="\n".join(stderr_lines),
                        truncated=truncated,
                    )
                state = "OUTSIDE"
                current_sec = None
                current_cmd = None
            elif begin_match:
                msg = (
                    f"Malformed stream: unclosed section '{current_sec}' "
                    f"before new BEGIN '{begin_match.group(1)}'"
                )
                raise CollectorFramingError(msg)
            else:
                stderr_lines.append(line)

        line_idx += 1

    if state != "OUTSIDE":
        raise CollectorFramingError(
            f"Malformed stream: unclosed section '{current_sec}' at end of output"
        )

    return RawCollectorEnvelope(
        schema_version="1.0.0",
        collector_version=collector_version,
        collected_at=collected_at,
        hostname=hostname,
        target_uri=target_uri,
        euid=euid,
        degraded_mode=degraded_mode,
        sections=sections,
    )
