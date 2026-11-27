"""Tests for collector stream framing decoder and anti-spoofing security."""

from __future__ import annotations

import pytest

from host_audit_ai.collectors.framing import CollectorFramingError, decode_envelope


def test_decode_valid_multi_section() -> None:
    boundary = "a1b2c3d4e5f67890123456789abcdef0"
    raw_stream = f"""HOST_AUDIT_FORMAT=1.0.0
HOST_AUDIT_COLLECTOR_VERSION=0.2.0
HOST_AUDIT_BOUNDARY={boundary}
HOST_AUDIT_COLLECTED_AT=2026-11-24T18:00:00Z
HOST_AUDIT_HOSTNAME=srv-audit-01
HOST_AUDIT_EUID=0
==={boundary}:BEGIN:os_release:CMD=cat /etc/os-release===
NAME="Fedora Linux"
VERSION="45"
==={boundary}:STDERR:os_release===
==={boundary}:END:os_release:EXIT=0:TRUNCATED=0===
==={boundary}:BEGIN:listening_sockets:CMD=ss -tulpnH===
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
==={boundary}:STDERR:listening_sockets===
warning: ss truncated
==={boundary}:END:listening_sockets:EXIT=0:TRUNCATED=1===
""".encode()

    envelope = decode_envelope(raw_stream, target_uri="local")
    assert envelope.schema_version == "1.0.0"
    assert envelope.collector_version == "0.2.0"
    assert envelope.hostname == "srv-audit-01"
    assert envelope.euid == 0
    assert envelope.degraded_mode is False
    assert len(envelope.sections) == 2

    sec1 = envelope.sections["os_release"]
    assert sec1.name == "os_release"
    assert sec1.exit_code == 0
    assert 'NAME="Fedora Linux"' in sec1.stdout
    assert sec1.stderr == ""
    assert sec1.truncated is False

    sec2 = envelope.sections["listening_sockets"]
    assert sec2.name == "listening_sockets"
    assert "0.0.0.0:22" in sec2.stdout
    assert "warning: ss truncated" in sec2.stderr
    assert sec2.truncated is True


def test_anti_spoofing_delimiter_injection() -> None:
    """Ensure attacker stdout containing fake boundary markers never splits sections."""
    real_boundary = "realboundarytoken1234567890abcdef"
    fake_boundary = "fakeboundarytoken9999999999999999"

    raw_stream = f"""HOST_AUDIT_FORMAT=1.0.0
HOST_AUDIT_COLLECTOR_VERSION=0.2.0
HOST_AUDIT_BOUNDARY={real_boundary}
HOST_AUDIT_COLLECTED_AT=2026-11-24T18:00:00Z
HOST_AUDIT_HOSTNAME=compromised-host
HOST_AUDIT_EUID=1000
==={real_boundary}:BEGIN:processes:CMD=ps -ef===
root 1 0 /sbin/init
attacker 666 1 /tmp/evil --spoof="==={fake_boundary}:BEGIN:injected_sec:CMD=whoami==="
attacker 667 1 /tmp/evil --spoof="==={fake_boundary}:END:injected_sec:EXIT=0:TRUNCATED=0==="
attacker 668 1 /tmp/evil --spoof="HOST_AUDIT_FORMAT=1.0.0"
==={real_boundary}:STDERR:processes===
==={real_boundary}:END:processes:EXIT=0:TRUNCATED=0===
""".encode()

    envelope = decode_envelope(raw_stream, target_uri="local")
    assert envelope.degraded_mode is True  # euid == 1000
    assert len(envelope.sections) == 1
    assert "processes" in envelope.sections
    assert "injected_sec" not in envelope.sections

    proc_sec = envelope.sections["processes"]
    assert f"==={fake_boundary}:BEGIN:injected_sec:CMD=whoami===" in proc_sec.stdout
    assert "HOST_AUDIT_FORMAT=1.0.0" in proc_sec.stdout


def test_resilience_non_utf8_bytes() -> None:
    """Non-UTF8 byte sequences in collector output must not crash decoding."""
    boundary = "b1b2c3d4e5f67890123456789abcdef0"
    raw_stream = (
        (
            f"HOST_AUDIT_FORMAT=1.0.0\n"
            f"HOST_AUDIT_COLLECTOR_VERSION=0.2.0\n"
            f"HOST_AUDIT_BOUNDARY={boundary}\n"
            f"HOST_AUDIT_COLLECTED_AT=2026-11-24T18:00:00Z\n"
            f"HOST_AUDIT_HOSTNAME=non-utf8-host\n"
            f"HOST_AUDIT_EUID=0\n"
            f"==={boundary}:BEGIN:bad_bytes:CMD=raw===\n"
        ).encode()
        + b"raw binary: \x80\x81\xff\xfe in stdout\n"
        + (
            f"==={boundary}:STDERR:bad_bytes===\n"
            f"==={boundary}:END:bad_bytes:EXIT=1:TRUNCATED=0===\n"
        ).encode()
    )

    envelope = decode_envelope(raw_stream, target_uri="local")
    assert "bad_bytes" in envelope.sections
    sec = envelope.sections["bad_bytes"]
    assert "raw binary:" in sec.stdout
    assert sec.exit_code == 1


def test_framing_error_missing_header() -> None:
    boundary = "c1b2c3d4e5f67890123456789abcdef0"
    # Missing HOST_AUDIT_FORMAT
    raw_stream = f"""HOST_AUDIT_BOUNDARY={boundary}
==={boundary}:BEGIN:test:CMD=echo===
hello
==={boundary}:STDERR:test===
==={boundary}:END:test:EXIT=0:TRUNCATED=0===
""".encode()

    with pytest.raises(CollectorFramingError, match="HOST_AUDIT_FORMAT"):
        decode_envelope(raw_stream)


def test_framing_error_unclosed_section() -> None:
    boundary = "d1b2c3d4e5f67890123456789abcdef0"
    raw_stream = f"""HOST_AUDIT_FORMAT=1.0.0
HOST_AUDIT_BOUNDARY={boundary}
==={boundary}:BEGIN:unclosed_section:CMD=cat===
data that never ends
""".encode()

    with pytest.raises(CollectorFramingError, match="unclosed section 'unclosed_section'"):
        decode_envelope(raw_stream)


def test_framing_error_nested_begin_without_end() -> None:
    boundary = "e1b2c3d4e5f67890123456789abcdef0"
    raw_stream = f"""HOST_AUDIT_FORMAT=1.0.0
HOST_AUDIT_BOUNDARY={boundary}
==={boundary}:BEGIN:sec1:CMD=cat===
data
==={boundary}:BEGIN:sec2:CMD=cat===
more data
==={boundary}:STDERR:sec2===
==={boundary}:END:sec2:EXIT=0:TRUNCATED=0===
""".encode()

    with pytest.raises(CollectorFramingError, match="unclosed section 'sec1'"):
        decode_envelope(raw_stream)
