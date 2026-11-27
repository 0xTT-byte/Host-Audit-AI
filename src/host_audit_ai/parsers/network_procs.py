"""Pure parser for network listening sockets and process table."""

from __future__ import annotations

import re

from host_audit_ai.models.snapshot import ListeningSocket, ParseWarning, ProcessEntry

WILD_ADDRESSES = {"0.0.0.0", "*", "::", "[::]", "0:0:0:0:0:0:0:0"}  # noqa: S104


def normalize_address(addr: str) -> str:
    """Normalize wildcard IPv4 and IPv6 addresses."""
    clean = addr.strip().strip("[]")
    if clean in ("0.0.0.0", "*"):  # noqa: S104
        return "0.0.0.0"  # noqa: S104
    if clean in ("::", "[::]", "0:0:0:0:0:0:0:0"):
        return "::"
    return clean


def parse_listening_sockets(raw_text: str, warnings: list[ParseWarning]) -> list[ListeningSocket]:
    """Parse ss -tulpnH or netstat -tulpn output into ListeningSocket list."""
    sockets: list[ListeningSocket] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith(("Netid", "Active", "Proto")):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue

        # In ss -tulpnH: Proto State Recv-Q Send-Q Local-Address:Port Peer-Address:Port [Process]
        # In netstat:   Proto Recv-Q Send-Q Local-Address Foreign-Address [State] [PID/Program]
        local_endpoint = ""
        for p in parts[3:6]:
            if ":" in p:
                local_endpoint = p
                break

        process_part = " ".join(
            tok for tok in parts[5:] if "users:(" in tok or "pid=" in tok or "/" in tok
        )

        if not local_endpoint or ":" not in local_endpoint:
            continue

        # Split host and port (handling IPv6 [::]:port or :::port)
        if local_endpoint.startswith("["):
            # e.g. [::]:22 or [fe80::1]:80
            match = re.match(r"^\[(.*?)\]:([0-9]+)$", local_endpoint)
            if match:
                raw_addr = match.group(1)
                port_str = match.group(2)
            else:
                continue
        elif local_endpoint.count(":") > 1:
            # e.g. :::22 or ::1:5432
            raw_addr, port_str = local_endpoint.rsplit(":", 1)
        else:
            raw_addr, port_str = local_endpoint.split(":", 1)

        try:
            port = int(port_str)
        except ValueError:
            continue

        addr = normalize_address(raw_addr)

        # Extract pid and process name from process_part
        pid: int | None = None
        pname: str | None = None
        if "users:(" in process_part or "pid=" in process_part:
            pid_match = re.search(r"pid=([0-9]+)", process_part)
            if pid_match:
                pid = int(pid_match.group(1))
            name_match = re.search(r'"([^"]+)"', process_part)
            if name_match:
                pname = name_match.group(1)
        elif "/" in process_part:
            # netstat format: 1234/program
            net_pid_str, _, net_name = process_part.partition("/")
            if net_pid_str.isdigit():
                pid = int(net_pid_str)
            pname = net_name.strip()

        sockets.append(
            ListeningSocket(
                protocol=proto[:3],  # 'tcp' or 'udp'
                local_address=addr,
                local_port=port,
                pid=pid,
                process_name=pname,
                interface=None,
            )
        )

    return sockets


def parse_processes(raw_text: str, warnings: list[ParseWarning]) -> list[ProcessEntry]:
    """Parse ps output into ProcessEntry list."""
    procs: list[ProcessEntry] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("UID"):
            continue

        parts = line.split(None, 6)
        if len(parts) < 6:
            continue

        try:
            pid = int(parts[0])
            ppid = int(parts[1]) if parts[1].isdigit() else None
        except ValueError:
            continue

        user = parts[2]
        cmd = parts[6] if len(parts) > 6 else parts[5]

        deleted_binary = "(deleted)" in cmd or "[deleted]" in cmd

        procs.append(
            ProcessEntry(
                pid=pid,
                ppid=ppid,
                user=user,
                command=cmd,
                deleted_binary=deleted_binary,
            )
        )

    return procs
