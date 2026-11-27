"""Pure parser for container workloads, IOC surface, and auth logs."""

from __future__ import annotations

import json
import re

from host_audit_ai.models.snapshot import (
    AuthLogSummary,
    ContainerInstance,
    ContainerState,
    FilePermCheck,
    IocSurface,
    ParseWarning,
    ProcessEntry,
)


def parse_containers(raw_text: str, warnings: list[ParseWarning]) -> ContainerState:
    """Parse container socket status, process lists, and docker inspect output."""
    socket_paths: list[str] = []
    socket_permissions: list[FilePermCheck] = []
    containers: list[ContainerInstance] = []

    lines = raw_text.splitlines()
    in_inspect = False
    inspect_json_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped == "=== DOCKER INSPECT ===":
            in_inspect = True
            continue
        if in_inspect:
            if stripped.startswith("==="):
                in_inspect = False
            else:
                inspect_json_lines.append(line)
                continue

        # Socket permission lines e.g. srw-rw---- 1 root docker 0 Nov 24 /var/run/docker.sock
        if "/var/run/docker.sock" in stripped or "/run/podman/podman.sock" in stripped:
            parts = stripped.split()
            if len(parts) >= 8 and parts[0].startswith("s"):
                perms = parts[0]
                owner = parts[2]
                group = parts[3]
                path = parts[-1]
                socket_paths.append(path)
                socket_permissions.append(
                    FilePermCheck(
                        path=path,
                        permissions=perms,
                        owner=owner,
                        group=group,
                        is_world_writable="w" in perms[-3:],
                    )
                )

    # Parse docker inspect JSON if present
    if inspect_json_lines:
        inspect_raw = "\n".join(inspect_json_lines).strip()
        if inspect_raw.startswith("[") and inspect_raw.endswith("]"):
            try:
                inspect_data = json.loads(inspect_raw)
                if isinstance(inspect_data, list):
                    for item in inspect_data:
                        if not isinstance(item, dict):
                            continue
                        c_id = item.get("Id", "")[:12]
                        name = item.get("Name", "").lstrip("/")
                        config = item.get("Config", {}) or {}
                        host_config = item.get("HostConfig", {}) or {}

                        image = config.get("Image", "")
                        privileged = bool(host_config.get("Privileged", False))
                        net_mode = str(host_config.get("NetworkMode", ""))
                        pid_mode = str(host_config.get("PidMode", ""))
                        ipc_mode = str(host_config.get("IpcMode", ""))
                        caps_add = list(host_config.get("CapAdd") or [])

                        # Extract mounts
                        mounts: list[str] = []
                        binds = host_config.get("Binds") or []
                        for bind in binds:
                            if isinstance(bind, str):
                                mounts.append(bind.split(":")[0])

                        state_dict = item.get("State", {}) or {}
                        status = state_dict.get("Status", "running")

                        containers.append(
                            ContainerInstance(
                                id=c_id,
                                name=name,
                                image=image,
                                privileged=privileged,
                                network_mode=net_mode,
                                pid_mode=pid_mode,
                                ipc_mode=ipc_mode,
                                caps_add=caps_add,
                                mounts=mounts,
                                status=status,
                            )
                        )
            except Exception as e:
                warnings.append(
                    ParseWarning(
                        section_name="containers",
                        message=f"Failed to parse docker inspect JSON: {e}",
                    )
                )

    return ContainerState(
        socket_paths=socket_paths,
        socket_permissions=socket_permissions,
        running_containers=containers,
    )


def parse_ioc_surface(raw_text: str, warnings: list[ParseWarning]) -> IocSurface:
    """Parse IOC telemetry: deleted binary processes, ld.so.preload, and temp executables."""
    deleted_procs: list[ProcessEntry] = []
    ld_preload: str | None = None
    temp_executables: list[str] = []
    auth_keys: list[FilePermCheck] = []

    lines = raw_text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("===") or stripped.startswith("#"):
            continue

        # 1. Deleted binary execution e.g. ... /proc/1234/exe -> /tmp/miner (deleted)
        if "/proc/" in stripped and "deleted" in stripped:
            match = re.search(r"/proc/(\d+)/exe\s*->\s*(.+)", stripped)
            if match:
                pid = int(match.group(1))
                cmd = match.group(2).strip()
                deleted_procs.append(
                    ProcessEntry(
                        pid=pid,
                        user="unknown",
                        command=cmd,
                        deleted_binary=True,
                    )
                )

        # 2. Preload contents
        if line.startswith("/") and (".so" in line or "/lib" in line):
            ld_preload = line.strip()

        # 3. Executables in /tmp or /dev/shm
        if (stripped.startswith("-rwx") or stripped.startswith("-r-x")) and (
            "/tmp/" in stripped or "/dev/shm/" in stripped  # noqa: S108
        ):
            parts = stripped.split()
            if parts:
                temp_executables.append(parts[-1])

    return IocSurface(
        deleted_binary_processes=deleted_procs,
        ld_preload_contents=ld_preload,
        temp_executables=temp_executables,
        authorized_keys_files=auth_keys,
        capabilities=[],
    )


def parse_auth_logs(raw_text: str, warnings: list[ParseWarning]) -> AuthLogSummary:
    """Parse authentication logs for failed and successful logins."""
    failed = 0
    accepted = 0
    root_logins = 0

    for line in raw_text.splitlines():
        line_lower = line.lower()
        if "failed password" in line_lower or "authentication failure" in line_lower:
            failed += 1
            if "for root" in line_lower or "user=root" in line_lower:
                root_logins += 1
        elif "accepted password" in line_lower or "accepted publickey" in line_lower:
            accepted += 1
            if "for root" in line_lower:
                root_logins += 1

    return AuthLogSummary(
        failed_logins=failed,
        accepted_logins=accepted,
        root_logins=root_logins,
        summary_window="last_500_lines",
    )
