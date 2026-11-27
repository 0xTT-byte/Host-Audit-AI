"""Top-level parser orchestrating all pure parsers into a HostSnapshot."""

from __future__ import annotations

from host_audit_ai.models.envelope import RawCollectorEnvelope
from host_audit_ai.models.snapshot import (
    FilePermCheck,
    HostMetadata,
    HostSnapshot,
    ListeningSocket,
    ParseWarning,
    ProcessEntry,
    UserAccount,
)
from host_audit_ai.parsers.containers_ioc import (
    parse_auth_logs,
    parse_containers,
    parse_ioc_surface,
)
from host_audit_ai.parsers.fs_perms import parse_file_perms, parse_suid_and_caps
from host_audit_ai.parsers.kernel_fw import parse_firewall, parse_sysctl
from host_audit_ai.parsers.network_procs import (
    parse_listening_sockets,
    parse_processes,
)
from host_audit_ai.parsers.os_meta import parse_os_meta
from host_audit_ai.parsers.packages import parse_packages
from host_audit_ai.parsers.services_cron import parse_cron, parse_systemd_units
from host_audit_ai.parsers.sshd import parse_sshd
from host_audit_ai.parsers.users_sudo import parse_sudoers, parse_users_passwd

EXPECTED_SECTIONS = [
    "os_release",
    "users_passwd",
    "users_group",
    "shadow_meta",
    "sudoers",
    "sshd_effective",
    "listening_sockets",
    "processes",
    "systemd_units",
    "cron",
    "suid_sgid",
    "critical_perms",
    "sysctl",
    "firewall",
    "packages",
    "containers",
    "auth_logs",
    "ioc_surface",
]


def parse_envelope(envelope: RawCollectorEnvelope) -> HostSnapshot:
    """Parse a RawCollectorEnvelope into a normalized, strongly-typed HostSnapshot.

    Emits typed ParseWarning entries for missing, truncated, or non-zero exit sections.
    Guaranteed pure: no network, no subprocesses, and no side-effects.
    """
    warnings: list[ParseWarning] = []

    # Check for missing sections or sections with warnings
    for sec_name in EXPECTED_SECTIONS:
        if sec_name not in envelope.sections:
            warnings.append(
                ParseWarning(
                    section_name=sec_name,
                    message=f"Expected section '{sec_name}' was not present in collector envelope",
                )
            )
        else:
            sec = envelope.sections[sec_name]
            if sec.truncated:
                warnings.append(
                    ParseWarning(
                        section_name=sec_name,
                        message=f"Section '{sec_name}' output exceeded size limit (truncated)",
                    )
                )
            if sec.exit_code != 0 and sec.stderr:
                warnings.append(
                    ParseWarning(
                        section_name=sec_name,
                        message=(
                            f"Section '{sec_name}' exited with code {sec.exit_code}: "
                            f"{sec.stderr.strip()[:100]}"
                        ),
                    )
                )

    # 1. OS Metadata
    os_sec = envelope.sections.get("os_release")
    meta = (
        parse_os_meta(os_sec.stdout, warnings)
        if os_sec
        else HostMetadata(hostname=envelope.hostname)
    )
    if meta.hostname in ("unknown", "") and envelope.hostname != "unknown":
        meta = HostMetadata(
            hostname=envelope.hostname,
            os_name=meta.os_name,
            os_version=meta.os_version,
            kernel_release=meta.kernel_release,
            architecture=meta.architecture,
            uptime_seconds=meta.uptime_seconds,
        )

    # 2. Users and Sudo
    users_sec = envelope.sections.get("users_passwd")
    users: list[UserAccount] = parse_users_passwd(users_sec.stdout, warnings) if users_sec else []

    sudo_sec = envelope.sections.get("sudoers")
    sudo_rules = parse_sudoers(sudo_sec.stdout, warnings) if sudo_sec else []

    # 3. SSH Daemon Config
    sshd_sec = envelope.sections.get("sshd_effective")
    sshd_cfg = parse_sshd(sshd_sec.stdout, warnings) if sshd_sec else None

    # 4. Networking and Processes
    net_sec = envelope.sections.get("listening_sockets")
    listeners: list[ListeningSocket] = (
        parse_listening_sockets(net_sec.stdout, warnings) if net_sec else []
    )

    proc_sec = envelope.sections.get("processes")
    processes: list[ProcessEntry] = parse_processes(proc_sec.stdout, warnings) if proc_sec else []

    # 5. Systemd Units and Cron
    sysd_sec = envelope.sections.get("systemd_units")
    services = parse_systemd_units(sysd_sec.stdout, warnings) if sysd_sec else []

    cron_sec = envelope.sections.get("cron")
    cron_entries = parse_cron(cron_sec.stdout, warnings) if cron_sec else []

    # 6. File Permissions, SUID Binaries, and Capabilities
    file_perms_by_path: dict[str, FilePermCheck] = {}
    for sec_key in ("shadow_meta", "critical_perms"):
        perm_sec = envelope.sections.get(sec_key)
        if perm_sec:
            for item in parse_file_perms(perm_sec.stdout, warnings):
                if item.path not in file_perms_by_path:
                    file_perms_by_path[item.path] = item
    file_perms = list(file_perms_by_path.values())

    suid_sec = envelope.sections.get("suid_sgid")
    suid_binaries, capabilities = (
        parse_suid_and_caps(suid_sec.stdout, warnings) if suid_sec else ([], [])
    )

    # 7. Sysctl and Firewall
    sysctl_sec = envelope.sections.get("sysctl")
    sysctl_entries = parse_sysctl(sysctl_sec.stdout, warnings) if sysctl_sec else []

    fw_sec = envelope.sections.get("firewall")
    firewall = parse_firewall(fw_sec.stdout, warnings) if fw_sec else None

    # 8. Packages
    pkg_sec = envelope.sections.get("packages")
    packages = parse_packages(pkg_sec.stdout, warnings) if pkg_sec else []

    # 9. Containers and IOC Surface
    container_sec = envelope.sections.get("containers")
    container_state = (
        parse_containers(container_sec.stdout, warnings)
        if container_sec
        else parse_containers("", warnings)
    )

    ioc_sec = envelope.sections.get("ioc_surface")
    ioc_surface = (
        parse_ioc_surface(ioc_sec.stdout, warnings) if ioc_sec else parse_ioc_surface("", warnings)
    )

    auth_sec = envelope.sections.get("auth_logs")
    auth_summary = parse_auth_logs(auth_sec.stdout, warnings) if auth_sec else None

    return HostSnapshot(
        schema_version="1.0.0",
        collected_at=envelope.collected_at,
        degraded_mode=envelope.degraded_mode,
        metadata=meta,
        users=users,
        sudo_rules=sudo_rules,
        sshd_config=sshd_cfg,
        listening_sockets=listeners,
        processes=processes,
        services=services,
        cron_entries=cron_entries,
        suid_binaries=suid_binaries,
        file_permissions=file_perms,
        sysctl_entries=sysctl_entries,
        firewall=firewall,
        packages=packages,
        containers=container_state,
        ioc=ioc_surface,
        capabilities=capabilities,
        auth_summary=auth_summary,
        parse_warnings=warnings,
    )
