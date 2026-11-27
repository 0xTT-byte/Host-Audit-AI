"""Filesystem permissions and cron scheduled tasks rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot


@RuleRegistry.register(
    RuleMeta(
        rule_id="FS-001",
        title="Shadow file permissions overly permissive or world-readable",
        default_severity=Severity.CRITICAL,
        category="filesystem",
        cis_ref="6.1.3",
        mitre_attack=["T1003.008"],
    )
)
def check_shadow_file_perms(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen_paths: set[str] = set()
    for perm in snapshot.file_permissions:
        if perm.path in ("/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-"):
            if perm.path in seen_paths:
                continue
            # Permissible modes: 0000, 0640, 0400, 0600
            mode_int = int(perm.permissions, 8) if perm.permissions.isdigit() else 0
            is_overly_permissive = (
                (mode_int & 0o007) != 0 or (mode_int & 0o044) == 0o044 or perm.is_world_writable
            )
            if is_overly_permissive or (mode_int > 0o640):
                seen_paths.add(perm.path)
                fp = compute_fingerprint("FS-001", perm.path, "permissive_shadow")
                findings.append(
                    Finding(
                        rule_id="FS-001",
                        title=f"Insecure permissions ({perm.permissions}) on {perm.path}",
                        severity=Severity.CRITICAL,
                        category="filesystem",
                        target=perm.path,
                        key_attribute="shadow_permissions",
                        expected="mode <= 0640 (root:shadow/root:root)",
                        actual=f"mode {perm.permissions} owned by {perm.owner}:{perm.group}",
                        evidence=[
                            Evidence(
                                source_section="critical_perms",
                                snippet=f"{perm.permissions} {perm.owner}:{perm.group} {perm.path}",
                                path=perm.path,
                            )
                        ],
                        cis_ref="6.1.3",
                        mitre_attack=["T1003.008"],
                        fingerprint=fp,
                    )
                )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="FS-002",
        title="Critical system configuration file is group or world-writable",
        default_severity=Severity.CRITICAL,
        category="filesystem",
        cis_ref="6.1.2",
        mitre_attack=["T1565.001"],
    )
)
def check_critical_config_writable(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    critical_files = {
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/group",
    }

    seen_paths: set[str] = set()
    for perm in snapshot.file_permissions:
        if perm.path in critical_files and perm.path not in seen_paths:
            mode_int = int(perm.permissions, 8) if perm.permissions.isdigit() else 0
            if (mode_int & 0o002) != 0 or perm.is_world_writable:
                seen_paths.add(perm.path)
                fp = compute_fingerprint("FS-002", perm.path, "world_writable_critical")
                findings.append(
                    Finding(
                        rule_id="FS-002",
                        title=(
                            f"Critical file '{perm.path}' is world-writable "
                            f"(mode {perm.permissions})"
                        ),
                        severity=Severity.CRITICAL,
                        category="filesystem",
                        target=perm.path,
                        key_attribute="world_writable",
                        expected="Not world-writable (mode <= 0644)",
                        actual=f"mode {perm.permissions}",
                        evidence=[
                            Evidence(
                                source_section="critical_perms",
                                snippet=f"{perm.permissions} {perm.path}",
                                path=perm.path,
                            )
                        ],
                        cis_ref="6.1.2",
                        mitre_attack=["T1565.001"],
                        fingerprint=fp,
                    )
                )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="FS-003",
        title="World-writable directory missing sticky bit",
        default_severity=Severity.MEDIUM,
        category="filesystem",
        cis_ref="1.1.21",
        mitre_attack=["T1565.001"],
    )
)
def check_world_writable_sticky_bit(
    snapshot: HostSnapshot, params: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    seen_paths: set[str] = set()
    for perm in snapshot.file_permissions:
        # If mode ends with 2, 3, 6, 7 and sticky bit (1xxx in octal) is absent
        if perm.is_world_writable and perm.path not in seen_paths:
            mode_int = int(perm.permissions, 8) if perm.permissions.isdigit() else 0
            # Sticky bit is 0o1000
            if (mode_int & 0o1000) == 0 and perm.path not in ("/proc", "/sys", "/dev"):
                seen_paths.add(perm.path)
                fp = compute_fingerprint("FS-003", perm.path, "missing_sticky_bit")
                findings.append(
                    Finding(
                        rule_id="FS-003",
                        title=f"World-writable directory '{perm.path}' missing sticky bit",
                        severity=Severity.MEDIUM,
                        category="filesystem",
                        target=perm.path,
                        key_attribute="missing_sticky_bit",
                        expected="Sticky bit enabled (mode 1777)",
                        actual=f"mode {perm.permissions}",
                        evidence=[
                            Evidence(
                                source_section="critical_perms",
                                snippet=f"{perm.permissions} {perm.path}",
                                path=perm.path,
                            )
                        ],
                        cis_ref="1.1.21",
                        mitre_attack=["T1565.001"],
                        fingerprint=fp,
                    )
                )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="CRN-001",
        title="Scheduled cron job references temporary directory or untrusted path",
        default_severity=Severity.HIGH,
        category="cron",
        cis_ref="5.1.8",
        mitre_attack=["T1053.003"],
    )
)
def check_cron_untrusted_paths(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    untrusted_prefixes = ("/tmp/", "/var/tmp/", "/dev/shm/")  # noqa: S108

    for cron in snapshot.cron_entries:
        for prefix in untrusted_prefixes:
            if prefix in cron.command:
                target = f"{cron.source_file}:{cron.user}"
                fp = compute_fingerprint("CRN-001", target, f"untrusted_cron:{prefix}")
                findings.append(
                    Finding(
                        rule_id="CRN-001",
                        title=f"Cron job executes from untrusted location ({prefix})",
                        severity=Severity.HIGH,
                        category="cron",
                        target=target,
                        key_attribute="untrusted_cron_path",
                        expected="Cron commands located in standard system paths (/usr, /etc)",
                        actual=cron.command,
                        evidence=[
                            Evidence(
                                source_section="cron",
                                snippet=(
                                    f"{cron.schedule} {cron.user} {cron.command} "
                                    f"(source: {cron.source_file})"
                                ),
                                path=cron.source_file,
                            )
                        ],
                        cis_ref="5.1.8",
                        mitre_attack=["T1053.003"],
                        fingerprint=fp,
                    )
                )
                break
    return findings
