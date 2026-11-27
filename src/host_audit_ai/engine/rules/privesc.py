"""Privilege escalation and authorization rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot
from host_audit_ai.parsers.fs_perms import GTFOBINS

DANGEROUS_CAPS = {
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_dac_override",
    "cap_sys_ptrace",
    "cap_dac_read_search",
}


@RuleRegistry.register(
    RuleMeta(
        rule_id="PRV-001",
        title="Unrestricted NOPASSWD wildcard rule in sudoers",
        default_severity=Severity.CRITICAL,
        category="privesc",
        cis_ref="5.3.4",
        mitre_attack=["T1548.003"],
    )
)
def check_sudo_nopasswd_all(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in snapshot.sudo_rules:
        if rule.nopasswd:
            for cmd in rule.commands:
                cmd_clean = cmd.strip()
                if cmd_clean in ("ALL", "*", "(ALL) ALL", "(ALL:ALL) ALL"):
                    target = f"sudoers:{rule.user_or_group}"
                    fp = compute_fingerprint("PRV-001", target, "nopasswd_all")
                    snippet = f"{rule.user_or_group} ALL=({rule.run_as}) NOPASSWD: {cmd_clean}"
                    findings.append(
                        Finding(
                            rule_id="PRV-001",
                            title=f"Unrestricted NOPASSWD: ALL granted to '{rule.user_or_group}'",
                            severity=Severity.CRITICAL,
                            category="privesc",
                            target=target,
                            key_attribute="nopasswd_all",
                            expected="Password authentication required for privilege escalation",
                            actual=snippet,
                            evidence=[
                                Evidence(
                                    source_section="sudoers",
                                    snippet=snippet,
                                )
                            ],
                            cis_ref="5.3.4",
                            mitre_attack=["T1548.003"],
                            fingerprint=fp,
                        )
                    )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="PRV-002",
        title="Dangerous GTFOBins or shell binary granted in sudoers",
        default_severity=Severity.HIGH,
        category="privesc",
        cis_ref="5.3.5",
        mitre_attack=["T1548.003"],
    )
)
def check_sudo_gtfobins(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in snapshot.sudo_rules:
        for cmd in rule.commands:
            bin_name = cmd.split()[0].rsplit("/", 1)[-1] if cmd.split() else ""
            if bin_name in GTFOBINS:
                target = f"sudoers:{rule.user_or_group}"
                fp = compute_fingerprint("PRV-002", target, f"gtfobins:{bin_name}")
                findings.append(
                    Finding(
                        rule_id="PRV-002",
                        title=f"GTFOBins escape binary '{bin_name}' executable via sudo",
                        severity=Severity.HIGH,
                        category="privesc",
                        target=f"{target}:{bin_name}",
                        key_attribute="gtfobins_sudo",
                        expected=(
                            f"Restricted wrapper script or non-shell executable (found {bin_name})"
                        ),
                        actual=f"{rule.user_or_group} can execute {cmd}",
                        evidence=[
                            Evidence(
                                source_section="sudoers",
                                snippet=f"{rule.user_or_group} sudoers command: {cmd}",
                            )
                        ],
                        cis_ref="5.3.5",
                        mitre_attack=["T1548.003"],
                        fingerprint=fp,
                    )
                )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="PRV-003",
        title="Unexpected SUID or SGID binary present on filesystem",
        default_severity=Severity.HIGH,
        category="privesc",
        cis_ref="6.1.13",
        mitre_attack=["T1548.001"],
    )
)
def check_unexpected_suid(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    allowed_suid = set(
        params.get(
            "allowed_suid",
            [
                "/usr/bin/sudo",
                "/usr/bin/su",
                "/usr/bin/passwd",
                "/usr/bin/mount",
                "/usr/bin/umount",
                "/usr/bin/chfn",
                "/usr/bin/chsh",
                "/usr/bin/gpasswd",
                "/usr/bin/newgrp",
                "/usr/bin/pkexec",
            ],
        )
    )

    for suid in snapshot.suid_binaries:
        if suid.path not in allowed_suid:
            bin_name = suid.path.rsplit("/", 1)[-1]
            is_gtfo = suid.known_gtfobins or (bin_name in GTFOBINS)
            temp_dirs = ("/tmp", "/dev/shm", "/var/tmp", "/home")  # noqa: S108
            is_in_temp = any(suid.path.startswith(d) for d in temp_dirs)

            sev = Severity.CRITICAL if (is_gtfo or is_in_temp) else Severity.HIGH
            fp = compute_fingerprint("PRV-003", suid.path, "unexpected_suid")
            title_suffix = " (GTFOBins escape!)" if is_gtfo else ""
            findings.append(
                Finding(
                    rule_id="PRV-003",
                    title=f"Unexpected SUID binary '{suid.path}'{title_suffix}",
                    severity=sev,
                    category="privesc",
                    target=suid.path,
                    key_attribute="suid_binary",
                    expected="Binary in baseline allowlist",
                    actual=f"SUID mode {suid.permissions} owned by {suid.owner}",
                    evidence=[
                        Evidence(
                            source_section="suid_sgid",
                            snippet=f"{suid.permissions} {suid.owner} {suid.path}",
                            path=suid.path,
                        )
                    ],
                    cis_ref="6.1.13",
                    mitre_attack=["T1548.001"],
                    fingerprint=fp,
                )
            )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="PRV-004",
        title="Dangerous Linux file capability granted to binary",
        default_severity=Severity.HIGH,
        category="privesc",
        cis_ref="6.1.14",
        mitre_attack=["T1548.001"],
    )
)
def check_dangerous_capabilities(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for cap_entry in snapshot.capabilities:
        parts = cap_entry.split()
        if len(parts) >= 2:
            path = parts[0]
            caps = parts[1].lower()
            for dangerous in DANGEROUS_CAPS:
                if dangerous in caps:
                    fp = compute_fingerprint("PRV-004", path, f"dangerous_cap:{dangerous}")
                    findings.append(
                        Finding(
                            rule_id="PRV-004",
                            title=f"Dangerous capability '{dangerous}' granted to {path}",
                            severity=Severity.HIGH,
                            category="privesc",
                            target=path,
                            key_attribute="capability",
                            expected="Standard non-elevated capabilities",
                            actual=cap_entry,
                            evidence=[
                                Evidence(
                                    source_section="suid_sgid",
                                    snippet=cap_entry,
                                    path=path,
                                )
                            ],
                            cis_ref="6.1.14",
                            mitre_attack=["T1548.001"],
                            fingerprint=fp,
                        )
                    )
                    break
    return findings
