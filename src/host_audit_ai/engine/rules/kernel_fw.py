"""Kernel hardening and host firewall rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot

# ------------------------------------------------------------------------------
# Firewall Rules
# ------------------------------------------------------------------------------


@RuleRegistry.register(
    RuleMeta(
        rule_id="FW-001",
        title="No active host firewall detected",
        default_severity=Severity.HIGH,
        category="firewall",
        cis_ref="3.5.1",
        mitre_attack=["T1562.004"],
    )
)
def check_firewall_active(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.firewall is None or not snapshot.firewall.active:
        fp = compute_fingerprint("FW-001", "firewall", "inactive")
        findings.append(
            Finding(
                rule_id="FW-001",
                title="Host firewall is inactive or unconfigured",
                severity=Severity.HIGH,
                category="firewall",
                target="firewall:status",
                key_attribute="active_firewall",
                expected="Active nftables, ufw, or iptables ruleset",
                actual="No active ruleset detected",
                evidence=[
                    Evidence(source_section="firewall", snippet="No active firewall rules found")
                ],
                cis_ref="3.5.1",
                mitre_attack=["T1562.004"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="FW-002",
        title="Docker firewall bypass detected via unrestricted DOCKER-USER chain",
        default_severity=Severity.HIGH,
        category="firewall",
        cis_ref="3.5.2",
        mitre_attack=["T1562.004"],
    )
)
def check_docker_firewall_bypass(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.firewall and snapshot.firewall.docker_user_bypasses:
        fp = compute_fingerprint("FW-002", "iptables:DOCKER-USER", "docker_bypass")
        findings.append(
            Finding(
                rule_id="FW-002",
                title="Docker container ports bypass host firewall (unrestricted DOCKER-USER)",
                severity=Severity.HIGH,
                category="firewall",
                target="iptables:DOCKER-USER",
                key_attribute="docker_user_bypass",
                expected="DOCKER-USER chain filters incoming container traffic",
                actual="-A DOCKER-USER -j RETURN (traffic bypasses host rules)",
                evidence=[
                    Evidence(
                        source_section="firewall",
                        snippet="iptables -S DOCKER-USER shows unconditional RETURN",
                    )
                ],
                cis_ref="3.5.2",
                mitre_attack=["T1562.004"],
                fingerprint=fp,
            )
        )
    return findings


# ------------------------------------------------------------------------------
# Kernel Hardening Rules (sysctl)
# ------------------------------------------------------------------------------


@RuleRegistry.register(
    RuleMeta(
        rule_id="SYS-001",
        title="Address Space Layout Randomization (ASLR) disabled or weak",
        default_severity=Severity.CRITICAL,
        category="kernel",
        cis_ref="1.5.1",
        mitre_attack=["T1564"],
    )
)
def check_aslr_enabled(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    sysctl_map = {entry.key: entry.value for entry in snapshot.sysctl_entries}
    val = sysctl_map.get("kernel.randomize_va_space")
    if val is not None and val.strip() != "2":
        fp = compute_fingerprint("SYS-001", "kernel.randomize_va_space", "aslr")
        findings.append(
            Finding(
                rule_id="SYS-001",
                title=f"ASLR disabled or suboptimal (kernel.randomize_va_space = {val})",
                severity=Severity.CRITICAL,
                category="kernel",
                target="kernel.randomize_va_space",
                key_attribute="aslr",
                expected="2 (full randomization)",
                actual=val.strip(),
                evidence=[
                    Evidence(
                        source_section="sysctl",
                        snippet=f"kernel.randomize_va_space = {val}",
                    )
                ],
                cis_ref="1.5.1",
                mitre_attack=["T1564"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SYS-002",
        title="Kernel pointer and dmesg restriction disabled",
        default_severity=Severity.MEDIUM,
        category="kernel",
        cis_ref="1.5.2",
        mitre_attack=["T1082"],
    )
)
def check_kernel_ptr_restrict(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    sysctl_map = {entry.key: entry.value for entry in snapshot.sysctl_entries}

    kptr = sysctl_map.get("kernel.kptr_restrict")
    if kptr is not None and kptr.strip() in ("0",):
        fp = compute_fingerprint("SYS-002", "kernel.kptr_restrict", "kptr")
        findings.append(
            Finding(
                rule_id="SYS-002",
                title="Kernel symbol pointers exposed to unprivileged users (kptr_restrict = 0)",
                severity=Severity.MEDIUM,
                category="kernel",
                target="kernel.kptr_restrict",
                key_attribute="kptr_restrict",
                expected="1 or 2",
                actual=kptr.strip(),
                evidence=[Evidence(source_section="sysctl", snippet="kernel.kptr_restrict = 0")],
                cis_ref="1.5.2",
                mitre_attack=["T1082"],
                fingerprint=fp,
            )
        )

    dmesg = sysctl_map.get("kernel.dmesg_restrict")
    if dmesg is not None and dmesg.strip() in ("0",):
        fp = compute_fingerprint("SYS-002", "kernel.dmesg_restrict", "dmesg")
        findings.append(
            Finding(
                rule_id="SYS-002",
                title="Kernel dmesg log buffer readable by unprivileged users (dmesg_restrict = 0)",
                severity=Severity.LOW,
                category="kernel",
                target="kernel.dmesg_restrict",
                key_attribute="dmesg_restrict",
                expected="1",
                actual=dmesg.strip(),
                evidence=[Evidence(source_section="sysctl", snippet="kernel.dmesg_restrict = 0")],
                cis_ref="1.5.2",
                mitre_attack=["T1082"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SYS-003",
        title="Core dumps of SUID programs enabled or ptrace unrestricted",
        default_severity=Severity.MEDIUM,
        category="kernel",
        cis_ref="1.5.3",
        mitre_attack=["T1055.008"],
    )
)
def check_suid_dumpable(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    sysctl_map = {entry.key: entry.value for entry in snapshot.sysctl_entries}

    dumpable = sysctl_map.get("fs.suid_dumpable")
    if dumpable is not None and dumpable.strip() != "0":
        fp = compute_fingerprint("SYS-003", "fs.suid_dumpable", "suid_dumpable")
        findings.append(
            Finding(
                rule_id="SYS-003",
                title=f"SUID process core dumps enabled (fs.suid_dumpable = {dumpable})",
                severity=Severity.MEDIUM,
                category="kernel",
                target="fs.suid_dumpable",
                key_attribute="suid_dumpable",
                expected="0",
                actual=dumpable.strip(),
                evidence=[
                    Evidence(source_section="sysctl", snippet=f"fs.suid_dumpable = {dumpable}")
                ],
                cis_ref="1.5.3",
                mitre_attack=["T1055.008"],
                fingerprint=fp,
            )
        )

    ptrace = sysctl_map.get("kernel.yama.ptrace_scope")
    if ptrace is not None and ptrace.strip() == "0":
        fp = compute_fingerprint("SYS-003", "kernel.yama.ptrace_scope", "ptrace_scope")
        findings.append(
            Finding(
                rule_id="SYS-003",
                title="Unrestricted ptrace allowed across processes (kernel.yama.ptrace_scope = 0)",
                severity=Severity.MEDIUM,
                category="kernel",
                target="kernel.yama.ptrace_scope",
                key_attribute="ptrace_scope",
                expected=">= 1",
                actual=ptrace.strip(),
                evidence=[
                    Evidence(source_section="sysctl", snippet="kernel.yama.ptrace_scope = 0")
                ],
                cis_ref="1.5.3",
                mitre_attack=["T1055.008"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SYS-004",
        title="IPv4 packet forwarding enabled against security baseline",
        default_severity=Severity.LOW,
        category="kernel",
        cis_ref="3.1.1",
        mitre_attack=["T1090"],
    )
)
def check_ip_forwarding(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    sysctl_map = {entry.key: entry.value for entry in snapshot.sysctl_entries}
    allow_forward = params.get("allow_ip_forward", False)

    fwd = sysctl_map.get("net.ipv4.ip_forward")
    if not allow_forward and fwd is not None and fwd.strip() == "1":
        fp = compute_fingerprint("SYS-004", "net.ipv4.ip_forward", "ip_forward")
        findings.append(
            Finding(
                rule_id="SYS-004",
                title="IPv4 packet forwarding enabled (net.ipv4.ip_forward = 1)",
                severity=Severity.LOW,
                category="kernel",
                target="net.ipv4.ip_forward",
                key_attribute="ip_forward",
                expected="0",
                actual="1",
                evidence=[Evidence(source_section="sysctl", snippet="net.ipv4.ip_forward = 1")],
                cis_ref="3.1.1",
                mitre_attack=["T1090"],
                fingerprint=fp,
            )
        )
    return findings
