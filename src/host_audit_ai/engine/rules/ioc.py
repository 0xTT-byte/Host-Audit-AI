"""Indicators of compromise (IOC) and runtime anomaly rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot


@RuleRegistry.register(
    RuleMeta(
        rule_id="IOC-001",
        title="Running process executing deleted binary on disk",
        default_severity=Severity.HIGH,
        category="ioc",
        cis_ref="6.2.1",
        mitre_attack=["T1070.004", "T1059"],
    )
)
def check_deleted_binary_execution(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for proc in snapshot.ioc.deleted_binary_processes:
        fp = compute_fingerprint("IOC-001", f"proc:{proc.pid}:{proc.command}", "deleted_binary")
        findings.append(
            Finding(
                rule_id="IOC-001",
                title=(
                    f"Running process PID {proc.pid} executes "
                    f"deleted binary on disk: {proc.command}"
                ),
                severity=Severity.HIGH,
                category="ioc",
                target=f"proc:{proc.pid}",
                key_attribute="deleted_binary",
                expected="Process executes from existing registered binary",
                actual=f"/proc/{proc.pid}/exe -> {proc.command} (deleted)",
                evidence=[
                    Evidence(
                        source_section="ioc_surface",
                        snippet=f"/proc/{proc.pid}/exe -> {proc.command} (deleted)",
                    )
                ],
                cis_ref="6.2.1",
                mitre_attack=["T1070.004", "T1059"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="IOC-002",
        title="Shared library preload hook configured via /etc/ld.so.preload",
        default_severity=Severity.CRITICAL,
        category="ioc",
        cis_ref="6.2.2",
        mitre_attack=["T1574.006"],
    )
)
def check_ld_preload(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.ioc.ld_preload_contents:
        fp = compute_fingerprint("IOC-002", "/etc/ld.so.preload", "ld_so_preload")
        findings.append(
            Finding(
                rule_id="IOC-002",
                title=(
                    "Global LD_PRELOAD library rootkit hook active: "
                    f"{snapshot.ioc.ld_preload_contents}"
                ),
                severity=Severity.CRITICAL,
                category="ioc",
                target="/etc/ld.so.preload",
                key_attribute="ld_preload",
                expected="Empty or non-existent /etc/ld.so.preload",
                actual=snapshot.ioc.ld_preload_contents,
                evidence=[
                    Evidence(
                        source_section="ioc_surface",
                        snippet=f"/etc/ld.so.preload: {snapshot.ioc.ld_preload_contents}",
                        path="/etc/ld.so.preload",
                    )
                ],
                cis_ref="6.2.2",
                mitre_attack=["T1574.006"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="IOC-003",
        title="Executable file staged in temporary or shared memory directory",
        default_severity=Severity.HIGH,
        category="ioc",
        cis_ref="6.2.3",
        mitre_attack=["T1059", "T1027"],
    )
)
def check_temp_executable_staging(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for exec_path in snapshot.ioc.temp_executables:
        fp = compute_fingerprint("IOC-003", exec_path, "temp_executable")
        findings.append(
            Finding(
                rule_id="IOC-003",
                title=f"Executable file staged in temporary directory: {exec_path}",
                severity=Severity.HIGH,
                category="ioc",
                target=exec_path,
                key_attribute="temp_executable",
                expected="No executable binaries staged in /tmp or /dev/shm",
                actual=f"Executable staged at {exec_path}",
                evidence=[
                    Evidence(
                        source_section="ioc_surface",
                        snippet=f"Executable file: {exec_path}",
                        path=exec_path,
                    )
                ],
                cis_ref="6.2.3",
                mitre_attack=["T1059", "T1027"],
                fingerprint=fp,
            )
        )
    return findings
