"""Container runtime and workload isolation rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot

DANGEROUS_MOUNTS = {"/", "/etc", "/root", "/proc", "/sys", "/var/run/docker.sock"}


@RuleRegistry.register(
    RuleMeta(
        rule_id="CNT-001",
        title="Container daemon socket is world-accessible or insecurely permitted",
        default_severity=Severity.CRITICAL,
        category="containers",
        cis_ref="2.1",
        mitre_attack=["T1068", "T1611"],
    )
)
def check_container_socket_perms(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for perm in snapshot.containers.socket_permissions:
        if perm.is_world_writable:
            fp = compute_fingerprint("CNT-001", perm.path, "world_writable_socket")
            findings.append(
                Finding(
                    rule_id="CNT-001",
                    title=(
                        f"Container daemon socket '{perm.path}' "
                        f"is world-writable ({perm.permissions})"
                    ),
                    severity=Severity.CRITICAL,
                    category="containers",
                    target=perm.path,
                    key_attribute="socket_world_writable",
                    expected="Mode 0660 owned by root:docker",
                    actual=f"Mode {perm.permissions} owned by {perm.owner}:{perm.group}",
                    evidence=[
                        Evidence(
                            source_section="containers",
                            snippet=f"{perm.permissions} {perm.owner}:{perm.group} {perm.path}",
                            path=perm.path,
                        )
                    ],
                    cis_ref="2.1",
                    mitre_attack=["T1068", "T1611"],
                    fingerprint=fp,
                )
            )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="CNT-002",
        title="Running container has privileged execution enabled (--privileged)",
        default_severity=Severity.CRITICAL,
        category="containers",
        cis_ref="5.4",
        mitre_attack=["T1611"],
    )
)
def check_container_privileged(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for c in snapshot.containers.running_containers:
        if c.privileged:
            fp = compute_fingerprint("CNT-002", f"container:{c.name}", "privileged")
            findings.append(
                Finding(
                    rule_id="CNT-002",
                    title=f"Container '{c.name}' running with --privileged flag",
                    severity=Severity.CRITICAL,
                    category="containers",
                    target=f"container:{c.name}",
                    key_attribute="privileged",
                    expected="privileged=False",
                    actual="privileged=True",
                    evidence=[
                        Evidence(
                            source_section="containers",
                            snippet=(
                                f"container: {c.name} ({c.id}) image: {c.image} Privileged=true"
                            ),
                        )
                    ],
                    cis_ref="5.4",
                    mitre_attack=["T1611"],
                    fingerprint=fp,
                )
            )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="CNT-003",
        title="Running container shares host namespace (PID, network, or IPC)",
        default_severity=Severity.HIGH,
        category="containers",
        cis_ref="5.9",
        mitre_attack=["T1611", "T1612"],
    )
)
def check_container_host_namespaces(
    snapshot: HostSnapshot, params: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    for c in snapshot.containers.running_containers:
        shared_ns: list[str] = []
        if c.network_mode.lower() == "host":
            shared_ns.append("host_network")
        if c.pid_mode.lower() == "host":
            shared_ns.append("host_pid")
        if c.ipc_mode.lower() == "host":
            shared_ns.append("host_ipc")

        if shared_ns:
            ns_tag = "_".join(shared_ns)
            fp = compute_fingerprint("CNT-003", f"container:{c.name}", f"shared_ns:{ns_tag}")
            findings.append(
                Finding(
                    rule_id="CNT-003",
                    title=f"Container '{c.name}' shares host namespaces ({', '.join(shared_ns)})",
                    severity=Severity.HIGH,
                    category="containers",
                    target=f"container:{c.name}",
                    key_attribute="host_namespaces",
                    expected="Isolated container namespaces",
                    actual=", ".join(shared_ns),
                    evidence=[
                        Evidence(
                            source_section="containers",
                            snippet=(
                                f"container: {c.name} net={c.network_mode} "
                                f"pid={c.pid_mode} ipc={c.ipc_mode}"
                            ),
                        )
                    ],
                    cis_ref="5.9",
                    mitre_attack=["T1611", "T1612"],
                    fingerprint=fp,
                )
            )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="CNT-004",
        title="Running container mounts sensitive host directory",
        default_severity=Severity.CRITICAL,
        category="containers",
        cis_ref="5.12",
        mitre_attack=["T1611"],
    )
)
def check_container_sensitive_mounts(
    snapshot: HostSnapshot, params: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    allowed_mounts = set(params.get("allowed_mounts", []))

    for c in snapshot.containers.running_containers:
        for mount in c.mounts:
            if mount in DANGEROUS_MOUNTS and mount not in allowed_mounts:
                fp = compute_fingerprint(
                    "CNT-004", f"container:{c.name}:{mount}", "sensitive_mount"
                )
                findings.append(
                    Finding(
                        rule_id="CNT-004",
                        title=f"Container '{c.name}' mounts sensitive host path '{mount}'",
                        severity=Severity.CRITICAL,
                        category="containers",
                        target=f"container:{c.name}:{mount}",
                        key_attribute="sensitive_mount",
                        expected="Isolated container filesystem without sensitive host binds",
                        actual=f"Mounts host directory {mount}",
                        evidence=[
                            Evidence(
                                source_section="containers",
                                snippet=f"container: {c.name} bind mount: {mount}",
                            )
                        ],
                        cis_ref="5.12",
                        mitre_attack=["T1611"],
                        fingerprint=fp,
                    )
                )
    return findings
