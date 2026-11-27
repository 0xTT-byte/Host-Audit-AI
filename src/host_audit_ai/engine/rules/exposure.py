"""Network exposure rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot

CRITICAL_SERVICE_PORTS = {
    2375: "docker (unencrypted)",
    2376: "docker daemon",
    3306: "mysql",
    3307: "mysql",
    5432: "postgresql",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


@RuleRegistry.register(
    RuleMeta(
        rule_id="EXP-001",
        title="Unexpected public listener bound to wildcard interface",
        default_severity=Severity.MEDIUM,
        category="exposure",
        cis_ref="3.1.1",
        mitre_attack=["T1046", "T1043"],
    )
)
def check_unexpected_wildcard_listener(
    snapshot: HostSnapshot, params: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    allowed_ports = set(params.get("allowed_public_ports", [22, 80, 443]))
    critical_ports = set(params.get("critical_ports", list(CRITICAL_SERVICE_PORTS.keys())))

    for sock in snapshot.listening_sockets:
        # Wildcard bind: 0.0.0.0 or ::
        if sock.local_address in ("0.0.0.0", "::"):  # noqa: S104
            # If port is critical, handled by EXP-002
            if sock.local_port in critical_ports:
                continue
            if sock.local_port not in allowed_ports:
                endpoint = f"{sock.local_address}:{sock.local_port}"
                fp = compute_fingerprint("EXP-001", endpoint, f"wildcard_listener:{sock.protocol}")
                findings.append(
                    Finding(
                        rule_id="EXP-001",
                        title=(
                            f"Unexpected public listener on port {sock.local_port}/{sock.protocol}"
                        ),
                        severity=Severity.MEDIUM,
                        category="exposure",
                        target=endpoint,
                        key_attribute="listener",
                        expected=f"Port in {sorted(allowed_ports)} or bound to loopback",
                        actual=f"{sock.protocol.upper()} listening on {endpoint}",
                        evidence=[
                            Evidence(
                                source_section="listening_sockets",
                                snippet=(
                                    f"{sock.protocol} {endpoint} "
                                    f"(proc: {sock.process_name or 'unknown'})"
                                ),
                            )
                        ],
                        cis_ref="3.1.1",
                        mitre_attack=["T1046", "T1043"],
                        fingerprint=fp,
                    )
                )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="EXP-002",
        title="Critical datastore or admin service exposed publicly on wildcard interface",
        default_severity=Severity.CRITICAL,
        category="exposure",
        cis_ref="3.1.2",
        mitre_attack=["T1190", "T1046"],
    )
)
def check_critical_service_exposed(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    critical_ports = set(params.get("critical_ports", list(CRITICAL_SERVICE_PORTS.keys())))

    for sock in snapshot.listening_sockets:
        if sock.local_address in ("0.0.0.0", "::") and sock.local_port in critical_ports:  # noqa: S104
            svc_name = CRITICAL_SERVICE_PORTS.get(sock.local_port, f"port {sock.local_port}")
            endpoint = f"{sock.local_address}:{sock.local_port}"
            fp = compute_fingerprint(
                "EXP-002", endpoint, f"critical_service_exposed:{sock.protocol}"
            )
            findings.append(
                Finding(
                    rule_id="EXP-002",
                    title=f"Critical service ({svc_name}) exposed on wildcard interface",
                    severity=Severity.CRITICAL,
                    category="exposure",
                    target=endpoint,
                    key_attribute="critical_exposure",
                    expected="Bound to 127.0.0.1 or restricted private interface",
                    actual=f"Listening on {endpoint}",
                    evidence=[
                        Evidence(
                            source_section="listening_sockets",
                            snippet=f"{sock.protocol} {endpoint} ({svc_name})",
                        )
                    ],
                    cis_ref="3.1.2",
                    mitre_attack=["T1190", "T1046"],
                    fingerprint=fp,
                )
            )
    return findings
