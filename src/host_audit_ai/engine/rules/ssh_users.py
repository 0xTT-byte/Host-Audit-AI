"""SSH and user account hardening rules."""

from __future__ import annotations

from typing import Any

from host_audit_ai.engine.registry import RuleMeta, RuleRegistry
from host_audit_ai.models.finding import Evidence, Finding, Severity, compute_fingerprint
from host_audit_ai.models.snapshot import HostSnapshot

# ------------------------------------------------------------------------------
# SSH Rules
# ------------------------------------------------------------------------------


@RuleRegistry.register(
    RuleMeta(
        rule_id="SSH-001",
        title="Direct root SSH login is permitted",
        default_severity=Severity.HIGH,
        category="ssh",
        cis_ref="5.2.8",
        mitre_attack=["T1021.004", "T1078.003"],
    )
)
def check_ssh_permit_root_login(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.sshd_config is None:
        return findings

    allowed = params.get("allowed_root_login", ["no", "prohibit-password"])
    current = snapshot.sshd_config.permit_root_login.lower()

    if current not in allowed:
        fp = compute_fingerprint("SSH-001", "sshd_config", "PermitRootLogin")
        findings.append(
            Finding(
                rule_id="SSH-001",
                title=f"Root SSH login permitted ({current})",
                severity=Severity.HIGH,
                category="ssh",
                target="sshd:PermitRootLogin",
                key_attribute="PermitRootLogin",
                expected=f"one of {allowed}",
                actual=current,
                evidence=[
                    Evidence(
                        source_section="sshd_effective",
                        snippet=f"PermitRootLogin {current}",
                    )
                ],
                cis_ref="5.2.8",
                mitre_attack=["T1021.004", "T1078.003"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SSH-002",
        title="SSH password authentication is enabled",
        default_severity=Severity.HIGH,
        category="ssh",
        cis_ref="5.2.9",
        mitre_attack=["T1110.001"],
    )
)
def check_ssh_password_auth(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.sshd_config is None:
        return findings

    if snapshot.sshd_config.password_authentication:
        fp = compute_fingerprint("SSH-002", "sshd_config", "PasswordAuthentication")
        findings.append(
            Finding(
                rule_id="SSH-002",
                title="SSH password authentication is enabled",
                severity=Severity.HIGH,
                category="ssh",
                target="sshd:PasswordAuthentication",
                key_attribute="PasswordAuthentication",
                expected="no",
                actual="yes",
                evidence=[
                    Evidence(
                        source_section="sshd_effective",
                        snippet="PasswordAuthentication yes",
                    )
                ],
                cis_ref="5.2.9",
                mitre_attack=["T1110.001"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SSH-003",
        title="SSH empty passwords permitted",
        default_severity=Severity.CRITICAL,
        category="ssh",
        cis_ref="5.2.11",
        mitre_attack=["T1078.001"],
    )
)
def check_ssh_empty_passwords(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.sshd_config is None:
        return findings

    val = snapshot.sshd_config.raw_options.get("permitemptypasswords", "no").lower()
    if val in ("yes", "true", "1"):
        fp = compute_fingerprint("SSH-003", "sshd_config", "PermitEmptyPasswords")
        findings.append(
            Finding(
                rule_id="SSH-003",
                title="SSH empty passwords permitted",
                severity=Severity.CRITICAL,
                category="ssh",
                target="sshd:PermitEmptyPasswords",
                key_attribute="PermitEmptyPasswords",
                expected="no",
                actual=val,
                evidence=[
                    Evidence(
                        source_section="sshd_effective",
                        snippet=f"PermitEmptyPasswords {val}",
                    )
                ],
                cis_ref="5.2.11",
                mitre_attack=["T1078.001"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SSH-004",
        title="SSH MaxAuthTries exceeds security baseline",
        default_severity=Severity.MEDIUM,
        category="ssh",
        cis_ref="5.2.7",
        mitre_attack=["T1110"],
    )
)
def check_ssh_max_auth_tries(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.sshd_config is None:
        return findings

    threshold = int(params.get("max_auth_tries_threshold", 4))
    raw_val = snapshot.sshd_config.raw_options.get("maxauthtries")
    if raw_val and raw_val.isdigit():
        val = int(raw_val)
        if val > threshold:
            fp = compute_fingerprint("SSH-004", "sshd_config", "MaxAuthTries")
            findings.append(
                Finding(
                    rule_id="SSH-004",
                    title=f"SSH MaxAuthTries ({val}) exceeds threshold ({threshold})",
                    severity=Severity.MEDIUM,
                    category="ssh",
                    target="sshd:MaxAuthTries",
                    key_attribute="MaxAuthTries",
                    expected=f"<= {threshold}",
                    actual=str(val),
                    evidence=[
                        Evidence(
                            source_section="sshd_effective",
                            snippet=f"MaxAuthTries {val}",
                        )
                    ],
                    cis_ref="5.2.7",
                    mitre_attack=["T1110"],
                    fingerprint=fp,
                )
            )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SSH-005",
        title="SSH X11 or TCP forwarding enabled against baseline",
        default_severity=Severity.LOW,
        category="ssh",
        cis_ref="5.2.6",
        mitre_attack=["T1090"],
    )
)
def check_ssh_forwarding(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.sshd_config is None:
        return findings

    allow_x11 = params.get("allow_x11_forwarding", False)
    val_x11 = snapshot.sshd_config.raw_options.get("x11forwarding", "no").lower()
    if not allow_x11 and val_x11 in ("yes", "true", "1"):
        fp = compute_fingerprint("SSH-005", "sshd_config", "X11Forwarding")
        findings.append(
            Finding(
                rule_id="SSH-005",
                title="SSH X11Forwarding is enabled",
                severity=Severity.LOW,
                category="ssh",
                target="sshd:X11Forwarding",
                key_attribute="X11Forwarding",
                expected="no",
                actual=val_x11,
                evidence=[
                    Evidence(
                        source_section="sshd_effective",
                        snippet=f"X11Forwarding {val_x11}",
                    )
                ],
                cis_ref="5.2.6",
                mitre_attack=["T1090"],
                fingerprint=fp,
            )
        )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="SSH-006",
        title="Weak or deprecated SSH configuration option enabled",
        default_severity=Severity.HIGH,
        category="ssh",
        cis_ref="5.2.4",
        mitre_attack=["T1556"],
    )
)
def check_ssh_weak_options(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if snapshot.sshd_config is None:
        return findings

    raw = snapshot.sshd_config.raw_options
    # Protocol 1 or PermitUserEnvironment yes or UsePAM no
    if raw.get("protocol") == "1":
        fp = compute_fingerprint("SSH-006", "sshd_config", "Protocol")
        findings.append(
            Finding(
                rule_id="SSH-006",
                title="Deprecated SSH Protocol 1 enabled",
                severity=Severity.CRITICAL,
                category="ssh",
                target="sshd:Protocol",
                key_attribute="Protocol",
                expected="2",
                actual="1",
                evidence=[Evidence(source_section="sshd_effective", snippet="Protocol 1")],
                cis_ref="5.2.4",
                mitre_attack=["T1556"],
                fingerprint=fp,
            )
        )

    if raw.get("permituserenvironment", "no").lower() in ("yes", "true", "1"):
        fp = compute_fingerprint("SSH-006", "sshd_config", "PermitUserEnvironment")
        findings.append(
            Finding(
                rule_id="SSH-006",
                title="SSH PermitUserEnvironment is enabled",
                severity=Severity.HIGH,
                category="ssh",
                target="sshd:PermitUserEnvironment",
                key_attribute="PermitUserEnvironment",
                expected="no",
                actual="yes",
                evidence=[
                    Evidence(
                        source_section="sshd_effective",
                        snippet="PermitUserEnvironment yes",
                    )
                ],
                cis_ref="5.2.12",
                mitre_attack=["T1556"],
                fingerprint=fp,
            )
        )
    return findings


# ------------------------------------------------------------------------------
# User Account Rules
# ------------------------------------------------------------------------------


@RuleRegistry.register(
    RuleMeta(
        rule_id="USR-001",
        title="Non-root user account has superuser UID 0",
        default_severity=Severity.CRITICAL,
        category="identity",
        cis_ref="5.4.3",
        mitre_attack=["T1078.003"],
    )
)
def check_non_root_uid_zero(snapshot: HostSnapshot, params: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for user in snapshot.users:
        if user.uid == 0 and user.username != "root":
            fp = compute_fingerprint("USR-001", f"user:{user.username}", "uid_zero")
            findings.append(
                Finding(
                    rule_id="USR-001",
                    title=f"Non-root account '{user.username}' has UID 0 (root equivalent)",
                    severity=Severity.CRITICAL,
                    category="identity",
                    target=f"user:{user.username}",
                    key_attribute="uid",
                    expected="uid != 0",
                    actual="0",
                    evidence=[
                        Evidence(
                            source_section="users_passwd",
                            snippet=f"{user.username}:x:0:{user.gid}:{user.home}:{user.shell}",
                        )
                    ],
                    cis_ref="5.4.3",
                    mitre_attack=["T1078.003"],
                    fingerprint=fp,
                )
            )
    return findings


@RuleRegistry.register(
    RuleMeta(
        rule_id="USR-002",
        title="System service account has interactive login shell",
        default_severity=Severity.MEDIUM,
        category="identity",
        cis_ref="5.4.2",
        mitre_attack=["T1078.001"],
    )
)
def check_system_account_interactive_shell(
    snapshot: HostSnapshot, params: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    interactive_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/sh"}

    for user in snapshot.users:
        # System accounts: non-root with UID < 1000
        if 0 < user.uid < 1000 and user.shell in interactive_shells:
            fp = compute_fingerprint("USR-002", f"user:{user.username}", "shell")
            findings.append(
                Finding(
                    rule_id="USR-002",
                    title=(
                        f"System account '{user.username}' (UID {user.uid}) has interactive shell"
                    ),
                    severity=Severity.MEDIUM,
                    category="identity",
                    target=f"user:{user.username}",
                    key_attribute="shell",
                    expected="/usr/sbin/nologin or /bin/false",
                    actual=user.shell,
                    evidence=[
                        Evidence(
                            source_section="users_passwd",
                            snippet=f"{user.username}:x:{user.uid}:{user.gid}:{user.home}:{user.shell}",
                        )
                    ],
                    cis_ref="5.4.2",
                    mitre_attack=["T1078.001"],
                    fingerprint=fp,
                )
            )
    return findings
