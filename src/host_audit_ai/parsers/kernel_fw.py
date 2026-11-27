"""Pure parser for sysctl settings and firewall rulesets."""

from __future__ import annotations

from host_audit_ai.models.snapshot import FirewallState, ParseWarning, SysctlEntry


def parse_sysctl(raw_text: str, warnings: list[ParseWarning]) -> list[SysctlEntry]:
    """Parse sysctl key-value lines into SysctlEntry list."""
    entries: list[SysctlEntry] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" in line:
            k, v = line.split("=", 1)
            entries.append(SysctlEntry(key=k.strip(), value=v.strip()))
        elif ":" in line:
            k, v = line.split(":", 1)
            entries.append(SysctlEntry(key=k.strip(), value=v.strip()))

    return entries


def parse_firewall(raw_text: str, warnings: list[ParseWarning]) -> FirewallState:
    """Parse firewall ruleset output (nftables, ufw, iptables) into FirewallState."""
    backend = "none"
    active = False
    rules_summary: list[str] = []
    docker_user_bypasses = False

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    # Check backend and activity
    if any("=== NFTABLE RULESET ===" in line for line in lines):
        backend = "nftables"
    elif any("=== UFW STATUS ===" in line for line in lines):
        backend = "ufw"
    elif any("=== IPTABLES" in line for line in lines):
        backend = "iptables"

    section = ""
    docker_user_lines: list[str] = []
    ufw_inactive = False
    has_active_filter = False

    for line in lines:
        if line == "=== NFTABLE RULESET ===":
            section = "nft"
            continue
        if line == "=== UFW STATUS ===":
            section = "ufw"
            continue
        if line == "=== IPTABLES RULES ===":
            section = "iptables"
            continue
        if line == "=== IPTABLES DOCKER-USER CHAIN ===":
            section = "docker_user"
            continue
        if line.startswith("==="):
            section = ""
            continue

        if section == "docker_user":
            docker_user_lines.append(line)
            continue

        rules_summary.append(line)
        if section == "ufw":
            if line.lower().startswith("status: inactive"):
                ufw_inactive = True
            elif line.lower().startswith("status: active"):
                has_active_filter = True
        elif section == "nft":
            has_active_filter = True
        elif section == "iptables":
            if line.startswith(("-P INPUT DROP", "-P INPUT REJECT")) or (
                line.startswith("-A ") and not line.startswith("-A DOCKER")
            ):
                has_active_filter = True
        else:
            # Generic fallback when headers aren't present
            if not line.startswith("Status: inactive"):
                has_active_filter = True

    active = has_active_filter and not (backend == "ufw" and ufw_inactive)
    rules_summary = [line for line in rules_summary if not line.startswith("Status: inactive")][:50]

    if docker_user_lines and len(docker_user_lines) == 1 and "-j RETURN" in docker_user_lines[0]:
        # e.g. "-A DOCKER-USER -j RETURN" with no prior DROP or state check
        docker_user_bypasses = True

    return FirewallState(
        backend=backend,
        active=active,
        rules_summary=rules_summary,
        docker_user_bypasses=docker_user_bypasses,
    )
