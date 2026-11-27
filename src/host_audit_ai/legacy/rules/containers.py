import json
from pathlib import Path
from typing import Any
from host_audit.schema import Finding


def check_containers(collect_dir: Path, baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    inspect_file = collect_dir / "docker-inspect.json"
    if not inspect_file.exists():
        return findings

    raw_text = inspect_file.read_text(errors="replace").strip()
    if not raw_text:
        return findings

    # Strip any comment lines prepended by collector
    lines = [l for l in raw_text.splitlines() if not l.startswith("###")]
    try:
        containers = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return findings

    if not isinstance(containers, list):
        return findings

    c_cfg = baseline.get("containers", {})
    allowed_priv = set(c_cfg.get("allowed_privileged", []))
    allowed_host_net = set(c_cfg.get("allowed_host_network", []))
    allowed_sock = set(c_cfg.get("allowed_docker_sock", []))
    dangerous_caps = set(c_cfg.get("dangerous_caps", ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"]))
    sensitive_mounts = set(c_cfg.get("sensitive_mounts", ["/", "/etc", "/root", "/proc", "/var/run/docker.sock"]))

    for c in containers:
        if not isinstance(c, dict):
            continue

        name = c.get("Name", "").lstrip("/")
        host_cfg = c.get("HostConfig", {}) or {}
        config = c.get("Config", {}) or {}
        mounts = c.get("Mounts", []) or []

        # 1. Privileged mode
        if host_cfg.get("Privileged") is True and name not in allowed_priv:
            findings.append(
                Finding(
                    rule_id="CNT-001",
                    domain="containers",
                    title=f"Container '{name}' is running in --privileged mode",
                    target=f"container:{name}",
                    evidence=f'"Name": "/{name}", "Privileged": true',
                    why_it_matters="Privileged containers disable seccomp and AppArmor profiles and expose host devices (/dev), allowing simple host root breakout.",
                    verify_cmd=f"docker inspect --format '{{{{.HostConfig.Privileged}}}}' {name}",
                    remediation_hint="Remove 'privileged: true' from container configuration and grant only strictly required capabilities.",
                    reachability=2,
                    privilege_gain=3,
                    ease=3,
                )
            )

        # 2. Docker socket and sensitive host mounts
        seen_mount_targets: set[str] = set()

        for m in mounts:
            if not isinstance(m, dict):
                continue
            src = m.get("Source", "")
            if src == "/var/run/docker.sock" and name not in allowed_sock:
                target_key = f"container:{name}:docker.sock"
                seen_mount_targets.add(target_key)
                findings.append(
                    Finding(
                        rule_id="CNT-002",
                        domain="containers",
                        title=f"Container '{name}' mounts host Docker socket",
                        target=target_key,
                        evidence=json.dumps(m),
                        why_it_matters="Access to the Docker socket allows the container to communicate with the host Docker daemon, spin up privileged containers, and gain full host root.",
                        verify_cmd=f"docker inspect --format '{{{{json .Mounts}}}}' {name}",
                        remediation_hint="Avoid mounting /var/run/docker.sock; use an isolated API proxy or rootless containers if Docker access is necessary.",
                        reachability=2,
                        privilege_gain=3,
                        ease=3,
                    )
                )
            elif src in sensitive_mounts:
                target_key = f"container:{name}:{src}"
                seen_mount_targets.add(target_key)
                findings.append(
                    Finding(
                        rule_id="CNT-003",
                        domain="containers",
                        title=f"Container '{name}' bind-mounts sensitive host path '{src}'",
                        target=target_key,
                        evidence=json.dumps(m),
                        why_it_matters=f"Mounting host filesystem location '{src}' exposes sensitive files or configuration to containerized processes.",
                        verify_cmd=f"docker inspect --format '{{{{json .Mounts}}}}' {name}",
                        remediation_hint=f"Remove host bind mount for '{src}' and use a dedicated named volume.",
                        reachability=2,
                        privilege_gain=3,
                        ease=2,
                    )
                )

        # Also inspect HostConfig.Binds for formats like "/var/run/docker.sock:/var/run/docker.sock"
        binds = host_cfg.get("Binds") or []
        for b in binds:
            if not isinstance(b, str):
                continue
            src = b.split(":", 1)[0]
            if src == "/var/run/docker.sock" and name not in allowed_sock:
                target_key = f"container:{name}:docker.sock"
                if target_key not in seen_mount_targets:
                    seen_mount_targets.add(target_key)
                    findings.append(
                        Finding(
                            rule_id="CNT-002",
                            domain="containers",
                            title=f"Container '{name}' mounts host Docker socket",
                            target=target_key,
                            evidence=f'"Binds": {json.dumps(b)}',
                            why_it_matters="Access to the Docker socket allows the container to communicate with the host Docker daemon, spin up privileged containers, and gain full host root.",
                            verify_cmd=f"docker inspect --format '{{{{json .HostConfig.Binds}}}}' {name}",
                            remediation_hint="Avoid mounting /var/run/docker.sock; use an isolated API proxy or rootless containers if Docker access is necessary.",
                            reachability=2,
                            privilege_gain=3,
                            ease=3,
                        )
                    )
            elif src in sensitive_mounts:
                target_key = f"container:{name}:{src}"
                if target_key not in seen_mount_targets:
                    seen_mount_targets.add(target_key)
                    findings.append(
                        Finding(
                            rule_id="CNT-003",
                            domain="containers",
                            title=f"Container '{name}' bind-mounts sensitive host path '{src}'",
                            target=target_key,
                            evidence=f'"Binds": {json.dumps(b)}',
                            why_it_matters=f"Mounting host filesystem location '{src}' exposes sensitive files or configuration to containerized processes.",
                            verify_cmd=f"docker inspect --format '{{{{json .HostConfig.Binds}}}}' {name}",
                            remediation_hint=f"Remove host bind mount for '{src}' and use a dedicated named volume.",
                            reachability=2,
                            privilege_gain=3,
                            ease=2,
                        )
                    )

        # 3. Host network mode
        if host_cfg.get("NetworkMode") == "host" and name not in allowed_host_net:
            findings.append(
                Finding(
                    rule_id="CNT-004",
                    domain="containers",
                    title=f"Container '{name}' uses host network namespace",
                    target=f"container:{name}:net=host",
                    evidence='"NetworkMode": "host"',
                    why_it_matters="Host networking bypasses container network isolation, exposes container ports directly on host network interfaces, and enables traffic sniffing.",
                    verify_cmd=f"docker inspect --format '{{{{.HostConfig.NetworkMode}}}}' {name}",
                    remediation_hint="Use bridge network mode with specific published ports rather than host network mode.",
                    reachability=3,
                    privilege_gain=2,
                    ease=2,
                )
            )

        # 4. Dangerous capabilities
        added_caps = set(c_cap.upper() for c_cap in (host_cfg.get("CapAdd") or []))
        risky = added_caps.intersection({cap.upper() for cap in dangerous_caps})
        if risky:
            findings.append(
                Finding(
                    rule_id="CNT-005",
                    domain="containers",
                    title=f"Container '{name}' granted dangerous Linux capabilities: {', '.join(sorted(risky))}",
                    target=f"container:{name}:caps",
                    evidence=f'"CapAdd": {json.dumps(list(added_caps))}',
                    why_it_matters="High-risk capabilities like SYS_ADMIN, SYS_PTRACE, or DAC_OVERRIDE can be abused for namespace escapes and host inspection.",
                    verify_cmd=f"docker inspect --format '{{{{.HostConfig.CapAdd}}}}' {name}",
                    remediation_hint="Drop all capabilities ('cap_drop: [ALL]') and add back only the minimal set required for operation.",
                    reachability=2,
                    privilege_gain=3,
                    ease=2,
                )
            )

        # 5. Root user inside container
        user = str(config.get("User", "")).strip()
        if user in ("", "0", "root"):
            findings.append(
                Finding(
                    rule_id="CNT-006",
                    domain="containers",
                    title=f"Container '{name}' runs as root (UID 0)",
                    target=f"container:{name}:user",
                    evidence=f'"User": "{user}"',
                    why_it_matters="Running as root inside the container ensures that any application flaw provides the attacker with UID 0 within the container context.",
                    verify_cmd=f"docker exec {name} id 2>/dev/null || docker inspect --format '{{{{.Config.User}}}}' {name}",
                    remediation_hint="Define a non-privileged user in the Dockerfile (USER appuser) or specify 'user: 1000:1000' in compose.",
                    reachability=2,
                    privilege_gain=1,
                    ease=2,
                )
            )

    return findings
