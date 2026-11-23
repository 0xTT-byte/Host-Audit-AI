import json
from pathlib import Path
from engine.schema import Finding


def check_containers(collect_dir: Path, baseline: dict) -> list[Finding]:
    findings: list[Finding] = []
    inspect_file = collect_dir / "docker-inspect.json"
    if not inspect_file.exists():
        return findings

    raw_text = inspect_file.read_text(errors="replace").strip()
    if not raw_text:
        return findings

    # Strip header line if collector prepended "### CMD:"
    lines = [l for l in raw_text.splitlines() if not l.startswith("###")]
    try:
        containers = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return findings

    c_cfg = baseline["containers"]
    allowed_priv = set(c_cfg["allowed_privileged"])
    allowed_host_net = set(c_cfg["allowed_host_network"])
    allowed_sock = set(c_cfg["allowed_docker_sock"])
    dangerous_caps = set(c_cfg["dangerous_caps"])
    sensitive_mounts = set(c_cfg["sensitive_mounts"])

    for c in containers:
        name = c.get("Name", "").lstrip("/")
        host_cfg = c.get("HostConfig", {})
        config = c.get("Config", {})
        mounts = c.get("Mounts", [])

        # 1. Privileged mode
        if host_cfg.get("Privileged") is True and name not in allowed_priv:
            findings.append(
                Finding(
                    rule_id="CNT-001",
                    domain="containers",
                    title=f"Container '{name}' is running in --privileged mode",
                    target=f"container:{name}",
                    evidence=f'"Name": "/{name}", "Privileged": true',
                    why_it_matters="Privileged containers disable seccomp/AppArmor and grant full device access, making container escape trivial.",
                    verify_cmd=f"docker inspect --format '{{{{.HostConfig.Privileged}}}}' {name}",
                    remediation_hint="Remove 'privileged: true' and grant only the specific Linux capabilities required.",
                    reachability=2,
                    privilege_gain=3,
                    ease=3,
                )
            )

        # 2. Docker socket mount
        for m in mounts:
            src = m.get("Source", "")
            if src == "/var/run/docker.sock" and name not in allowed_sock:
                findings.append(
                    Finding(
                        rule_id="CNT-002",
                        domain="containers",
                        title=f"Container '{name}' mounts the host Docker socket",
                        target=f"container:{name}:docker.sock",
                        evidence=json.dumps(m),
                        why_it_matters="Access to docker.sock allows spawning a privileged host-mounted container, which equals full root on the host.",
                        verify_cmd=f"docker inspect --format '{{{{json .Mounts}}}}' {name}",
                        remediation_hint="Remove /var/run/docker.sock mount or place a filtered Docker socket proxy (e.g., tecnativa/docker-socket-proxy) in front.",
                        reachability=2,
                        privilege_gain=3,
                        ease=3,
                    )
                )
            elif src in sensitive_mounts:
                findings.append(
                    Finding(
                        rule_id="CNT-003",
                        domain="containers",
                        title=f"Container '{name}' bind-mounts sensitive host path '{src}'",
                        target=f"container:{name}:{src}",
                        evidence=json.dumps(m),
                        why_it_matters=f"Mounting host '{src}' exposes host configuration, credentials, or filesystem control to the container.",
                        verify_cmd=f"docker inspect --format '{{{{json .Mounts}}}}' {name}",
                        remediation_hint=f"Replace host bind mount '{src}' with a named volume or a narrow sub-directory.",
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
                    why_it_matters="Bypasses Docker network isolation; all ports bound inside the container listen directly on host interfaces, and it can sniff host traffic.",
                    verify_cmd=f"docker inspect --format '{{{{.HostConfig.NetworkMode}}}}' {name}",
                    remediation_hint="Use a user-defined bridge network and publish only required ports.",
                    reachability=3,
                    privilege_gain=2,
                    ease=2,
                )
            )

        # 4. Dangerous capabilities
        added_caps = set(host_cfg.get("CapAdd") or [])
        risky = added_caps.intersection(dangerous_caps)
        if risky:
            findings.append(
                Finding(
                    rule_id="CNT-005",
                    domain="containers",
                    title=f"Container '{name}' granted high-risk capabilities: {', '.join(sorted(risky))}",
                    target=f"container:{name}:caps",
                    evidence=f'"CapAdd": {json.dumps(list(added_caps))}',
                    why_it_matters="Capabilities like SYS_ADMIN or SYS_PTRACE allow kernel-level operations or host process injection.",
                    verify_cmd=f"docker inspect --format '{{{{.HostConfig.CapAdd}}}}' {name}",
                    remediation_hint="Drop all capabilities with 'cap_drop: [ALL]' and add back only minimal required ones.",
                    reachability=2,
                    privilege_gain=3,
                    ease=2,
                )
            )

        # 5. Running as root inside container
        user = config.get("User", "")
        if user in ("", "0", "root"):
            findings.append(
                Finding(
                    rule_id="CNT-006",
                    domain="containers",
                    title=f"Container '{name}' runs as root (UID 0)",
                    target=f"container:{name}:user",
                    evidence=f'"User": "{user}"',
                    why_it_matters="If an attacker exploits the app inside the container, they immediately have root inside the container namespace.",
                    verify_cmd=f"docker exec {name} id",
                    remediation_hint="Specify a non-root UID/GID in Dockerfile (USER 1000:1000) or compose 'user:' directive.",
                    reachability=2,
                    privilege_gain=1,
                    ease=2,
                )
            )

    return findings