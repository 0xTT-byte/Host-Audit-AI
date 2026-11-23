import re
from pathlib import Path
from typing import Any
from host_audit.schema import Finding

CRITICAL_PORTS = {
    "5432": "postgres",
    "3306": "mysql",
    "3307": "mysql",
    "6379": "redis-server",
    "27017": "mongod",
    "2375": "dockerd",
    "2376": "dockerd",
    "9100": "node_exporter",
    "8080": "cadvisor",
}


def check_exposure(collect_dir: Path, baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    net_cfg = baseline.get("network", {})
    listen_public_allowed = set(net_cfg.get("listen_public", []))
    critical_services = set(net_cfg.get("critical_services", []))

    # 1. Parse net-listen.txt (ss -tulpnH)
    net_file = collect_dir / "net-listen.txt"
    if net_file.exists():
        for line in net_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("###"):
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0].lower()  # tcp, udp
            if proto not in ("tcp", "udp"):
                continue

            # In ss -tulpnH:
            # col 0: proto (tcp/udp)
            # col 1: state (LISTEN, UNCONN, etc.)
            # col 2: recv-q
            # col 3: send-q
            # col 4: local address:port
            state = parts[1].upper()
            if proto == "tcp" and state != "LISTEN":
                continue

            local_addr_col = parts[4]
            port = None
            is_public = False

            # Check for public wildcards: 0.0.0.0, [::], *, :::
            if local_addr_col.startswith("0.0.0.0:") or local_addr_col.startswith("*:") or local_addr_col.startswith(":::"):
                is_public = True
                port = local_addr_col.rsplit(":", 1)[-1]
            elif local_addr_col.startswith("[::]:") or local_addr_col.startswith("[*]:"):
                is_public = True
                port = local_addr_col.rsplit(":", 1)[-1]
            elif local_addr_col.startswith("*."):
                is_public = True
                port = local_addr_col.rsplit(".", 1)[-1]

            if not is_public or not port or not port.isdigit():
                continue

            # Extract process name from users:(("proc",pid=...,fd=...))
            proc_match = re.search(r'users:\(\("?([^",]+)"?', line)
            proc_name = proc_match.group(1) if proc_match else "unknown"

            # Fallback to well-known critical ports if process name was masked
            if proc_name == "unknown" and port in CRITICAL_PORTS:
                proc_name = CRITICAL_PORTS[port]

            port_id = f"{port}/{proto}"

            if port_id not in listen_public_allowed:
                # Check if it is a critical service
                is_critical = any(cs in proc_name.lower() for cs in critical_services) or (port in CRITICAL_PORTS)

                if is_critical:
                    findings.append(
                        Finding(
                            rule_id="EXP-002",
                            domain="exposure",
                            title=f"Critical service '{proc_name}' exposed on public interface ({port_id})",
                            target=f"port:{port_id}:{proc_name}",
                            evidence=line,
                            why_it_matters=f"High-risk service '{proc_name}' is accessible to untrusted networks, increasing attack surface for brute force or unauthenticated exploitation.",
                            verify_cmd=f"ss -tulpnH | grep -E ':{port}\\b'",
                            remediation_hint=f"Bind {proc_name} to 127.0.0.1 or an internal private interface, or block port {port} at the firewall.",
                            reachability=3,
                            privilege_gain=3,
                            ease=3,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            rule_id="EXP-001",
                            domain="exposure",
                            title=f"Unexpected public listener: {port_id} ({proc_name})",
                            target=f"port:{port_id}",
                            evidence=line,
                            why_it_matters=f"Service '{proc_name}' listening on 0.0.0.0/:: is not declared in the baseline network policy.",
                            verify_cmd=f"ss -tulpnH | grep -E ':{port}\\b'",
                            remediation_hint=f"Bind service to localhost or update baselines if {port_id} is intentionally public.",
                            reachability=3,
                            privilege_gain=2,
                            ease=2,
                        )
                    )

    # 2. Correlate docker-ps.txt published ports against fw-docker-user.txt
    docker_ps_file = collect_dir / "docker-ps.txt"
    fw_user_file = collect_dir / "fw-docker-user.txt"

    if docker_ps_file.exists():
        ps_content = docker_ps_file.read_text(errors="replace")
        has_docker_user_rules = False
        if fw_user_file.exists():
            fw_lines = [
                l.strip()
                for l in fw_user_file.read_text(errors="replace").splitlines()
                if l.strip() and not l.startswith("###") and not l.startswith("-N DOCKER-USER")
            ]
            # Active filtering rules exist if there are rules other than default RETURN
            active_rules = [l for l in fw_lines if l != "-A DOCKER-USER -j RETURN"]
            has_docker_user_rules = len(active_rules) > 0

        # Look for public port mappings like 0.0.0.0:8080->80/tcp or :::8080->80/tcp
        port_maps = re.findall(r'((?:0\.0\.0\.0|:::?|\[::\]):(\d+)->[^\s,]+)', ps_content)
        seen_docker_ports: set[str] = set()

        for full_mapping, host_port in port_maps:
            if host_port in seen_docker_ports:
                continue
            seen_docker_ports.add(host_port)

            if not has_docker_user_rules:
                findings.append(
                    Finding(
                        rule_id="EXP-003",
                        domain="exposure",
                        title=f"Docker published port {full_mapping} bypasses host firewall without DOCKER-USER filtering",
                        target=f"docker:port:{host_port}",
                        evidence=f"Published: {full_mapping}; DOCKER-USER chain is empty or default RETURN",
                        why_it_matters="Docker manipulates iptables PREROUTING directly, exposing container ports to the public internet regardless of UFW/firewalld rules unless filtered in DOCKER-USER.",
                        verify_cmd="iptables -S DOCKER-USER",
                        remediation_hint=f"Bind container to 127.0.0.1:{host_port} or add explicit filter rules to the DOCKER-USER iptables chain.",
                        reachability=3,
                        privilege_gain=2,
                        ease=2,
                    )
                )

    return findings
