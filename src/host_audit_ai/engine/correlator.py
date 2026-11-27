"""Deterministic pre-LLM exposure chain correlator.

Joins host snapshot telemetry (listeners, processes, systemd units, users,
containers, cron jobs, IOCs) with active policy findings into reproducible
multi-step ExposureChain graphs without using LLMs or performing I/O.
"""

from __future__ import annotations

import hashlib

from host_audit_ai.models.finding import (
    DriftStatus,
    ExposureChain,
    ExposureNode,
    Finding,
    Severity,
)
from host_audit_ai.models.snapshot import (
    ContainerInstance,
    CronEntry,
    HostSnapshot,
    ListeningSocket,
    ProcessEntry,
    ServiceUnit,
    UserAccount,
)

WILD_ADDRESSES = {"0.0.0.0", "::", "*"}  # noqa: S104

_NEXT_SEVERITY: dict[Severity, Severity] = {
    Severity.INFO: Severity.LOW,
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}

_SERVICE_ALIASES: dict[str, set[str]] = {
    "sshd": {"ssh", "sshd"},
    "postgres": {"postgres", "postgresql"},
    "dockerd": {"docker", "dockerd"},
    "containerd": {"containerd"},
    "mysqld": {"mysql", "mysqld", "mariadb"},
    "mariadbd": {"mariadb", "mysql", "mariadbd"},
    "redis-server": {"redis", "redis-server"},
    "mongod": {"mongod", "mongodb"},
}


def _compute_chain_id(chain_type: str, nodes: list[ExposureNode]) -> str:
    """Compute deterministic SHA-256 chain_id with no PIDs or timestamps in labels."""
    parts = [chain_type, *(f"{n.node_type}:{n.label}" for n in nodes)]
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _max_severity(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), key=lambda s: s.weight)


def _escalate_severity(severity: Severity) -> Severity:
    return _NEXT_SEVERITY[severity]


def _is_public_address(addr: str) -> bool:
    return addr.strip() in WILD_ADDRESSES


def _binary_name(command: str) -> str:
    tokens = command.strip().split()
    if not tokens:
        return ""
    return tokens[0].rstrip(":").rsplit("/", 1)[-1]


def _match_process(sock: ListeningSocket, processes: list[ProcessEntry]) -> ProcessEntry | None:
    if sock.pid is not None:
        for proc in processes:
            if proc.pid == sock.pid:
                return proc
    if sock.process_name:
        target_name = sock.process_name.lower()
        for proc in processes:
            if _binary_name(proc.command).lower() == target_name:
                return proc
    return None


def _match_service(proc_name: str, services: list[ServiceUnit]) -> ServiceUnit | None:
    if not proc_name:
        return None
    low = proc_name.lower()
    candidates = _SERVICE_ALIASES.get(low, {low})
    for unit in services:
        base = unit.name.removesuffix(".service").lower()
        if base in candidates:
            return unit
    return None


def _match_user(username: str, users: list[UserAccount]) -> UserAccount | None:
    if not username:
        return None
    for user in users:
        if user.username == username:
            return user
    return None


def _is_root_account(username: str, user: UserAccount | None) -> bool:
    if username == "root":
        return True
    return bool(user is not None and (user.uid == 0 or user.is_root_equivalent))


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen[f.fingerprint] = f
    return sorted(
        seen.values(),
        key=lambda f: (-f.severity.weight, f.rule_id, f.target, f.fingerprint),
    )


def _build_public_listener_chains(
    snapshot: HostSnapshot,
    active: list[Finding],
) -> list[ExposureChain]:
    """Class 1: Public Listener -> Process -> Service -> User -> Privilege/Path."""
    chains: list[ExposureChain] = []
    fw_findings = [f for f in active if f.rule_id in ("FW-001", "FW-002")]

    for sock in snapshot.listening_sockets:
        if not _is_public_address(sock.local_address):
            continue

        endpoint = f"{sock.local_address}:{sock.local_port}"
        proc = _match_process(sock, snapshot.processes)
        proc_name = sock.process_name or (_binary_name(proc.command) if proc else "") or "unknown"
        service = _match_service(proc_name, snapshot.services)
        username = proc.user if (proc and proc.user) else ""
        user = _match_user(username, snapshot.users)

        exp_findings = [
            f for f in active if f.rule_id in ("EXP-001", "EXP-002") and f.target == endpoint
        ]

        priv_findings: list[Finding] = []
        path_findings: list[Finding] = []
        for f in active:
            is_usr_priv = f.rule_id == "USR-001" and (
                username == "root" or f.target == f"user:{username}"
            )
            is_sudo_priv = (
                f.rule_id in ("PRV-001", "PRV-002")
                and bool(username)
                and (
                    f.target == f"sudoers:{username}" or f.target.startswith(f"sudoers:{username}:")
                )
            )
            if is_usr_priv or is_sudo_priv:
                priv_findings.append(f)
            elif f.rule_id in ("PRV-003", "PRV-004"):
                bin_base = f.target.rsplit("/", 1)[-1].lower()
                if proc_name != "unknown" and (
                    bin_base == proc_name.lower() or bin_base.startswith(proc_name.lower())
                ):
                    path_findings.append(f)
            elif f.rule_id in ("FS-001", "FS-002"):
                is_sshd_cfg = proc_name == "sshd" and f.target == "/etc/ssh/sshd_config"
                is_crit_file = f.target in ("/etc/passwd", "/etc/sudoers", "/etc/shadow") and (
                    _is_root_account(username, user) or bool(exp_findings)
                )
                if is_sshd_cfg or is_crit_file:
                    path_findings.append(f)

        linked = _dedup_findings(exp_findings + fw_findings + priv_findings + path_findings)
        if not linked:
            continue

        is_root = _is_root_account(username, user)
        # Require either direct exposure/privilege/path finding or root listener lacking firewall
        if not (exp_findings or priv_findings or path_findings or (fw_findings and is_root)):
            continue

        nodes: list[ExposureNode] = [
            ExposureNode(
                node_type="listener",
                label=f"{endpoint}/{sock.protocol}",
                metadata={
                    "address": sock.local_address,
                    "port": str(sock.local_port),
                    "protocol": sock.protocol,
                },
            )
        ]

        if proc_name != "unknown" or proc is not None:
            proc_meta: dict[str, str] = {}
            if proc is not None:
                proc_meta["pid"] = str(proc.pid)
                proc_meta["command"] = proc.command
            nodes.append(ExposureNode(node_type="process", label=proc_name, metadata=proc_meta))

        if service is not None:
            nodes.append(
                ExposureNode(
                    node_type="service",
                    label=service.name,
                    metadata={"active_state": service.active_state},
                )
            )

        if username:
            user_meta: dict[str, str] = {}
            if user is not None:
                user_meta["uid"] = str(user.uid)
            nodes.append(ExposureNode(node_type="user", label=username, metadata=user_meta))

        for pf in _dedup_findings(path_findings):
            nodes.append(
                ExposureNode(
                    node_type="path",
                    label=pf.target,
                    metadata={"rule_id": pf.rule_id},
                )
            )

        priv_rules = sorted({f.rule_id for f in priv_findings})
        if priv_rules or is_root:
            priv_label = (
                f"privileged_access ({', '.join(priv_rules)})" if priv_rules else "root_execution"
            )
            nodes.append(
                ExposureNode(
                    node_type="privilege",
                    label=priv_label,
                    metadata={"root_context": str(is_root).lower()},
                )
            )
        elif exp_findings or fw_findings:
            exp_rules = sorted({f.rule_id for f in exp_findings + fw_findings})
            nodes.append(
                ExposureNode(
                    node_type="privilege",
                    label=f"exposed_service ({', '.join(exp_rules)})",
                )
            )

        sev = _max_severity(linked)
        if is_root or any(
            f.rule_id in ("USR-001", "PRV-001", "PRV-002", "PRV-004") for f in linked
        ):
            sev = _escalate_severity(sev)

        chain_id = _compute_chain_id("public_listener_privilege", nodes)
        title = f"Public listener {endpoint}/{sock.protocol} ({proc_name}) exposure chain"
        chains.append(
            ExposureChain(
                chain_id=chain_id,
                title=title,
                severity=sev,
                nodes=nodes,
                related_finding_fingerprints=[f.fingerprint for f in linked],
            )
        )

    return chains


def _build_ssh_chains(
    snapshot: HostSnapshot,
    active: list[Finding],
) -> list[ExposureChain]:
    """Class 2: SSH Remote Access -> Weak Auth -> Escalation Chain."""
    ssh_port = snapshot.sshd_config.port if snapshot.sshd_config else 22
    ssh_sockets = [
        s
        for s in snapshot.listening_sockets
        if _is_public_address(s.local_address)
        and (s.local_port == ssh_port or (s.process_name or "").lower() == "sshd")
    ]
    if not ssh_sockets:
        return []

    ssh_auth = [f for f in active if f.rule_id in ("SSH-001", "SSH-002", "SSH-003")]
    if not ssh_auth:
        return []

    ssh_extra = [f for f in active if f.rule_id == "SSH-006"]
    esc_findings = [f for f in active if f.rule_id in ("USR-001", "PRV-001", "PRV-002")]
    fw_findings = [f for f in active if f.rule_id == "FW-001"]

    linked = _dedup_findings(ssh_auth + ssh_extra + esc_findings + fw_findings)
    service = _match_service("sshd", snapshot.services)

    chains: list[ExposureChain] = []
    for sock in ssh_sockets:
        endpoint = f"{sock.local_address}:{sock.local_port}"
        proc = _match_process(sock, snapshot.processes)
        nodes: list[ExposureNode] = [
            ExposureNode(
                node_type="listener",
                label=f"{endpoint}/{sock.protocol}",
                metadata={"service": "ssh", "port": str(sock.local_port)},
            ),
            ExposureNode(
                node_type="process",
                label="sshd",
                metadata={"pid": str(proc.pid)} if proc else {},
            ),
        ]
        if service is not None:
            nodes.append(
                ExposureNode(
                    node_type="service",
                    label=service.name,
                    metadata={"active_state": service.active_state},
                )
            )

        auth_rules = sorted({f.rule_id for f in ssh_auth + ssh_extra})
        nodes.append(
            ExposureNode(
                node_type="privilege",
                label=f"weak_ssh_auth ({', '.join(auth_rules)})",
            )
        )

        # Link root or escalation user context
        has_root_login = any(f.rule_id == "SSH-001" for f in ssh_auth)
        if has_root_login or any(f.rule_id == "USR-001" for f in esc_findings):
            nodes.append(ExposureNode(node_type="user", label="root"))

        if esc_findings:
            esc_rules = sorted({f.rule_id for f in esc_findings})
            nodes.append(
                ExposureNode(
                    node_type="privilege",
                    label=f"privilege_escalation ({', '.join(esc_rules)})",
                )
            )

        sev = _max_severity(linked)
        if has_root_login or any(f.rule_id == "SSH-003" for f in ssh_auth) or esc_findings:
            sev = _escalate_severity(sev)

        chain_id = _compute_chain_id("ssh_auth_escalation", nodes)
        chains.append(
            ExposureChain(
                chain_id=chain_id,
                title=f"Public SSH ({endpoint}) weak authentication to host escalation",
                severity=sev,
                nodes=nodes,
                related_finding_fingerprints=[f.fingerprint for f in linked],
            )
        )

    return chains


def _extract_container_name(target: str) -> str:
    # CNT-002 / CNT-003: "container:<name>"
    # CNT-004: "container:<name>:<mount>"
    if not target.startswith("container:"):
        return target
    rest = target.removeprefix("container:")
    return rest.split(":", 1)[0]


def _build_container_chains(
    snapshot: HostSnapshot,
    active: list[Finding],
) -> list[ExposureChain]:
    """Class 3: Container Escape / Host Compromise Chain."""
    chains: list[ExposureChain] = []
    fw_docker = [f for f in active if f.rule_id == "FW-002"]
    exp_findings = [f for f in active if f.rule_id in ("EXP-001", "EXP-002")]
    docker_service = _match_service("dockerd", snapshot.services)

    # 3a. Exposed / world-writable container daemon socket (CNT-001)
    cnt_socket_findings = [f for f in active if f.rule_id == "CNT-001"]
    for sf in cnt_socket_findings:
        linked = _dedup_findings([sf, *fw_docker])
        nodes: list[ExposureNode] = [
            ExposureNode(node_type="path", label=sf.target, metadata={"rule_id": "CNT-001"}),
        ]
        if docker_service is not None:
            nodes.append(ExposureNode(node_type="service", label=docker_service.name))
        else:
            nodes.append(ExposureNode(node_type="service", label="container-runtime"))
        if fw_docker:
            nodes.append(ExposureNode(node_type="listener", label="iptables:DOCKER-USER"))
        nodes.append(
            ExposureNode(
                node_type="privilege",
                label="host_root_via_container_socket",
            )
        )
        sev = _escalate_severity(_max_severity(linked))
        chain_id = _compute_chain_id("container_escape", nodes)
        chains.append(
            ExposureChain(
                chain_id=chain_id,
                title=f"World-writable container socket ({sf.target}) host takeover",
                severity=sev,
                nodes=nodes,
                related_finding_fingerprints=[f.fingerprint for f in linked],
            )
        )

    # 3b. Running container workload breakout chains (CNT-002, CNT-003, CNT-004)
    workload_by_name: dict[str, list[Finding]] = {}
    for f in active:
        if f.rule_id in ("CNT-002", "CNT-003", "CNT-004"):
            cname = _extract_container_name(f.target)
            workload_by_name.setdefault(cname, []).append(f)

    inst_by_name: dict[str, ContainerInstance] = {
        c.name: c for c in snapshot.containers.running_containers if c.name
    }
    public_sockets = [s for s in snapshot.listening_sockets if _is_public_address(s.local_address)]

    for cname in sorted(workload_by_name):
        c_findings = workload_by_name[cname]
        c_inst = inst_by_name.get(cname)
        extra_links: list[Finding] = list(fw_docker)
        if c_inst and c_inst.network_mode.lower() == "host":
            extra_links.extend(exp_findings)

        linked = _dedup_findings(c_findings + extra_links)
        nodes = []

        if fw_docker:
            nodes.append(
                ExposureNode(
                    node_type="listener",
                    label="docker_port_firewall_bypass",
                    metadata={"chain": "DOCKER-USER"},
                )
            )
        elif c_inst and c_inst.network_mode.lower() == "host" and public_sockets:
            first_sock = sorted(
                public_sockets, key=lambda s: (s.local_port, s.local_address, s.protocol)
            )[0]
            nodes.append(
                ExposureNode(
                    node_type="listener",
                    label=f"{first_sock.local_address}:{first_sock.local_port}/{first_sock.protocol}",
                    metadata={"network_mode": "host"},
                )
            )

        nodes.append(
            ExposureNode(
                node_type="service",
                label=f"container:{cname}",
                metadata={"image": c_inst.image} if c_inst and c_inst.image else {},
            )
        )

        mount_findings = [f for f in c_findings if f.rule_id == "CNT-004"]
        for mf in sorted(mount_findings, key=lambda x: x.target):
            mount_path = mf.target.split(":", 2)[2] if mf.target.count(":") >= 2 else mf.target
            nodes.append(
                ExposureNode(
                    node_type="path",
                    label=mount_path,
                    metadata={"rule_id": "CNT-004"},
                )
            )

        cnt_rules = sorted({f.rule_id for f in c_findings})
        nodes.append(
            ExposureNode(
                node_type="privilege",
                label=f"container_host_escape ({', '.join(cnt_rules)})",
            )
        )

        sev = _max_severity(linked)
        if fw_docker or (c_inst and c_inst.network_mode.lower() == "host"):
            sev = _escalate_severity(sev)

        chain_id = _compute_chain_id("container_escape", nodes)
        chains.append(
            ExposureChain(
                chain_id=chain_id,
                title=f"Container '{cname}' host escape / breakout chain",
                severity=sev,
                nodes=nodes,
                related_finding_fingerprints=[f.fingerprint for f in linked],
            )
        )

    return chains


def _find_cron_for_finding(finding: Finding, crons: list[CronEntry]) -> CronEntry | None:
    if ":" in finding.target:
        source_file, _, user = finding.target.rpartition(":")
        for c in crons:
            if c.source_file == source_file and c.user == user:
                return c
    return None


def _build_ioc_chains(
    snapshot: HostSnapshot,
    active: list[Finding],
) -> list[ExposureChain]:
    """Class 4: Persistence / Runtime IOC -> Privilege Chain."""
    ioc_findings = [f for f in active if f.rule_id in ("IOC-001", "IOC-002", "IOC-003", "CRN-001")]
    if not ioc_findings:
        return []

    chains: list[ExposureChain] = []
    priv_findings = [f for f in active if f.rule_id in ("USR-001", "PRV-001", "PRV-002")]
    proc_by_pid = {p.pid: p for p in snapshot.processes}

    # Index IOC-003 findings by path for cross-linking with CRN-001
    temp_exec_by_path = {f.target: f for f in ioc_findings if f.rule_id == "IOC-003"}
    linked_temp_paths: set[str] = set()

    for f in ioc_findings:
        if f.rule_id == "IOC-001":
            pid_str = f.target.removeprefix("proc:")
            proc = proc_by_pid.get(int(pid_str)) if pid_str.isdigit() else None
            if proc is None:
                for dp in snapshot.ioc.deleted_binary_processes:
                    if pid_str.isdigit() and dp.pid == int(pid_str):
                        proc = dp
                        break

            cmd_label = proc.command if proc else f.actual
            bin_name = _binary_name(cmd_label.replace("(deleted)", "").strip()) or "deleted-proc"
            username = proc.user if (proc and proc.user and proc.user != "unknown") else ""
            user = _match_user(username, snapshot.users)
            user_privs = [
                pf
                for pf in priv_findings
                if username
                and (pf.target == f"user:{username}" or pf.target.startswith(f"sudoers:{username}"))
            ]
            linked = _dedup_findings([f, *user_privs])

            nodes: list[ExposureNode] = [
                ExposureNode(node_type="path", label=cmd_label, metadata={"rule_id": "IOC-001"}),
                ExposureNode(
                    node_type="process",
                    label=bin_name,
                    metadata={"pid": pid_str} if pid_str.isdigit() else {},
                ),
            ]
            if username:
                nodes.append(ExposureNode(node_type="user", label=username))

            is_root = _is_root_account(username, user)
            priv_label = (
                "root_deleted_binary_execution" if is_root else "untrusted_deleted_binary_execution"
            )
            nodes.append(ExposureNode(node_type="privilege", label=priv_label))

            sev = _max_severity(linked)
            if is_root or user_privs:
                sev = _escalate_severity(sev)

            chain_id = _compute_chain_id("ioc_privilege", nodes)
            chains.append(
                ExposureChain(
                    chain_id=chain_id,
                    title=f"Deleted binary execution ({bin_name}) runtime IOC chain",
                    severity=sev,
                    nodes=nodes,
                    related_finding_fingerprints=[x.fingerprint for x in linked],
                )
            )

        elif f.rule_id == "IOC-002":
            linked = _dedup_findings([f])
            nodes = [
                ExposureNode(node_type="path", label="/etc/ld.so.preload"),
                ExposureNode(node_type="binary", label=f.actual.strip()),
                ExposureNode(
                    node_type="privilege",
                    label="global_ld_preload_execution_hijack",
                ),
            ]
            sev = _escalate_severity(_max_severity(linked))
            chain_id = _compute_chain_id("ioc_privilege", nodes)
            chains.append(
                ExposureChain(
                    chain_id=chain_id,
                    title=f"Global LD_PRELOAD rootkit hook ({f.actual.strip()})",
                    severity=sev,
                    nodes=nodes,
                    related_finding_fingerprints=[x.fingerprint for x in linked],
                )
            )

        elif f.rule_id == "CRN-001":
            cron = _find_cron_for_finding(f, snapshot.cron_entries)
            cron_user = cron.user if cron else f.target.rpartition(":")[2]
            cron_cmd = cron.command if cron else f.actual
            cron_bin = _binary_name(cron_cmd) or cron_cmd
            user = _match_user(cron_user, snapshot.users)

            matched_temp = [tf for path, tf in temp_exec_by_path.items() if path in cron_cmd]
            for tf in matched_temp:
                linked_temp_paths.add(tf.target)

            user_privs = [
                pf
                for pf in priv_findings
                if cron_user
                and (
                    pf.target == f"user:{cron_user}" or pf.target.startswith(f"sudoers:{cron_user}")
                )
            ]
            linked = _dedup_findings([f, *matched_temp, *user_privs])

            nodes = [
                ExposureNode(
                    node_type="path",
                    label=cron.source_file if cron and cron.source_file else f.target,
                ),
                ExposureNode(node_type="binary", label=cron_bin),
            ]
            if cron_user:
                nodes.append(ExposureNode(node_type="user", label=cron_user))

            is_root = _is_root_account(cron_user, user)
            nodes.append(
                ExposureNode(
                    node_type="privilege",
                    label=("root_cron_persistence" if is_root else "scheduled_cron_persistence"),
                )
            )

            sev = _max_severity(linked)
            if is_root or user_privs:
                sev = _escalate_severity(sev)

            chain_id = _compute_chain_id("ioc_privilege", nodes)
            chains.append(
                ExposureChain(
                    chain_id=chain_id,
                    title=f"Untrusted cron persistence ({cron_bin} as {cron_user or 'unknown'})",
                    severity=sev,
                    nodes=nodes,
                    related_finding_fingerprints=[x.fingerprint for x in linked],
                )
            )

    # Emit standalone IOC-003 chains for temp executables not already linked to a CRN-001 chain
    for f in ioc_findings:
        if f.rule_id != "IOC-003" or f.target in linked_temp_paths:
            continue
        matching_proc = next((p for p in snapshot.processes if f.target in p.command), None)
        nodes = [
            ExposureNode(node_type="path", label=f.target, metadata={"rule_id": "IOC-003"}),
        ]
        if matching_proc is not None:
            nodes.append(
                ExposureNode(
                    node_type="process",
                    label=_binary_name(matching_proc.command) or f.target.rsplit("/", 1)[-1],
                    metadata={"pid": str(matching_proc.pid)},
                )
            )
            if matching_proc.user:
                nodes.append(ExposureNode(node_type="user", label=matching_proc.user))
        nodes.append(
            ExposureNode(
                node_type="privilege",
                label="staged_temp_executable",
            )
        )
        linked = [f]
        sev = _max_severity(linked)
        if matching_proc is not None and matching_proc.user == "root":
            sev = _escalate_severity(sev)
        chain_id = _compute_chain_id("ioc_privilege", nodes)
        chains.append(
            ExposureChain(
                chain_id=chain_id,
                title=f"Staged temporary executable ({f.target})",
                severity=sev,
                nodes=nodes,
                related_finding_fingerprints=[f.fingerprint],
            )
        )

    return chains


def correlate_exposures(
    snapshot: HostSnapshot,
    findings: list[Finding],
) -> list[ExposureChain]:
    """Correlate snapshot telemetry and active findings into deterministic ExposureChains.

    Pure Python, zero LLM/IO. Excludes WAIVED findings; treats WAIVER_EXPIRED as active.
    Deduplicates identical chain_ids and sorts deterministically by (severity desc, chain_id asc).
    """
    active = [f for f in findings if f.drift_status != DriftStatus.WAIVED]
    if not active:
        return []

    raw_chains: list[ExposureChain] = []
    raw_chains.extend(_build_public_listener_chains(snapshot, active))
    raw_chains.extend(_build_ssh_chains(snapshot, active))
    raw_chains.extend(_build_container_chains(snapshot, active))
    raw_chains.extend(_build_ioc_chains(snapshot, active))

    deduped: dict[str, ExposureChain] = {}
    for chain in raw_chains:
        if chain.chain_id not in deduped:
            deduped[chain.chain_id] = chain
        else:
            existing = deduped[chain.chain_id]
            merged_fps = sorted(
                set(existing.related_finding_fingerprints) | set(chain.related_finding_fingerprints)
            )
            best_sev = max(existing.severity, chain.severity, key=lambda s: s.weight)
            deduped[chain.chain_id] = ExposureChain(
                chain_id=existing.chain_id,
                title=existing.title,
                severity=best_sev,
                nodes=existing.nodes,
                related_finding_fingerprints=merged_fps,
            )

    result = list(deduped.values())
    result.sort(key=lambda c: (-c.severity.weight, c.chain_id))
    return result
