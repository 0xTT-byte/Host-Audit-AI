"""Token-budgeted, evidence-capped, redaction-capable AI context bundle exporter."""

from __future__ import annotations

import ipaddress
import re

from host_audit_ai.models.finding import DriftStatus, ExposureNode, Finding
from host_audit_ai.models.report import (
    AIBundle,
    AIBundleChain,
    AIBundleFinding,
    AIBundlePackage,
    AuditReport,
)
from host_audit_ai.models.snapshot import HostSnapshot

_PRESERVED_IPS = {"0.0.0.0", "::", "127.0.0.1", "::1"}  # noqa: S104
_PRESERVED_USERS = {"root", "nobody"}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"(?<![a-zA-Z0-9:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![a-zA-Z0-9:])"
)
_HOME_PATH_RE = re.compile(r"/home/([a-zA-Z0-9_.-]+)")
_FQDN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:local|internal|lan|corp|home|internal\.net|com|net|org|io|dev)\b"
)

_PACKAGE_KEYWORDS: dict[str, set[str]] = {
    "ssh": {"openssh", "ssh"},
    "sshd": {"openssh", "ssh"},
    "postgres": {"postgres", "postgresql"},
    "docker": {"docker", "containerd"},
    "dockerd": {"docker", "containerd"},
    "podman": {"podman", "conmon"},
    "mysql": {"mysql", "mariadb"},
    "mysqld": {"mysql", "mariadb"},
    "nginx": {"nginx"},
    "apache2": {"apache2"},
    "httpd": {"httpd"},
    "redis": {"redis"},
    "redis-server": {"redis"},
    "sudo": {"sudo"},
    "python3": {"python3"},
}


class _BundleRedactor:
    """Deterministic value-to-placeholder redactor for AI bundles."""

    def __init__(
        self,
        hosts: list[str],
        users: list[str],
    ) -> None:
        self._counts = {"HOST": 0, "IP": 0, "USER": 0}
        self._map: dict[str, str] = {}

        for h in sorted({x.strip() for x in hosts if x.strip() and x.strip() != "unknown"}):
            self._placeholder("HOST", h)
        for u in sorted(
            {x.strip() for x in users if x.strip() and x.strip() not in _PRESERVED_USERS}
        ):
            self._placeholder("USER", u)

    def _placeholder(self, kind: str, value: str) -> str:
        if value in self._map:
            return self._map[value]
        self._counts[kind] += 1
        token = f"[{kind}_{self._counts[kind]}]"
        self._map[value] = token
        return token

    def redact_text(self, text: str) -> str:
        if not text:
            return text

        out = text

        # 1. Replace IPv4 addresses (preserving wildcard/loopback)
        def _sub_ipv4(m: re.Match[str]) -> str:
            cand = m.group(0)
            if cand in _PRESERVED_IPS:
                return cand
            try:
                ipaddress.IPv4Address(cand)
            except ValueError:
                return cand
            return self._placeholder("IP", cand)

        out = _IPV4_RE.sub(_sub_ipv4, out)

        # 2. Replace IPv6 addresses (preserving :: and ::1)
        def _sub_ipv6(m: re.Match[str]) -> str:
            cand = m.group(0)
            if cand in _PRESERVED_IPS:
                return cand
            try:
                ipaddress.IPv6Address(cand)
            except ValueError:
                return cand
            return self._placeholder("IP", cand)

        out = _IPV6_RE.sub(_sub_ipv6, out)

        # 3. Replace /home/<user> paths
        def _sub_home(m: re.Match[str]) -> str:
            uname = m.group(1)
            if uname in _PRESERVED_USERS:
                return m.group(0)
            ph = self._placeholder("USER", uname)
            return f"/home/{ph}"

        out = _HOME_PATH_RE.sub(_sub_home, out)

        # 4. Replace FQDNs
        def _sub_fqdn(m: re.Match[str]) -> str:
            return self._placeholder("HOST", m.group(0))

        out = _FQDN_RE.sub(_sub_fqdn, out)

        # 5. Replace known hostnames and non-root usernames longest-first
        known_items = sorted(
            ((val, ph) for val, ph in self._map.items() if ph.startswith(("[HOST_", "[USER_"))),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        for val, ph in known_items:
            # Word-like boundaries that also handle target prefixes like user:victim or victim:x
            pattern = re.compile(rf"(?<![A-Za-z0-9_\[]){re.escape(val)}(?![A-Za-z0-9_\]])")
            out = pattern.sub(ph, out)

        return out


def _truncate_snippet(text: str, max_chars: int) -> str:
    clean = " ".join(text.splitlines()).strip()
    if len(clean) <= max_chars:
        return clean
    if max_chars <= 3:
        return clean[:max_chars]
    return clean[: max_chars - 3].rstrip() + "..."


def _collect_redaction_seeds(
    report: AuditReport,
    snapshot: HostSnapshot | None,
) -> tuple[list[str], list[str]]:
    hosts: list[str] = [report.hostname, report.host_id]
    users: list[str] = []

    if snapshot is not None:
        if snapshot.metadata.hostname:
            hosts.append(snapshot.metadata.hostname)
        for u in snapshot.users:
            if u.username not in _PRESERVED_USERS and (u.uid >= 1000 or u.uid == 0):
                users.append(u.username)
        for m in _HOME_PATH_RE.findall(" ".join(u.home for u in snapshot.users)):
            users.append(m)
        for cron in snapshot.cron_entries:
            if cron.user and cron.user not in _PRESERVED_USERS:
                users.append(cron.user)

    for f in report.findings:
        if f.target.startswith("user:"):
            users.append(f.target.removeprefix("user:"))
        elif f.target.startswith("sudoers:"):
            rest = f.target.removeprefix("sudoers:")
            uname = rest.split(":", 1)[0].lstrip("%")
            if uname:
                users.append(uname)
        for ev in f.evidence:
            users.extend(_HOME_PATH_RE.findall(ev.snippet))
            if ev.path:
                users.extend(_HOME_PATH_RE.findall(ev.path))

    return hosts, users


def _select_relevant_packages(
    report: AuditReport,
    snapshot: HostSnapshot | None,
) -> list[AIBundlePackage]:
    if snapshot is None or not snapshot.packages:
        return []

    needles: set[str] = set()
    for sock in snapshot.listening_sockets:
        if sock.process_name:
            pname = sock.process_name.lower()
            needles.update(_PACKAGE_KEYWORDS.get(pname, {pname}))

    for f in report.findings:
        if f.drift_status == DriftStatus.WAIVED:
            continue
        if f.category == "ssh":
            needles.update({"openssh", "ssh"})
        elif f.category == "containers":
            needles.update({"docker", "containerd", "podman"})
        elif f.rule_id in ("PRV-001", "PRV-002"):
            needles.add("sudo")

    if not needles:
        return []

    matched: list[AIBundlePackage] = []
    for pkg in snapshot.packages:
        low_name = pkg.name.lower()
        if any(n in low_name for n in needles):
            matched.append(
                AIBundlePackage(
                    name=pkg.name,
                    version=pkg.version,
                    architecture=pkg.architecture,
                )
            )
    return matched[:20]


def _redact_node(node: ExposureNode, redactor: _BundleRedactor) -> ExposureNode:
    return ExposureNode(
        node_type=node.node_type,
        label=redactor.redact_text(node.label),
        metadata={k: redactor.redact_text(v) for k, v in node.metadata.items()},
    )


def build_ai_bundle(
    report: AuditReport,
    snapshot: HostSnapshot | None = None,
    *,
    max_findings: int = 30,
    max_evidence_per_finding: int = 2,
    max_snippet_chars: int = 240,
    redact: bool = False,
) -> AIBundle:
    """Build a compact, token-budgeted AIBundle for local 4B-8B LLM triage."""
    active_findings: list[Finding] = [
        f for f in report.findings if f.drift_status != DriftStatus.WAIVED
    ]
    active_findings.sort(key=lambda f: (-f.severity.weight, f.rule_id, f.target, f.fingerprint))

    limited_findings = active_findings[: max(0, max_findings)]
    truncated_count = max(0, len(active_findings) - len(limited_findings))

    redactor: _BundleRedactor | None = None
    if redact:
        hosts, users = _collect_redaction_seeds(report, snapshot)
        redactor = _BundleRedactor(hosts=hosts, users=users)

    def _clean(text: str) -> str:
        return redactor.redact_text(text) if redactor is not None else text

    bundle_chains: list[AIBundleChain] = []
    for chain in report.exposure_chains:
        nodes = (
            [_redact_node(n, redactor) for n in chain.nodes]
            if redactor is not None
            else list(chain.nodes)
        )
        path_summary = " -> ".join(f"{n.node_type}:{n.label}" for n in nodes)
        bundle_chains.append(
            AIBundleChain(
                chain_id=chain.chain_id,
                title=_clean(chain.title),
                severity=chain.severity,
                path_summary=path_summary,
                nodes=nodes,
                related_finding_fingerprints=list(chain.related_finding_fingerprints),
            )
        )

    bundle_findings: list[AIBundleFinding] = []
    for f in limited_findings:
        raw_snippets = [ev.snippet for ev in f.evidence[: max(0, max_evidence_per_finding)]]
        snippets = [_truncate_snippet(_clean(s), max_snippet_chars) for s in raw_snippets]
        bundle_findings.append(
            AIBundleFinding(
                rule_id=f.rule_id,
                title=_clean(f.title),
                severity=f.severity,
                category=f.category,
                target=_clean(f.target),
                expected=_clean(f.expected),
                actual=_clean(f.actual),
                evidence_snippets=snippets,
                cis_ref=f.cis_ref,
                mitre_attack=list(f.mitre_attack),
                fingerprint=f.fingerprint,
                drift_status=f.drift_status,
                waiver_reason=_clean(f.waiver_reason) if f.waiver_reason else None,
            )
        )

    relevant_pkgs = _select_relevant_packages(report, snapshot)
    if redactor is not None:
        relevant_pkgs = [
            AIBundlePackage(
                name=_clean(p.name),
                version=_clean(p.version),
                architecture=p.architecture,
            )
            for p in relevant_pkgs
        ]

    return AIBundle(
        run_id=report.run_id,
        host_id=_clean(report.host_id),
        hostname=_clean(report.hostname),
        created_at=report.created_at,
        baseline_name=report.baseline_name,
        degraded_mode=report.degraded_mode,
        redacted=redact,
        summary=report.summary,
        total_active_findings=len(active_findings),
        included_findings_count=len(bundle_findings),
        truncated_findings_count=truncated_count,
        exposure_chains=bundle_chains,
        findings=bundle_findings,
        relevant_packages=relevant_pkgs,
    )


def export_ai_bundle(
    report: AuditReport,
    snapshot: HostSnapshot | None = None,
    *,
    max_findings: int = 30,
    max_evidence_per_finding: int = 2,
    max_snippet_chars: int = 240,
    redact: bool = False,
) -> str:
    """Serialize a token-budgeted AIBundle as indented JSON."""
    bundle = build_ai_bundle(
        report,
        snapshot=snapshot,
        max_findings=max_findings,
        max_evidence_per_finding=max_evidence_per_finding,
        max_snippet_chars=max_snippet_chars,
        redact=redact,
    )
    return bundle.model_dump_json(indent=2)
