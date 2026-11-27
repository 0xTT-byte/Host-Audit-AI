"""Pure-Python Markdown technical and executive audit report exporter."""

from __future__ import annotations

from host_audit_ai.models.finding import DriftStatus, Finding, Severity
from host_audit_ai.models.report import AuditReport, RunDiff

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _render_finding_block(finding: Finding) -> list[str]:
    lines: list[str] = [
        f"#### [{finding.severity.value}] `{finding.rule_id}` - {finding.title}",
        "",
        f"- **Target:** `{finding.target}`",
        f"- **Category:** {finding.category}",
        f"- **Expected:** {finding.expected}",
        f"- **Actual:** {finding.actual}",
    ]
    if finding.cis_ref:
        lines.append(f"- **CIS Reference:** `{finding.cis_ref}`")
    if finding.mitre_attack:
        tags = ", ".join(f"`{t}`" for t in finding.mitre_attack)
        lines.append(f"- **MITRE ATT&CK:** {tags}")
    if finding.drift_status is not None:
        lines.append(f"- **Status:** `{finding.drift_status.value}`")
    if finding.waiver_reason:
        lines.append(f"- **Waiver Note:** {finding.waiver_reason}")
    lines.append(f"- **Fingerprint:** `{finding.fingerprint}`")

    if finding.evidence:
        lines.extend(["", "**Evidence:**", "", "```text"])
        for ev in finding.evidence:
            prefix = f"[{ev.source_section}] "
            if ev.path:
                prefix += f"({ev.path}) "
            lines.append(f"{prefix}{ev.snippet}")
        lines.append("```")
    lines.append("")
    return lines


def _render_diff_section(diff: RunDiff) -> list[str]:
    lines: list[str] = [
        "## Drift Delta",
        "",
        f"Comparing base run `{diff.base_run_id}` -> target run `{diff.target_run_id}`.",
        "",
        "| Classification | Count |",
        "| :--- | :---: |",
        f"| NEW | {len(diff.new)} |",
        f"| REGRESSED | {len(diff.regressed)} |",
        f"| RESOLVED | {len(diff.resolved)} |",
        f"| PERSISTENT | {len(diff.persistent)} |",
        f"| WAIVED | {len(diff.waived)} |",
        "",
    ]

    delta_rows: list[tuple[str, Finding]] = [
        *[(DriftStatus.NEW.value, f) for f in diff.new],
        *[(DriftStatus.REGRESSED.value, f) for f in diff.regressed],
        *[(DriftStatus.RESOLVED.value, f) for f in diff.resolved],
        *[(DriftStatus.PERSISTENT.value, f) for f in diff.persistent],
        *[(DriftStatus.WAIVED.value, f) for f in diff.waived],
    ]
    if delta_rows:
        lines.extend(
            [
                "| Drift | Severity | Rule ID | Target | Title |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for status_label, f in delta_rows:
            lines.append(
                f"| `{status_label}` | **{f.severity.value}** | `{f.rule_id}` | "
                f"`{_escape_cell(f.target)}` | {_escape_cell(f.title)} |"
            )
        lines.append("")
    return lines


def export_markdown(report: AuditReport, diff: RunDiff | None = None) -> str:
    """Render an AuditReport (and optional RunDiff) as pure-Python Markdown."""
    timestamp = report.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [
        f"# Host Security Audit Report: `{report.hostname}`",
        "",
        f"- **Run ID:** `{report.run_id}`",
        f"- **Host ID:** `{report.host_id}`",
        f"- **Baseline:** `{report.baseline_name}`",
        f"- **Timestamp:** {timestamp}",
        f"- **Snapshot Hash:** `{report.snapshot_hash}`",
        "",
    ]

    if report.degraded_mode:
        lines.extend(
            [
                "> **WARNING (Degraded Mode):** Collector executed with non-root EUID. "
                "Privileged telemetry sections may be incomplete.",
                "",
            ]
        )

    # Severity Summary Table
    counts = report.summary.counts_by_severity
    lines.extend(
        [
            "## Severity Summary",
            "",
            "| Metric | Count |",
            "| :--- | :---: |",
            f"| CRITICAL | {counts.get(Severity.CRITICAL, 0)} |",
            f"| HIGH | {counts.get(Severity.HIGH, 0)} |",
            f"| MEDIUM | {counts.get(Severity.MEDIUM, 0)} |",
            f"| LOW | {counts.get(Severity.LOW, 0)} |",
            f"| INFO | {counts.get(Severity.INFO, 0)} |",
            f"| **Total Active Findings** | **{report.summary.total_findings}** |",
            f"| Exposure Chains | {report.summary.exposure_chain_count} |",
            f"| Waived Findings | {report.summary.waived_count} |",
            f"| Expired Waivers | {report.summary.expired_waiver_count} |",
            "",
        ]
    )

    # Exposure Chains
    lines.extend(["## Exposure Chains", ""])
    if report.exposure_chains:
        for idx, chain in enumerate(report.exposure_chains, start=1):
            flow = " -> ".join(f"{n.node_type}:{n.label}" for n in chain.nodes)
            lines.extend(
                [
                    f"### {idx}. [{chain.severity.value}] {chain.title}",
                    "",
                    f"- **Chain ID:** `{chain.chain_id}`",
                    f"- **Path:** `{flow}`",
                    f"- **Linked Findings:** {len(chain.related_finding_fingerprints)}",
                    "",
                ]
            )
    else:
        lines.extend(["No multi-step exposure chains detected.", ""])

    # Active Findings grouped by severity
    active_findings = [f for f in report.findings if f.drift_status != DriftStatus.WAIVED]
    lines.extend(["## Active Findings", ""])
    if not active_findings:
        lines.extend(["No active policy violations detected.", ""])
    else:
        for sev in _SEVERITY_ORDER:
            group = [f for f in active_findings if f.severity == sev]
            if not group:
                continue
            lines.extend([f"### {sev.value} ({len(group)})", ""])
            for finding in group:
                lines.extend(_render_finding_block(finding))

    # Waived and Expired Waivers
    waived_or_expired = [
        f
        for f in report.findings
        if f.drift_status in (DriftStatus.WAIVED, DriftStatus.WAIVER_EXPIRED)
    ]
    lines.extend(["## Waived & Expired Waivers", ""])
    if not waived_or_expired:
        lines.extend(["No waived or expired-waiver findings recorded.", ""])
    else:
        lines.extend(
            [
                "| Status | Severity | Rule ID | Target | Reason |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in waived_or_expired:
            status_str = f.drift_status.value if f.drift_status else "-"
            reason_str = _escape_cell(f.waiver_reason or "-")
            lines.append(
                f"| `{status_str}` | {f.severity.value} | `{f.rule_id}` | "
                f"`{_escape_cell(f.target)}` | {reason_str} |"
            )
        lines.append("")

    if diff is not None:
        lines.extend(_render_diff_section(diff))

    return "\n".join(lines).rstrip() + "\n"
