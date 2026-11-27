"""Report generation module for creating Markdown audit reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import jinja2

from host_audit.schema import Finding, TriageReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_markdown_report(
    host: str,
    findings: list[Finding],
    diff: dict[str, list[Any]],
    triage: TriageReport | Any | None = None,
    redaction_mapping: dict[str, str] | None = None,
) -> str:
    """Generate Markdown report from audit findings, state diff, and optional triage."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.md.j2")

    summary = {
        "total_open": len(findings),
        "new_this_run": len(diff.get("new", [])),
        "persisting": len(diff.get("persisting", [])),
        "resolved_since_last": len(diff.get("resolved_ids", [])),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Determine triage representation and handle de-redaction
    triage_status: str | None = None
    triage_reason: str | None = None
    triage_stats: dict[str, Any] = {}
    triage_clusters: list[dict[str, Any]] = []
    triage_provenance: dict[str, Any] | None = None

    mapping = dict(redaction_mapping or {})
    if hasattr(triage, "redaction_mapping") and triage.redaction_mapping:
        mapping.update(triage.redaction_mapping)

    from host_audit.llm.redact import restore_text

    if isinstance(triage, dict):
        triage_status = triage.get("status")
        triage_reason = triage.get("reason")
        triage_stats = triage.get("stats", {})
        triage_provenance = triage.get("provenance")
        raw_clusters = triage.get("clusters", [])
        for c in raw_clusters:
            if isinstance(c, dict):
                hyp = restore_text(c.get("hypothesis", ""), mapping)
                checks = [restore_text(chk, mapping) for chk in c.get("next_checks", [])]
                triage_clusters.append({
                    "finding_ids": c.get("finding_ids", []),
                    "hypothesis": hyp,
                    "suggested_priority": c.get("suggested_priority", "medium"),
                    "next_checks": checks,
                })
    elif hasattr(triage, "clusters"):
        triage_status = getattr(triage, "status", "completed")
        triage_stats = getattr(triage, "stats", {})
        triage_provenance = getattr(triage, "provenance", None)
        for c in triage.clusters:
            hyp = restore_text(c.hypothesis, mapping)
            checks = [restore_text(chk, mapping) for chk in c.next_checks]
            triage_clusters.append({
                "finding_ids": c.finding_ids,
                "hypothesis": hyp,
                "suggested_priority": c.suggested_priority,
                "next_checks": checks,
            })

    rendered = template.render(
        host=host,
        timestamp=timestamp,
        findings=findings,
        diff=diff,
        summary=summary,
        triage=triage,
        triage_status=triage_status,
        triage_reason=triage_reason,
        triage_stats=triage_stats,
        triage_clusters=triage_clusters,
        triage_provenance=triage_provenance,
    )
    return rendered
