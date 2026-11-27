"""Structured and narrative exporters for AuditReport outputs."""

from __future__ import annotations

from host_audit_ai.exporters.ai_bundle import build_ai_bundle, export_ai_bundle
from host_audit_ai.exporters.json_out import export_json
from host_audit_ai.exporters.markdown import export_markdown
from host_audit_ai.exporters.sarif import build_sarif, export_sarif
from host_audit_ai.models.report import AuditReport, RunDiff
from host_audit_ai.models.snapshot import HostSnapshot

SUPPORTED_EXPORT_FORMATS = ("json", "sarif", "markdown", "ai-bundle")


def export_report(
    report: AuditReport,
    fmt: str,
    *,
    snapshot: HostSnapshot | None = None,
    diff: RunDiff | None = None,
    redact: bool = False,
    max_findings: int = 30,
) -> str:
    """Dispatch an AuditReport to the requested exporter format."""
    norm = fmt.strip().lower()
    if norm == "json":
        return export_json(report)
    if norm == "sarif":
        return export_sarif(report)
    if norm in ("markdown", "md"):
        return export_markdown(report, diff=diff)
    if norm == "ai-bundle":
        return export_ai_bundle(
            report,
            snapshot=snapshot,
            max_findings=max_findings,
            redact=redact,
        )
    raise ValueError(
        f"Unsupported export format '{fmt}'. "
        f"Expected one of: {', '.join(SUPPORTED_EXPORT_FORMATS)}."
    )


__all__ = [
    "SUPPORTED_EXPORT_FORMATS",
    "build_ai_bundle",
    "build_sarif",
    "export_ai_bundle",
    "export_json",
    "export_markdown",
    "export_report",
    "export_sarif",
]
