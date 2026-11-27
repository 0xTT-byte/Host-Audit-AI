"""Canonical AuditReport JSON exporter."""

from __future__ import annotations

from host_audit_ai.models.report import AuditReport


def export_json(report: AuditReport) -> str:
    """Serialize an AuditReport as canonical indented JSON."""
    return report.model_dump_json(indent=2)
