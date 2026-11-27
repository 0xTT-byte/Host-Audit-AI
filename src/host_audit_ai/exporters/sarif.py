"""SARIF 2.1.0 exporter for AuditReport findings."""

from __future__ import annotations

import json
from typing import Any

import host_audit_ai.engine.rules  # noqa: F401 Ensure RuleRegistry is populated
from host_audit_ai import __version__
from host_audit_ai.engine.registry import RuleRegistry
from host_audit_ai.models.finding import DriftStatus, Finding, Severity
from host_audit_ai.models.report import AuditReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_INFO_URI = "https://github.com/0xTT-byte/Host-Audit-AI"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _derive_artifact_uri(finding: Finding) -> str:
    for ev in finding.evidence:
        if ev.path:
            cleaned = ev.path.lstrip("/")
            return cleaned or "root-fs"
    target = finding.target.strip()
    if target.startswith("/"):
        return target.lstrip("/") or "root-fs"
    normalized = target.replace(":", "/").replace(" ", "_")
    return f"host/{normalized}" if normalized else "host/unknown"


def _build_driver_rule(rule_id: str, sample_finding: Finding) -> dict[str, Any]:
    reg = RuleRegistry.get_rule(rule_id)
    if reg is not None:
        meta, _ = reg
        return {
            "id": meta.rule_id,
            "shortDescription": {"text": meta.title},
            "properties": {
                "category": meta.category,
                "cis_ref": meta.cis_ref,
                "mitre_attack": list(meta.mitre_attack),
                "default_severity": meta.default_severity.value,
            },
        }
    return {
        "id": rule_id,
        "shortDescription": {"text": sample_finding.title},
        "properties": {
            "category": sample_finding.category,
            "cis_ref": sample_finding.cis_ref,
            "mitre_attack": list(sample_finding.mitre_attack),
            "default_severity": sample_finding.severity.value,
        },
    }


def build_sarif(report: AuditReport) -> dict[str, Any]:
    """Build a SARIF 2.1.0 compliant dictionary from an AuditReport."""
    rules_by_id: dict[str, Finding] = {}
    for finding in report.findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = finding

    driver_rules = [
        _build_driver_rule(rule_id, rules_by_id[rule_id]) for rule_id in sorted(rules_by_id.keys())
    ]

    results: list[dict[str, Any]] = []
    for finding in report.findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_TO_LEVEL[finding.severity],
            "message": {
                "text": (
                    f"{finding.title} (target: {finding.target}; "
                    f"expected: {finding.expected}; actual: {finding.actual})"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _derive_artifact_uri(finding),
                        }
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint,
            },
            "properties": {
                "severity": finding.severity.value,
                "category": finding.category,
                "target": finding.target,
                "drift_status": finding.drift_status.value if finding.drift_status else None,
            },
        }
        if finding.drift_status == DriftStatus.WAIVED:
            result["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": finding.waiver_reason or "Waived by policy",
                }
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "host-audit-ai",
                        "version": __version__,
                        "informationUri": TOOL_INFO_URI,
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def export_sarif(report: AuditReport) -> str:
    """Serialize an AuditReport as SARIF 2.1.0 indented JSON."""
    return json.dumps(build_sarif(report), indent=2)
