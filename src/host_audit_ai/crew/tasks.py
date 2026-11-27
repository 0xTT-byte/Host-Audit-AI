"""CrewAI task definitions for each isolated stage of the triage pipeline."""

from __future__ import annotations

import json

from crewai import Agent, Task

from host_audit_ai.models.triage import (
    AdvisoryBundle,
    AdvisoryMatch,
    SanitizedQueryItem,
    Stage3Plan,
    VerifiedEvidence,
    VerifiedEvidenceBundle,
)


def create_host_inspection_task(
    agent: Agent,
    wrapped_ai_bundle: str,
    live_ssh_enabled: bool,
) -> Task:
    """Create Stage 1 task inspecting wrapped AI bundle telemetry (optionally with SSH tools)."""
    mode_instruction = (
        "Live read-only SSH inspection tools are enabled. Use them only to verify ambiguous or "
        "critical findings referenced by fingerprint in the bundle."
        if live_ssh_enabled
        else "Offline mode is active (no SSH tools are attached). Evaluate and verify findings "
        "strictly using the evidence snippets and exposure chains inside the bundle below."
    )

    description = (
        f"{mode_instruction}\n\n"
        "Return ONLY valid JSON matching the VerifiedEvidenceBundle schema:\n"
        '{"items": [{"finding_fingerprint": "<sha256_or_id>", "verified": true, '
        '"live_observation": "<concise observation>", "confidence": "high|medium|low"}]}\n\n'
        f"{wrapped_ai_bundle}"
    )

    return Task(
        description=description,
        expected_output=(
            "Valid JSON object conforming to VerifiedEvidenceBundle with an 'items' list of "
            "VerifiedEvidence records."
        ),
        agent=agent,
        output_pydantic=VerifiedEvidenceBundle,
    )


def create_cve_research_task(
    agent: Agent,
    sanitized_items: list[SanitizedQueryItem],
) -> Task:
    """Create Stage 2 task receiving ONLY strictly sanitized software/OS/rule metadata."""
    sanitized_json = json.dumps(
        [item.model_dump() for item in sanitized_items],
        indent=2,
    )

    description = (
        "Research public CVE advisories, fixed versions, and official hardening documentation "
        "for the following sanitized software/OS/rule tuples.\n"
        "Return ONLY valid JSON matching the AdvisoryBundle schema:\n"
        '{"items": [{"cve_id": "CVE-YYYY-NNNN or null", "reference_url": "https://...", '
        '"summary": "<concise summary>", "fixed_version": "<version or null>"}]}\n\n'
        "Sanitized query items:\n"
        f"{sanitized_json}"
    )

    return Task(
        description=description,
        expected_output=(
            "Valid JSON object conforming to AdvisoryBundle with an 'items' list of "
            "AdvisoryMatch records."
        ),
        agent=agent,
        output_pydantic=AdvisoryBundle,
    )


def create_playbook_builder_task(
    agent: Agent,
    wrapped_ai_bundle: str,
    verified: list[VerifiedEvidence],
    advisories: list[AdvisoryMatch],
    human_input: bool = True,
) -> Task:
    """Create Stage 3 remediation synthesis task with optional human approval gate."""
    verified_json = json.dumps([v.model_dump() for v in verified], indent=2)
    advisories_json = json.dumps([a.model_dump() for a in advisories], indent=2)

    description = (
        "Synthesize the verified host evidence and advisory matches into an executive remediation "
        "summary, and draft idempotent, non-destructive remediation scripts using the "
        "write_remediation_skill tool (flat filenames ending in .sh, .py, .yml, .yaml, or .md).\n\n"
        "Return ONLY valid JSON matching the Stage3Plan schema:\n"
        '{"executive_summary": "<concise prioritization and impact summary>", '
        '"artifacts": [{"filename": "remediate.sh", "language": "bash", '
        '"summary": "<what it fixes>", "approved": false}]}\n\n'
        "Verified Evidence:\n"
        f"{verified_json}\n\n"
        "Public Advisories:\n"
        f"{advisories_json}\n\n"
        f"{wrapped_ai_bundle}"
    )

    return Task(
        description=description,
        expected_output=(
            "Valid JSON object conforming to Stage3Plan with executive_summary and artifacts."
        ),
        agent=agent,
        human_input=human_input,
        output_pydantic=Stage3Plan,
    )
