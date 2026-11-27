"""3-stage air-gapped CrewAI triage orchestrator with deterministic firewall."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TypeVar

from crewai import Crew, Process
from pydantic import BaseModel

from host_audit_ai.crew.agents import (
    create_cve_researcher_agent,
    create_host_inspector_agent,
    create_playbook_builder_agent,
)
from host_audit_ai.crew.llm import build_llm, parse_structured_output
from host_audit_ai.crew.mcp_tools import (
    SSHServerConfig,
    ssh_mcp_adapter,
    web_mcp_adapter,
)
from host_audit_ai.crew.sanitizer import (
    assert_no_host_leakage,
    build_sanitized_queries,
    collect_forbidden_tokens,
    wrap_untrusted_telemetry,
)
from host_audit_ai.crew.skills_writer import (
    JailedSkillsWriter,
    build_skills_writer_crewai_tool,
)
from host_audit_ai.crew.tasks import (
    create_cve_research_task,
    create_host_inspection_task,
    create_playbook_builder_task,
)
from host_audit_ai.exporters.ai_bundle import build_ai_bundle
from host_audit_ai.models.report import AuditReport
from host_audit_ai.models.snapshot import HostSnapshot
from host_audit_ai.models.triage import (
    AdvisoryBundle,
    AdvisoryMatch,
    LLMConfig,
    TriageReport,
    VerifiedEvidence,
    VerifiedEvidenceBundle,
)

T = TypeVar("T", bound=BaseModel)


class StageRunner(Protocol):
    """Protocol for executing a single-stage Crew (injectable for deterministic testing)."""

    def __call__(self, stage_name: str, crew: Crew) -> Any: ...


@dataclass(frozen=True)
class TriagePipelineOptions:
    """Execution options for the 3-stage air-gapped triage pipeline."""

    llm_config: LLMConfig
    ssh_config: SSHServerConfig | None = None
    enable_web_research: bool = True
    skills_dir: Path = Path("./skills")
    human_input: bool = True
    max_findings: int = 30
    verbose: bool = False


def _default_stage_runner(_stage_name: str, crew: Crew) -> Any:
    return crew.kickoff()


def _extract_stage_model(result: Any, model_cls: type[T]) -> T:
    if isinstance(result, model_cls):
        return result

    pydantic_obj = getattr(result, "pydantic", None)
    if isinstance(pydantic_obj, model_cls):
        return pydantic_obj

    json_dict = getattr(result, "json_dict", None)
    if isinstance(json_dict, dict):
        return model_cls.model_validate(json_dict)

    raw_text = getattr(result, "raw", None)
    text_to_parse = raw_text if isinstance(raw_text, str) else str(result)
    return parse_structured_output(text_to_parse, model_cls)


def run_triage_pipeline(
    report: AuditReport,
    snapshot: HostSnapshot | None,
    options: TriagePipelineOptions,
    *,
    crew_runner: StageRunner | None = None,
) -> TriageReport:
    """Execute the strictly isolated 3-stage BYOM triage pipeline."""
    from host_audit_ai.models.triage import Stage3Plan

    runner = crew_runner or _default_stage_runner

    ai_bundle = build_ai_bundle(
        report,
        snapshot=snapshot,
        max_findings=options.max_findings,
    )
    wrapped_bundle = wrap_untrusted_telemetry(ai_bundle.model_dump_json(indent=2))
    llm = build_llm(options.llm_config)

    # ------------------------------------------------------------------
    # Stage 1: Host Inspector (SSH tools only; closed before Stage 2 opens)
    # ------------------------------------------------------------------
    with ExitStack() as stage1_stack:
        ssh_tools: list[Any] = []
        if options.ssh_config is not None:
            loaded_ssh_tools = stage1_stack.enter_context(ssh_mcp_adapter(options.ssh_config))
            ssh_tools = list(loaded_ssh_tools)

        agent1 = create_host_inspector_agent(
            llm=llm,
            cfg=options.llm_config,
            ssh_tools=ssh_tools,
            verbose=options.verbose,
        )
        task1 = create_host_inspection_task(
            agent=agent1,
            wrapped_ai_bundle=wrapped_bundle,
            live_ssh_enabled=options.ssh_config is not None,
        )
        crew1 = Crew(
            agents=[agent1],
            tasks=[task1],
            process=Process.sequential,
            memory=False,
            verbose=options.verbose,
        )
        stage1_raw = runner("stage1_host_inspector", crew1)

    stage1_bundle = _extract_stage_model(stage1_raw, VerifiedEvidenceBundle)
    verified_items: list[VerifiedEvidence] = list(stage1_bundle.items)

    # ------------------------------------------------------------------
    # Deterministic Sanitization Firewall (Zero host PII across boundary)
    # ------------------------------------------------------------------
    sanitized_items = build_sanitized_queries(
        report=report,
        snapshot=snapshot,
        verified=verified_items,
    )
    forbidden_tokens = collect_forbidden_tokens(report, snapshot)
    assert_no_host_leakage(sanitized_items, forbidden_tokens)

    # ------------------------------------------------------------------
    # Stage 2: CVE Researcher (Web tools only; SSH strictly closed)
    # ------------------------------------------------------------------
    advisory_items: list[AdvisoryMatch] = []
    if options.enable_web_research and sanitized_items:
        with web_mcp_adapter() as web_tools:
            agent2 = create_cve_researcher_agent(
                llm=llm,
                cfg=options.llm_config,
                web_tools=list(web_tools),
                verbose=options.verbose,
            )
            task2 = create_cve_research_task(
                agent=agent2,
                sanitized_items=sanitized_items,
            )
            crew2 = Crew(
                agents=[agent2],
                tasks=[task2],
                process=Process.sequential,
                memory=False,
                verbose=options.verbose,
            )
            stage2_raw = runner("stage2_cve_researcher", crew2)

        stage2_bundle = _extract_stage_model(stage2_raw, AdvisoryBundle)
        advisory_items = list(stage2_bundle.items)

    # ------------------------------------------------------------------
    # Stage 3: Playbook Builder (Jailed ./skills/ writer only)
    # ------------------------------------------------------------------
    writer = JailedSkillsWriter(base_dir=options.skills_dir)
    skills_tool = build_skills_writer_crewai_tool(writer)
    agent3 = create_playbook_builder_agent(
        llm=llm,
        cfg=options.llm_config,
        skills_tools=[skills_tool],
        verbose=options.verbose,
    )
    task3 = create_playbook_builder_task(
        agent=agent3,
        wrapped_ai_bundle=wrapped_bundle,
        verified=verified_items,
        advisories=advisory_items,
        human_input=options.human_input,
    )
    crew3 = Crew(
        agents=[agent3],
        tasks=[task3],
        process=Process.sequential,
        memory=False,
        verbose=options.verbose,
    )
    stage3_raw = runner("stage3_playbook_builder", crew3)
    stage3_plan = _extract_stage_model(stage3_raw, Stage3Plan)

    return TriageReport(
        run_id=report.run_id,
        llm_model=options.llm_config.model,
        created_at=datetime.now(UTC),
        executive_summary=stage3_plan.executive_summary.strip(),
        verified_evidence=verified_items,
        advisories=advisory_items,
        artifacts=list(writer.written_artifacts),
    )
