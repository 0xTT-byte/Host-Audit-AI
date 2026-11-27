"""Spy & isolation tests for the 3-stage air-gapped CrewAI triage pipeline."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from host_audit_ai.collectors import OfflineTransport
from host_audit_ai.crew.mcp_tools import SSHServerConfig
from host_audit_ai.crew.sanitizer import collect_forbidden_tokens
from host_audit_ai.engine import evaluate, load_baseline
from host_audit_ai.models.triage import LLMConfig, TriageReport
from host_audit_ai.parsers import parse_envelope
from host_audit_ai.storage import AuditStore

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "phase2"


def _prep_crewai_sandbox_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    monkeypatch.setenv("CREWAI_STORAGE_DIR", "host-audit-ai-test")


def test_crew_pipeline_airgap_spy_and_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prep_crewai_sandbox_env(tmp_path, monkeypatch)
    crewai = pytest.importorskip("crewai")

    from host_audit_ai.crew import pipeline as pipeline_mod

    _, env = OfflineTransport(FIXTURES_DIR / "ubuntu_vulnerable.raw").collect()
    snapshot = parse_envelope(env)
    report = evaluate(snapshot, load_baseline())

    # Inject sensitive tokens into fixture to verify Stage 2 never receives them
    report.hostname = "prod-db-01.corp.internal"
    snapshot.metadata.hostname = "prod-db-01.corp.internal"
    forbidden_tokens = collect_forbidden_tokens(report, snapshot)

    lifecycle: list[str] = []
    captured_crews: dict[str, Any] = {}

    # Use real BaseTool subclasses so CrewAI Agent validates tools cleanly
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field

    base_tool_cls: Any = BaseTool

    class _DummyArgs(BaseModel):
        arg: str = Field(default="ok")

    class _SpyTool(base_tool_cls):  # type: ignore[misc]
        name: str
        description: str = "Spy mock tool"
        args_schema: type[BaseModel] = _DummyArgs

        def _run(self, arg: str = "ok") -> str:
            return arg

    @contextmanager
    def real_ssh_adapter(_cfg: SSHServerConfig) -> Iterator[list[Any]]:
        lifecycle.append("ssh_enter")
        try:
            yield [_SpyTool(name="ssh_inspect_unit"), _SpyTool(name="ssh_read_config")]
        finally:
            lifecycle.append("ssh_exit")

    @contextmanager
    def real_web_adapter() -> Iterator[list[Any]]:
        lifecycle.append("web_enter")
        try:
            yield [_SpyTool(name="duckduckgo_search"), _SpyTool(name="fetch_url")]
        finally:
            lifecycle.append("web_exit")

    monkeypatch.setattr(pipeline_mod, "ssh_mcp_adapter", real_ssh_adapter)
    monkeypatch.setattr(pipeline_mod, "web_mcp_adapter", real_web_adapter)

    def spy_runner(stage_name: str, crew: Any) -> str:
        lifecycle.append(stage_name)
        captured_crews[stage_name] = crew

        if stage_name == "stage1_host_inspector":
            fp = report.findings[0].fingerprint
            return (
                "<think>Checking port reachability.</think>\n"
                "```json\n"
                + json.dumps(
                    {
                        "items": [
                            {
                                "finding_fingerprint": fp,
                                "verified": True,
                                "live_observation": "Confirmed listening on wildcard socket.",
                                "confidence": "high",
                            }
                        ]
                    }
                )
                + "\n```"
            )
        if stage_name == "stage2_cve_researcher":
            return json.dumps(
                {
                    "items": [
                        {
                            "cve_id": "CVE-2024-6387",
                            "reference_url": "https://ubuntu.com/security/CVE-2024-6387",
                            "summary": "OpenSSH hardening and regression fix.",
                            "fixed_version": "1:8.9p1-3ubuntu0.10",
                        }
                    ]
                }
            )
        if stage_name == "stage3_playbook_builder":
            # Simulate Agent 3 invoking its jailed skills_writer tool
            agent3 = crew.agents[0]
            skills_tool = agent3.tools[0]
            skills_tool._run(
                filename="harden_ssh.sh",
                content="#!/usr/bin/env bash\nset -euo pipefail\necho harden ssh\n",
                summary="Disable root login and password auth in sshd_config.",
            )
            return json.dumps(
                {
                    "executive_summary": (
                        "Hardening SSH and closing public sockets cuts top chains."
                    ),
                    "artifacts": [
                        {
                            "filename": "hallucinated_not_written.sh",
                            "language": "bash",
                            "summary": "Should be ignored because not written to disk",
                            "approved": True,
                        }
                    ],
                }
            )
        raise AssertionError(f"Unexpected stage: {stage_name}")

    key_file = tmp_path / "id_ed25519"
    key_file.write_text("DUMMY_KEY", encoding="utf-8")
    skills_dir = tmp_path / "skills"
    llm_cfg = LLMConfig()

    options = pipeline_mod.TriagePipelineOptions(
        llm_config=llm_cfg,
        ssh_config=SSHServerConfig(target="ssh://auditor@10.0.0.5:22", identity_file=key_file),
        enable_web_research=True,
        skills_dir=skills_dir,
        human_input=True,
    )

    triage_report = pipeline_mod.run_triage_pipeline(
        report=report,
        snapshot=snapshot,
        options=options,
        crew_runner=spy_runner,
    )

    # 1. Temporal Air-Gap: SSH session exited completely BEFORE Web MCP entered
    assert lifecycle == [
        "ssh_enter",
        "stage1_host_inspector",
        "ssh_exit",
        "web_enter",
        "stage2_cve_researcher",
        "web_exit",
        "stage3_playbook_builder",
    ]
    assert lifecycle.index("ssh_exit") < lifecycle.index("web_enter")

    # 2. Verify every Crew stage has memory=False, Process.sequential, and 4B GGUF LLM flags
    for stage_name in (
        "stage1_host_inspector",
        "stage2_cve_researcher",
        "stage3_playbook_builder",
    ):
        crew_obj = captured_crews[stage_name]
        assert crew_obj.memory is False
        assert crew_obj.process == crewai.Process.sequential
        assert len(crew_obj.agents) == 1
        assert len(crew_obj.tasks) == 1
        ag = crew_obj.agents[0]
        assert ag.allow_delegation is False
        assert ag.max_iter == 3
        assert ag.llm.stream is False
        assert ag.llm.temperature == 0.1

    # 3. Stage 1 isolation: ONLY SSH tools, telemetry wrapped in untrusted tags
    s1_tools = {t.name for t in captured_crews["stage1_host_inspector"].agents[0].tools}
    assert s1_tools == {"ssh_inspect_unit", "ssh_read_config"}
    s1_desc = captured_crews["stage1_host_inspector"].tasks[0].description
    assert "<untrusted_host_telemetry>" in s1_desc
    assert "</untrusted_host_telemetry>" in s1_desc

    # 4. Stage 2 isolation: ONLY web tools, ZERO host PII in task description
    s2_tools = {t.name for t in captured_crews["stage2_cve_researcher"].agents[0].tools}
    assert s2_tools == {"duckduckgo_search", "fetch_url"}
    s2_desc = captured_crews["stage2_cve_researcher"].tasks[0].description
    for tok in forbidden_tokens:
        assert tok.lower() not in s2_desc.lower(), f"Stage 2 prompt leaked token: {tok}"

    # 5. Stage 3 isolation: ONLY skills_writer tool, human_input=True, verified on-disk artifact
    s3_tools = {t.name for t in captured_crews["stage3_playbook_builder"].agents[0].tools}
    assert s3_tools == {"write_remediation_skill"}
    assert captured_crews["stage3_playbook_builder"].tasks[0].human_input is True

    written_path = skills_dir / "harden_ssh.sh"
    assert written_path.is_file()
    if os.name == "posix":
        assert (written_path.stat().st_mode & 0o777) == 0o644

    # Returned artifacts must reflect actual on-disk writes (hallucinated model claims ignored)
    assert isinstance(triage_report, TriageReport)
    assert len(triage_report.artifacts) == 1
    assert triage_report.artifacts[0].filename == "harden_ssh.sh"
    assert triage_report.artifacts[0].approved is False
    sha = triage_report.artifacts[0].sha256
    assert sha is not None and len(sha) == 64

    # 6. SQLite persistence round-trip across two models on the same run_id
    db_file = tmp_path / "triage.db"
    with AuditStore(db_path=db_file) as store:
        store.save_run(report, snapshot)
        store.save_triage(triage_report)

        second_triage = triage_report.model_copy(
            update={"llm_model": "ollama/llama3.2:3b", "executive_summary": "Second run"}
        )
        store.save_triage(second_triage)

        persisted = store.get_triage_runs(report.run_id)
        assert len(persisted) == 2
        assert {p.llm_model for p in persisted} == {llm_cfg.model, "ollama/llama3.2:3b"}
        assert any(p == triage_report for p in persisted)


def test_crew_pipeline_offline_and_no_web_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prep_crewai_sandbox_env(tmp_path, monkeypatch)
    pytest.importorskip("crewai")

    from host_audit_ai.crew import pipeline as pipeline_mod

    _, env = OfflineTransport(FIXTURES_DIR / "ubuntu_vulnerable.raw").collect()
    snapshot = parse_envelope(env)
    report = evaluate(snapshot, load_baseline())

    def fail_if_called(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("MCP adapter must not be called in offline / --no-web mode")

    monkeypatch.setattr(pipeline_mod, "ssh_mcp_adapter", fail_if_called)
    monkeypatch.setattr(pipeline_mod, "web_mcp_adapter", fail_if_called)

    seen_stages: list[str] = []

    def spy_runner(stage_name: str, crew: Any) -> str:
        seen_stages.append(stage_name)
        if stage_name == "stage1_host_inspector":
            assert crew.agents[0].tools == []
            return '{"items": []}'
        if stage_name == "stage3_playbook_builder":
            assert crew.tasks[0].human_input is False
            return '{"executive_summary": "Air-gapped summary.", "artifacts": []}'
        raise AssertionError(f"Unexpected stage: {stage_name}")

    options = pipeline_mod.TriagePipelineOptions(
        llm_config=LLMConfig(),
        ssh_config=None,
        enable_web_research=False,
        skills_dir=tmp_path / "skills",
        human_input=False,
    )
    res = pipeline_mod.run_triage_pipeline(report, snapshot, options, crew_runner=spy_runner)
    assert seen_stages == ["stage1_host_inspector", "stage3_playbook_builder"]
    assert res.advisories == []
    assert res.executive_summary == "Air-gapped summary."
