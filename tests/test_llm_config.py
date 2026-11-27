"""Tests for BYOM LLM configuration loader, redaction, and structured output parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from host_audit_ai.crew.llm import (
    load_llm_config,
    parse_structured_output,
    redacted_config_summary,
    resolve_llm_config_path,
    strip_thinking_and_fences,
)
from host_audit_ai.models.triage import LLMConfig, VerifiedEvidenceBundle


def test_default_llm_config_4b_gguf_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HOST_AUDIT_LLM_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty_xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "empty_home"))
    for var in (
        "HOST_AUDIT_LLM_MODEL",
        "HOST_AUDIT_LLM_BASE_URL",
        "HOST_AUDIT_LLM_API_KEY",
        "HOST_AUDIT_LLM_TEMPERATURE",
        "HOST_AUDIT_LLM_STREAM",
        "HOST_AUDIT_LLM_MAX_ITER",
        "HOST_AUDIT_LLM_ALLOW_DELEGATION",
    ):
        monkeypatch.delenv(var, raising=False)

    cfg = load_llm_config()
    assert cfg.stream is False
    assert cfg.max_iter == 3
    assert cfg.allow_delegation is False
    assert cfg.temperature == 0.1
    assert cfg.base_url == "http://127.0.0.1:11434"
    assert "DeepSeek-V4-Pro-Qwen3.5-4B" in cfg.model


def test_llm_config_precedence_yaml_env_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yaml_file = tmp_path / "llm.yaml"
    yaml_file.write_text(
        "model: openai/gpt-4o-mini\n"
        "base_url: https://api.example.invalid/v1\n"
        "api_key: sk-yaml-secret-key\n"
        "temperature: 0.4\n"
        "stream: true\n"
        "max_iter: 5\n"
        "allow_delegation: false\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HOST_AUDIT_LLM_MODEL", "ollama/qwen2.5:7b")
    monkeypatch.setenv("HOST_AUDIT_LLM_STREAM", "false")
    monkeypatch.setenv("HOST_AUDIT_LLM_API_KEY", "sk-env-secret-key")

    cfg = load_llm_config(
        config_path=yaml_file,
        cli_overrides={"model": "ollama/cli-override:4b", "base_url": None},
    )
    assert cfg.model == "ollama/cli-override:4b"  # CLI > env > YAML
    assert cfg.base_url == "https://api.example.invalid/v1"  # YAML preserved when CLI None
    assert cfg.api_key == "sk-env-secret-key"  # env > YAML
    assert cfg.stream is False  # env > YAML
    assert cfg.temperature == 0.4  # YAML > default
    assert cfg.max_iter == 5

    summary = redacted_config_summary(cfg)
    assert summary["api_key"] == "***REDACTED***"
    assert "sk-env-secret-key" not in str(summary)
    assert summary["model"] == "ollama/cli-override:4b"


def test_resolve_llm_config_path_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = tmp_path / "explicit.yaml"
    env_cfg = tmp_path / "env.yaml"
    xdg_dir = tmp_path / "xdg"
    xdg_cfg = xdg_dir / "host-audit-ai" / "llm.yaml"
    xdg_cfg.parent.mkdir(parents=True)
    xdg_cfg.write_text("temperature: 0.2\n", encoding="utf-8")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.delenv("HOST_AUDIT_LLM_CONFIG", raising=False)
    assert resolve_llm_config_path() == xdg_cfg

    monkeypatch.setenv("HOST_AUDIT_LLM_CONFIG", str(env_cfg))
    assert resolve_llm_config_path() == env_cfg
    assert resolve_llm_config_path(explicit) == explicit


def test_strip_thinking_and_parse_structured_output() -> None:
    raw = (
        "<think>\nLet me analyze the findings carefully...\n"
        'Wait maybe {"wrong": true} inside think.\n</think>\n'
        "Here is the verified output:\n"
        "```json\n"
        '{"items": [{"finding_fingerprint": "fp-1", "verified": true, '
        '"live_observation": "Port 22 open", "confidence": "high"}]}\n'
        "```\n"
    )
    cleaned = strip_thinking_and_fences(raw)
    assert "<think>" not in cleaned
    parsed = parse_structured_output(raw, VerifiedEvidenceBundle)
    assert len(parsed.items) == 1
    assert parsed.items[0].finding_fingerprint == "fp-1"
    assert parsed.items[0].verified is True

    # Unclosed <think> followed by JSON object
    unclosed = (
        '<think>reasoning never closed\n{"items": [{"finding_fingerprint": "fp-2", '
        '"verified": false, "live_observation": "Filtered", "confidence": "medium"}]}'
    )
    parsed2 = parse_structured_output(unclosed, VerifiedEvidenceBundle)
    assert parsed2.items[0].finding_fingerprint == "fp-2"

    # Malformed output raises ValueError
    with pytest.raises(ValueError, match="could not be parsed"):
        parse_structured_output("<think>only thoughts</think> no json here", VerifiedEvidenceBundle)
    with pytest.raises(ValueError, match="could not be parsed"):
        parse_structured_output('{"unexpected": 123}', VerifiedEvidenceBundle)


def test_load_llm_config_missing_explicit_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_llm_config(config_path=tmp_path / "does_not_exist.yaml")

    assert isinstance(LLMConfig().stream, bool)
