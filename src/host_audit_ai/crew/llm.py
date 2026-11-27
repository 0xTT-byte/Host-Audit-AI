"""Model-agnostic BYOM configuration loader, lazy LLM factory, and output parser."""

from __future__ import annotations

import importlib
import json
import os
import re
from contextlib import suppress
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from host_audit_ai.models.triage import LLMConfig

T = TypeVar("T", bound=BaseModel)

_THINK_BLOCK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.IGNORECASE | re.DOTALL)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.IGNORECASE | re.DOTALL)


def _parse_bool_env(raw: str, var_name: str) -> bool:
    norm = raw.strip().lower()
    if norm in {"1", "true", "yes", "on"}:
        return True
    if norm in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value '{raw}' for {var_name}")


def resolve_llm_config_path(explicit_path: Path | None = None) -> Path | None:
    """Resolve llm.yaml path by precedence: explicit > env > XDG > ~/.config."""
    if explicit_path is not None:
        return explicit_path.expanduser()

    env_path = os.environ.get("HOST_AUDIT_LLM_CONFIG", "").strip()
    if env_path:
        return Path(env_path).expanduser()

    xdg_home = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg_home:
        xdg_candidate = Path(xdg_home).expanduser() / "host-audit-ai" / "llm.yaml"
        if xdg_candidate.is_file():
            return xdg_candidate

    home_candidate = Path.home() / ".config" / "host-audit-ai" / "llm.yaml"
    if home_candidate.is_file():
        return home_candidate

    return None


def load_llm_config(
    config_path: Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> LLMConfig:
    """Load LLMConfig merging defaults < YAML < HOST_AUDIT_LLM_* env < cli_overrides."""
    merged: dict[str, Any] = LLMConfig().model_dump()

    resolved_path = resolve_llm_config_path(config_path)
    if resolved_path is not None:
        if not resolved_path.is_file():
            raise FileNotFoundError(f"LLM configuration file not found: {resolved_path}")
        raw_yaml = yaml.safe_load(resolved_path.read_text(encoding="utf-8"))
        if raw_yaml is None:
            yaml_data: dict[str, Any] = {}
        elif isinstance(raw_yaml, dict):
            yaml_data = raw_yaml
        else:
            raise ValueError(f"LLM YAML config must be a mapping: {resolved_path}")

        # Validate YAML fields strictly against LLMConfig contract before merging
        yaml_validated = LLMConfig.model_validate({**merged, **yaml_data})
        merged.update({k: v for k, v in yaml_validated.model_dump().items() if k in yaml_data})

    env_model = os.environ.get("HOST_AUDIT_LLM_MODEL")
    if env_model is not None and env_model.strip():
        merged["model"] = env_model.strip()

    env_base_url = os.environ.get("HOST_AUDIT_LLM_BASE_URL")
    if env_base_url is not None and env_base_url.strip():
        merged["base_url"] = env_base_url.strip()

    env_api_key = os.environ.get("HOST_AUDIT_LLM_API_KEY")
    if env_api_key is not None and env_api_key.strip():
        merged["api_key"] = env_api_key.strip()

    env_temp = os.environ.get("HOST_AUDIT_LLM_TEMPERATURE")
    if env_temp is not None and env_temp.strip():
        merged["temperature"] = float(env_temp.strip())

    env_stream = os.environ.get("HOST_AUDIT_LLM_STREAM")
    if env_stream is not None and env_stream.strip():
        merged["stream"] = _parse_bool_env(env_stream, "HOST_AUDIT_LLM_STREAM")

    env_max_iter = os.environ.get("HOST_AUDIT_LLM_MAX_ITER")
    if env_max_iter is not None and env_max_iter.strip():
        merged["max_iter"] = int(env_max_iter.strip())

    env_delegation = os.environ.get("HOST_AUDIT_LLM_ALLOW_DELEGATION")
    if env_delegation is not None and env_delegation.strip():
        merged["allow_delegation"] = _parse_bool_env(
            env_delegation, "HOST_AUDIT_LLM_ALLOW_DELEGATION"
        )

    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None:
                merged[key] = value

    return LLMConfig.model_validate(merged)


def redacted_config_summary(cfg: LLMConfig) -> dict[str, Any]:
    """Return an operator-safe dictionary summary with api_key masked."""
    return {
        "model": cfg.model,
        "base_url": cfg.base_url,
        "api_key": "***REDACTED***" if cfg.api_key else None,
        "temperature": cfg.temperature,
        "stream": cfg.stream,
        "max_iter": cfg.max_iter,
        "allow_delegation": cfg.allow_delegation,
    }


def build_llm(cfg: LLMConfig) -> Any:
    """Lazily construct a crewai.LLM instance configured for BYOM / 4B GGUF compatibility."""
    try:
        crewai_mod = importlib.import_module("crewai")
        llm_cls = crewai_mod.LLM
    except ImportError as e:
        raise ImportError(
            "CrewAI optional dependencies are required for LLM triage. "
            'Install via: uv pip install "host-audit-ai[crew]"'
        ) from e

    kwargs: dict[str, Any] = {
        "model": cfg.model,
        "base_url": cfg.base_url,
        "temperature": cfg.temperature,
        "stream": cfg.stream,
    }
    if cfg.api_key is not None:
        kwargs["api_key"] = cfg.api_key

    return llm_cls(**kwargs)


def strip_thinking_and_fences(raw_text: str) -> str:
    """Remove <think>...</think> reasoning blocks and Markdown code fences."""
    cleaned = _THINK_BLOCK_RE.sub("", raw_text)

    # Handle unclosed <think> if JSON follows later
    lower = cleaned.lower()
    if "<think" in lower:
        think_idx = lower.find("<think")
        prefix = cleaned[:think_idx]
        suffix = cleaned[think_idx:]
        json_start = _find_first_json_token(suffix)
        cleaned = f"{prefix}\n{suffix[json_start:]}" if json_start is not None else prefix
    elif "</think>" in lower:
        close_idx = lower.rfind("</think>")
        cleaned = cleaned[close_idx + len("</think>") :]

    cleaned = cleaned.strip()

    fence_matches = _FENCE_RE.findall(cleaned)
    if fence_matches:
        # Prefer the fenced block that starts with JSON or last non-empty fenced block
        for block in fence_matches:
            stripped = str(block).strip()
            if stripped.startswith(("{", "[")):
                return stripped
        return str(fence_matches[-1]).strip()

    return cleaned


def _find_first_json_token(text: str) -> int | None:
    obj_idx = text.find("{")
    arr_idx = text.find("[")
    candidates = [idx for idx in (obj_idx, arr_idx) if idx != -1]
    return min(candidates) if candidates else None


def _extract_balanced_json_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch not in ("{", "["):
            i += 1
            continue

        open_ch = ch
        close_ch = "}" if open_ch == "{" else "]"
        depth = 0
        in_string = False
        escape = False
        j = i
        while j < n:
            cur = text[j]
            if in_string:
                if escape:
                    escape = False
                elif cur == "\\":
                    escape = True
                elif cur == '"':
                    in_string = False
            else:
                if cur == '"':
                    in_string = True
                elif cur == open_ch:
                    depth += 1
                elif cur == close_ch:
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[i : j + 1])
                        break
            j += 1
        i += 1
    return candidates


def parse_structured_output(raw_text: str, model_cls: type[T]) -> T:
    """Strip reasoning tags/fences, extract valid JSON, and validate into model_cls."""
    cleaned = strip_thinking_and_fences(raw_text)
    if not cleaned:
        raise ValueError(f"Empty model output could not be parsed as {model_cls.__name__}")

    if cleaned.startswith(("{", "[")):
        with suppress(ValidationError, ValueError):
            return model_cls.model_validate_json(cleaned)

    for candidate in _extract_balanced_json_candidates(cleaned):
        with suppress(ValidationError, json.JSONDecodeError, ValueError):
            json.loads(candidate)
            return model_cls.model_validate_json(candidate)

    raise ValueError(f"Model output could not be parsed into valid {model_cls.__name__} JSON")
