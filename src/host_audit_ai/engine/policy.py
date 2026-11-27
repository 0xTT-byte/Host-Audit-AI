"""Baseline policy and waiver configuration loader."""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import Any

import yaml

from host_audit_ai.models.policy import BaselinePolicy, BaselineRuleOverride, WaiverRule


def _normalize_policy_dict(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Ensure each rule entry in raw YAML dictionary includes its rule_id and uppercase severity."""
    normalized = dict(raw_data)
    raw_rules = raw_data.get("rules")
    if isinstance(raw_rules, dict):
        rules_copy: dict[str, Any] = {}
        for r_id, r_cfg in raw_rules.items():
            if isinstance(r_cfg, dict):
                entry = dict(r_cfg)
                entry.setdefault("rule_id", r_id)
                if isinstance(entry.get("severity_override"), str):
                    entry["severity_override"] = entry["severity_override"].upper()
                rules_copy[r_id] = entry
            else:
                rules_copy[r_id] = r_cfg
        normalized["rules"] = rules_copy
    return normalized


def load_default_baseline() -> BaselinePolicy:
    """Load the built-in default hardening baseline packaged with the distribution."""
    ref = importlib.resources.files("host_audit_ai.engine.baselines").joinpath("default.yaml")
    data = yaml.safe_load(ref.read_text(encoding="utf-8"))
    return BaselinePolicy.model_validate(_normalize_policy_dict(data))


def load_baseline(
    path: Path | str | None = None, merge_with_default: bool = True
) -> BaselinePolicy:
    """Load a custom baseline YAML file, optionally merging onto the default baseline."""
    default_policy = load_default_baseline()
    if path is None:
        return default_policy

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Baseline file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8")
    raw_data = yaml.safe_load(content)
    if not isinstance(raw_data, dict):
        raise ValueError(f"Invalid YAML baseline structure in {file_path}")

    if not merge_with_default:
        return BaselinePolicy.model_validate(_normalize_policy_dict(raw_data))

    # Merge custom overrides onto default policy
    merged_rules: dict[str, BaselineRuleOverride] = dict(default_policy.rules)
    custom_rules_raw: dict[str, Any] = raw_data.get("rules", {})

    for r_id, r_cfg in custom_rules_raw.items():
        if isinstance(r_cfg, dict):
            existing = merged_rules.get(r_id)
            enabled = r_cfg.get("enabled", existing.enabled if existing else True)
            sev_override = r_cfg.get(
                "severity_override", existing.severity_override if existing else None
            )
            if isinstance(sev_override, str):
                sev_override = sev_override.upper()
            params = dict(existing.params) if existing else {}
            params.update(r_cfg.get("params", {}))

            merged_rules[r_id] = BaselineRuleOverride(
                rule_id=r_id,
                enabled=enabled,
                severity_override=sev_override,
                params=params,
            )

    return BaselinePolicy(
        schema_version="1.0.0",
        name=raw_data.get("name", default_policy.name),
        description=raw_data.get("description", default_policy.description),
        rules=merged_rules,
    )


def load_waivers(path: Path | str | None = None) -> list[WaiverRule]:
    """Load waiver exception rules from a YAML file."""
    if path is None:
        return []

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Waiver file not found: {file_path}")

    raw_data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    if not isinstance(raw_data, dict):
        return []

    waivers_list = raw_data.get("waivers", [])
    if not isinstance(waivers_list, list):
        return []

    waivers: list[WaiverRule] = []
    for item in waivers_list:
        if isinstance(item, dict):
            waivers.append(WaiverRule.model_validate(item))

    return waivers
