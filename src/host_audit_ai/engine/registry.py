"""Rule metadata and deterministic rule registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from host_audit_ai.models.finding import Finding, Severity
from host_audit_ai.models.snapshot import HostSnapshot


@dataclass(frozen=True)
class RuleMeta:
    """Static metadata defining a deterministic security audit rule."""

    rule_id: str
    title: str
    default_severity: Severity
    category: str
    cis_ref: str | None = None
    mitre_attack: list[str] = field(default_factory=list)


RuleFn = Callable[[HostSnapshot, dict[str, Any]], list[Finding]]


class RuleRegistry:
    """Thread-safe, deterministic sorted registry of all auditing rules."""

    _registry: dict[str, tuple[RuleMeta, RuleFn]] = {}

    @classmethod
    def register(cls, meta: RuleMeta) -> Callable[[RuleFn], RuleFn]:
        """Decorator to register a rule function with metadata."""

        def decorator(fn: RuleFn) -> RuleFn:
            cls._registry[meta.rule_id] = (meta, fn)
            return fn

        return decorator

    @classmethod
    def get_rule(cls, rule_id: str) -> tuple[RuleMeta, RuleFn] | None:
        return cls._registry.get(rule_id)

    @classmethod
    def all_rules(cls) -> list[tuple[RuleMeta, RuleFn]]:
        """Return all rules deterministically sorted by rule_id."""
        return [cls._registry[k] for k in sorted(cls._registry.keys())]

    @classmethod
    def count(cls) -> int:
        return len(cls._registry)

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()
