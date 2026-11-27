# Contributing to host-audit-ai

Thank you for contributing to `host-audit-ai`!

## Design Principles

1. **Split Execution**: The remote collector (`src/host_audit_ai/collectors/scripts/collect.sh`) must remain agentless, POSIX/Bash read-only, and never write temporary files to the target filesystem (streaming framed telemetry over `stdout` only).
2. **Deterministic First**: Rules evaluate normalized `HostSnapshot` state against the YAML baseline (`src/host_audit_ai/engine/baselines/default.yaml`). All finding fingerprints must be stable SHA-256 hashes computed via `compute_fingerprint(rule_id, normalized_target, key_attribute)` without volatile PIDs or timestamps.
3. **Structured Schemas**: All core and `[crew]` contracts use strict Pydantic v2 models (`extra="forbid"`), and optional AI triage uses a 3-stage air-gapped CrewAI pipeline (`src/host_audit_ai/crew/`) across BYOM providers (Ollama, OpenAI-compatible, or Anthropic).

## Development Workflow

1. Install development dependencies:
   ```bash
   uv pip install -e ".[dev]"
   ```
2. Run linters, type checks, and unit tests before submitting changes:
   ```bash
   ruff check .
   ruff format --check .
   mypy src tests
   pytest -v -m "not e2e"
   ```
3. Ensure bash scripts pass syntax and static analysis:
   ```bash
   bash -n src/host_audit_ai/collectors/scripts/collect.sh src/host_audit_ai/collectors/scripts/host-audit-wrapper.sh
   shellcheck src/host_audit_ai/collectors/scripts/collect.sh src/host_audit_ai/collectors/scripts/host-audit-wrapper.sh
   ```

## Adding New Rules

- Place new rule checks in `src/host_audit_ai/engine/rules/` and register them via `@RuleRegistry.register(RuleMeta(...))`.
- Add default enablement and baseline parameters in `src/host_audit_ai/engine/baselines/default.yaml`.
- Ensure each `Finding` populates `rule_id`, `title`, `severity`, `category`, `target`, `key_attribute`, `expected`, `actual`, `evidence`, `cis_ref`, `mitre_attack`, and `fingerprint`.
- Add unit tests in `tests/test_rules.py` verifying detection against vulnerable captures (e.g., `tests/fixtures/phase2/ubuntu_vulnerable.raw`) and clean passes against hardened fixtures (e.g., `tests/fixtures/phase2/ubuntu_hardened.raw`).
