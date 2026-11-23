# Contributing to host-audit-ai

Thank you for contributing to `host-audit-ai`!

## Design Principles

1. **Split Execution**: The remote collector (`collect/audit-collect.sh`) must remain agentless, read-only, and completely silent on stdout. Never introduce write operations or heavy dependencies to the target server collector.
2. **Deterministic First**: Rules compute differences against the YAML baseline (`observed - expected`). All finding IDs must be stable SHA-256 hashes based on the rule ID, target, and evidence.
3. **Structured Schemas**: LLM triage uses strict Pydantic JSON schemas via Ollama's native structured outputs.

## Development Workflow

1. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
2. Run unit tests before submitting changes:
   ```bash
   pytest -v
   ```
3. Ensure bash scripts pass static analysis:
   ```bash
   shellcheck collect/audit-collect.sh scripts/run-remote-audit.sh
   ```

## Adding New Rules

- Place new rule checks in `src/host_audit/rules/`.
- Ensure each rule populates `rule_id`, `domain`, `title`, `target`, `evidence`, `why_it_matters`, `verify_cmd`, and `remediation_hint`.
- Provide reachability, privilege gain, and ease scores between 1 and 3.
- Add test coverage verifying detection in `tests/fixtures/vulnerable_host/` and clean execution in `tests/fixtures/clean_host/`.
