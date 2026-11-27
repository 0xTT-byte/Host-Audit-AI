# Changelog

All notable changes to `host-audit-ai` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-27

### Added
- **Disposable Docker E2E Security Lab (`tests/e2e/`)**:
  - Added reproducible Ubuntu 24.04 vulnerable target (`tests/e2e/Dockerfile.vuln` and `entrypoint.sh`) seeding SSH, sudoers, shadow permissions, SUID, cron, and temporary executable findings alongside dual SSH access (`audituser` collection + `auditmcp` forced-command wrapper).
  - Added `@pytest.mark.e2e` live SSH integration suite (`tests/e2e/test_e2e_docker.py`) validating zero target disk writes, live `RESOLVED` drift diffing, forced-command wrapper rejections (`exit 126`), SARIF 2.1.0 export, and sanitizer zero-leakage.
- **Security, Architecture & Operator Documentation**:
  - Added `SECURITY.md` documenting supported versions, vulnerability reporting, and the 6-layer threat model.
  - Added `ARCHITECTURE.md` documenting end-to-end Mermaid data flow, AST module dependency matrix, schema versioning, fingerprinting, and `LLMConfig` precedence.
  - Added ready-to-use BYOM YAML profiles under `examples/llm/` (`ollama-4b-local.yaml`, `ollama-32b.yaml`, `vllm-openai-compat.yaml`, `litellm-gateway.yaml`).
  - Rewrote `README.md` for `v1.0.0` with `uvx` / `uv tool install` instructions, all 8 subcommands, exit code table, and accurate 31-rule catalog.
- **OIDC Release Automation & E2E CI**:
  - Added `.github/workflows/release.yml` triggered on `v*` tags to verify tag/version parity, run full checks, build wheels/sdists, generate `SHA256SUMS.txt` plus CycloneDX & SPDX SBOMs (`anchore/sbom-action`), publish to PyPI via OIDC Trusted Publishing, and create GitHub Releases.
  - Updated `.github/workflows/ci.yml` to run unit/lint checks (`-m "not e2e"`) across Python 3.11–3.13 and execute live Docker E2E verification (`-m e2e`).

### Changed & Removed
- Polished `crew/sanitizer.py` so `linux-kernel` findings automatically derive `package_version` from normalized `kernel_version` when package metadata is absent.
- Updated `parsers/containers_ioc.py` (`parse_ioc_surface`) to also track `ls -la /tmp /var/tmp /dev/shm` directory header blocks produced on live Linux hosts.
- Retired quarantined `v0.1.0` legacy code (`src/host_audit_ai/legacy/`), obsolete root `baseline/` / `baselines/` duplicates, `collect/audit-collect.sh`, and legacy `scripts/`.

## [0.6.0] - 2026-11-27

### Added
- **BYOM LLM Configuration & Model Adapter (`crew/llm.py`)**:
  - Precedence configuration loader merging defaults, `~/.config/host-audit-ai/llm.yaml`, `HOST_AUDIT_LLM_*` environment variables, and CLI overrides.
  - Multi-provider support (Ollama, OpenAI-compatible, Anthropic) with model parsing, safe redacted summaries, and lazy CrewAI `LLM` instantiation.
  - 4B GGUF model compatibility pipeline with `stream=False`, `temperature=0.1`, `max_iter=3`, `allow_delegation=False`, and automated `<think>...</think>` tag and Markdown code-fence stripping before Pydantic validation.
- **Deterministic PII Sanitization Firewall (`crew/sanitizer.py`)**:
  - High-assurance token extractor collecting all forbidden tokens (IPs, hostnames, usernames, internal subnets) from raw host telemetry.
  - Automated prompt-injection insulation wrapping raw evidence in `<untrusted_host_telemetry>` boundaries.
  - Outbound query generator restricting Web Search queries strictly to public technology and vulnerability identifiers (CVEs, service names, software versions).
  - Pre-flight firewall assertion (`assert_no_host_leakage`) preventing accidental data exfiltration before Web Search execution.
- **Three-Stage Discrete CrewAI Triage Pipeline (`crew/agents.py`, `crew/tasks.py`, `crew/pipeline.py`)**:
  - Discrete single-stage `Crew` kickoffs with `memory=False` and `Process.sequential` to eliminate implicit context bleed.
  - Stage 1 (Verification Agent): Scoped read-only investigation using parameterized `audit-ssh` tools to verify active findings without full shell access.
  - Temporal air-gap firewall: Deterministic sanitization pass executing strictly between Stage 1 and Stage 2.
  - Stage 2 (Threat Intel Agent): Search queries filtered through the sanitizer firewall using scoped Web Search tools to look up relevant CVE advisories and mitigation guidance.
  - Stage 3 (Remediation Planner Agent): Generates structured remediation playbooks and security hardening recommendations, constrained to write skills exclusively through `JailedSkillsWriter` with on-disk SHA-256 verification and optional `human_input=True` approval gate.
- **CLI Subcommand & Persistence Integration**:
  - `host-audit triage` command supporting `--dry-run-sanitizer`, `--no-web`, `--ssh-target`, `--human-input`, `--model`, and custom LLM provider configuration.
  - SQLite persistence integration recording `triage_runs` linked to parent audit runs with JSON-serialized findings, evidence, threat intel, and artifact metadata.

## [0.5.0] - 2026-11-27

### Added
- **Core Architecture & Schemas (Phase 0)**:
  - Strong Pydantic v2 schemas across raw collector envelopes, normalized host snapshots, security findings, audit reports, and drift state.
  - Strict AST boundary enforcement isolating AI/MCP dependencies exclusively to optional packages.
- **Agentless 18-Section Collector & Multi-Transport (Phase 1)**:
  - POSIX/Bash read-only target collector (`collect.sh`) streaming evidence securely over stdout with trap-based ephemeral cleanup.
  - Section framing with size clamping, anti-spoofing delimiters, and degraded-mode fallback when unprivileged.
  - Multi-transport execution engine supporting `LocalTransport`, `SSHTransport`, and `OfflineTransport`.
- **Deterministic Evaluation & Policy Engine (Phase 2)**:
  - 9 pure parsers extracting normalized state (network listeners, processes, services, cron, users, sudoers, file permissions, kernel parameters, firewall rules, containers, IOCs).
  - RuleRegistry with 31 deterministic security rules spanning 7 rule modules (`exposure`, `ssh_users`, `containers`, `fs_cron`, `kernel_fw`, `privesc`, `ioc`).
  - YAML baseline policy loader (`default.yaml`) and expiring waiver engine.
- **Deterministic Exposure Correlator & SQLite Drift Store (Phase 3)**:
  - Pre-LLM 4-class graph exposure correlator constructing multi-stage attack chains without LLM inference.
  - `0o600` file-permission SQLite audit history database (`AuditStore`) with schema migrations.
  - 3-run drift diff engine (`diff_runs`) tracking `NEW`, `PERSISTENT`, `RESOLVED`, `REGRESSED`, and `WAIVED` findings across audit runs.
  - Multi-format report exporters: standard JSON, SARIF 2.1.0, human-readable Markdown, and sanitized context-bounded `ai-bundle`.
  - Comprehensive CLI subcommands: `scan`, `diff`, `export`, and `runs`.
- **Hardened Remote Provisioning & Scoped MCP Servers (Phase 4)**:
  - Target-side POSIX forced-command wrapper script (`host-audit-wrapper.sh`) restricting SSH key capabilities to 6 read-only verbs with strict path and argument validation.
  - Zero-AI `host-audit init-target` command generating hardened `authorized_keys` bundles and installation guides.
  - Read-only `audit-ssh` FastMCP server exposing parameterized inspection tools without shell execution capabilities.
  - Security-isolated `JailedSkillsWriter` enforcing target directory path traversal protection (`0o644`, `O_NOFOLLOW`).

## [0.2.0] - 2026-11-24

### Added
- **Optional Local LLM Triage Layer**:
  - Integrated local AI triage powered by Ollama, activated via optional extra `host-audit-ai[llm]`.
  - Added CLI flags `--triage`, `--model`, `--ollama-host`, and `--triage-timeout` (with `OLLAMA_MODEL` and `OLLAMA_HOST` environment variable fallbacks).
  - Triage is disabled by default; base package installation gains no new dependencies and functions identically.
  - LLM triage is strictly advisory: it clusters related findings and hypothesizes root causes without altering, adding, removing, or re-scoring deterministic findings.
- **Security & Delimiter Breakout Defenses**:
  - Strict XML escaping for `&`, `<`, and `>` (`&` escaped first) in evidence and attribute quote escaping before embedding in `<finding>` and `<evidence>` tags.
  - Control characters stripped after escaping decisions to prevent prompt structure manipulation.
- **Untrusted Output Protection for Verification Checks**:
  - Conservative command validator rejecting shell metacharacters (`|`, `;`, `&&`, `||`, backticks, `$(`, `>`, `<`), exfiltration utilities (`curl`, `wget`, `nc`, `bash -c`), arbitrary URLs, and restricting `cat` to `/etc` and `/var/log`.
  - Allowed commands restricted to safe read-only system utilities (`ALLOWED_CHECK_BINARIES`).
  - Next checks rendered in reports strictly inside fenced code blocks under the header `Model-suggested, unverified - review before running`.
  - Dropped checks tracked in triage provenance and stats.
- **Enhanced Redactor & Seeding**:
  - Shared `Redactor` instance across all batches and the second-pass merge pass.
  - Pre-seeded with known hostnames, usernames, and IPs extracted from collector targets and baseline context before running heuristic fallback regexes.
  - De-redaction applied to hypotheses, next_checks, and cluster summaries using longest-placeholder-first matching to prevent partial prefix replacements (e.g. `IP_1` vs `IP_10`).
  - Unmapped / model-invented placeholders preserved intact and counted in `unknown_placeholders`.
- **Strict Finding Coverage Invariant**:
  - Enforced post-condition: every input finding ID appears exactly once across clusters and unclustered findings.
  - Omitted findings appended deterministically to `unclustered`; cross-cluster duplicate assignments deduplicated (first retained).
- **Time Budget & Fault-Tolerant Partial Runs**:
  - Configurable `--triage-timeout` (default 900s) wall-clock budget. On budget exhaustion, completed batches are preserved, uncovered findings are routed to `unclustered`, and `triage.status` is set to `partial`.
  - Connection failures and schema errors after retry are marked `skipped` with audit exit code remaining 0.
- **Flag Semantics & Legacy Path Reconciliation**:
  - Mutually exclusive validation: passing `--triage` and `--no-llm` simultaneously terminates with exit code 2.
  - `--ollama-url` marked as a deprecated alias of `--ollama-host` emitting a `DeprecationWarning`.
  - Retained legacy `llm_client.py` as an isolated path under `--legacy-llm` outputting to its own separate `legacy_triage` key and `triage_report.json` without conflicting with `triage`.
- **Host-Isolated Stable Finding IDs**:
  - `Finding.id`: 12-character SHA-256 hash incorporating host context (`f"{host}:{rule_id}:{norm_evidence}"`) to prevent collisions across multi-host audits.
  - `Finding.finding_id`: 64-character full SHA-256 hash retained for SQLite state history tracking.
- **Benchmark Evaluation Harness**:
  - Added `scripts/eval_triage.py` and 3 golden benchmark datasets (`tests/golden/*.json`) measuring cluster precision/recall, schema-failure rate, and hallucinated-ID rate.

### Removed
- Removed dead and legacy prototype files: `analyze.py`, `Collector_Skeleton.sh`, `engine/`, and typo directory `assest/`.

## [0.1.0] - 2026-11-23

### Added
- Initial release of `host-audit-ai`.
- Agentless read-only Bash collection over SSH (`collect/audit-collect.sh`).
- Deterministic baseline policy engine (`exposure`, `ssh`, `containers`, `privesc`, `ioc`).
- SQLite audit history state store tracking `new`, `persisting`, and `resolved` findings.
- Jinja2-rendered Markdown audit reporting (`report.md`) and JSON serialization (`findings.json`).
