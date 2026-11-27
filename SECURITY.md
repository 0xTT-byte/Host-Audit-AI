# Security Policy

## Supported Versions

Security fixes and patches are actively maintained for the following release series:

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes |
| `0.6.x` | Security fixes only |
| `< 0.6.0` | No (upgrade to `1.0.x`) |

## Reporting a Vulnerability

Do **not** open public GitHub issues for suspected security vulnerabilities, authentication bypasses, command-injection vectors, or sanitization leaks.

Instead, report vulnerabilities privately through GitHub Security Advisories (**Security -> Advisories -> Report a vulnerability**) on this repository. Include:
- Affected component and version (`host-audit --version`)
- Exact reproduction steps or proof-of-concept payload
- Impact assessment (target-side exposure, operator host impact, or PII leakage)

---

## Trust Boundaries & Threat Model

`host-audit-ai` operates across an explicit boundary between **untrusted audited hosts**, the **local deterministic operator workstation**, **optional BYOM LLM endpoints**, and **optional upstream web research tools**. Security controls are enforced deterministically across six layers:

### 1. Split-Execution Target Boundary (`collect.sh`)
- **Stdin-streamed execution:** `SSHTransport` streams `src/host_audit_ai/collectors/scripts/collect.sh` over `ssh -T ... bash -s` (`stdin` piping with `shell=False` subprocess execution and `BatchMode=yes`).
- **Zero target disk writes:** All section captures, size clamping (`512 KiB` default, `2 MiB` for packages/containers), and `stderr`/exit-code routing run in memory via file descriptors. Nothing is written to `/tmp` or user home directories on audited hosts.
- **No secret exfiltration:** `collect_shadow_meta()` invokes `stat` and `ls -ld` on `/etc/shadow` and `/etc/gshadow` only; password hashes are never read.

### 2. Anti-Spoofing Collector Framing (`collectors/framing.py`)
- Each collection generates a cryptographic/random hexadecimal boundary token (`HOST_AUDIT_BOUNDARY`).
- Section boundaries (`===<token>:BEGIN:<section>:CMD=...===`, `===<token>:STDERR:...===`, `===<token>:END:<section>:EXIT=...:TRUNCATED=...===`) prevent a malicious banner, filename, cron entry, or process argument on the target from injecting forged audit sections into `RawCollectorEnvelope`.

### 3. Two-Layer SSH MCP Boundary (`audit_ssh_core.py` + `host-audit-wrapper.sh`)
- **No generic shell tool:** The `audit-ssh` MCP server never exposes `run_shell` or arbitrary command execution.
- **Client-side validation (`mcp_servers/audit_ssh_core.py`):** Every verb (`ping`, `inspect-unit`, `read-config`, `check-binary`, `check-port`, `check-pkg`) enforces strict token/regex allowlists, canonical path checks, rejection of `..`/control characters/shell metacharacters, `BatchMode=yes`, `IdentitiesOnly=yes`, and `StrictHostKeyChecking=yes` (unless explicitly overridden).
- **Target-side forced-command wrapper (`collectors/scripts/host-audit-wrapper.sh`):** Installed via `host-audit init-target` with `authorized_keys` prefix `command="/usr/local/bin/host-audit-wrapper",restrict`. The wrapper independently validates:
  - Only 6 read-only verbs are accepted; unknown commands/args exit `126`.
  - `read-config` resolves `realpath -e`, enforces a high-sensitivity denylist (`/etc/shadow*`, `/etc/gshadow*`, `/etc/sudoers*`, `/proc/*`, `/sys/*`, `/dev/*`, `*.key`, `*.pem`, `*/id_*`), and restricts reads to allowlisted configuration paths bounded to `1..120` lines.
  - All command responses are truncated to `MAX_OUTPUT_BYTES = 32768` (`32 KiB`).

### 4. Temporal & Structural AI Air-Gap (`crew/pipeline.py`)
- **No implicit context bleed:** `run_triage_pipeline()` executes **three discrete single-stage `Crew` instances** (`Process.sequential`, `memory=False`), never CrewAI multi-task shared memory or raw context chaining.
- **Temporal tool separation:** Stage 1 (`ssh_mcp_adapter`) is closed cleanly via `contextlib.ExitStack` before Stage 2 (`web_mcp_adapter`) opens. No single agent ever holds both internal SSH inspection tools and external Web research tools simultaneously.
- **Optional core isolation:** Core packages (`models/`, `collectors/`, `parsers/`, `engine/`, `storage/`, `exporters/`) and top-level `cli.py` never import `crewai`, `mcp`, `litellm`, `ollama`, or `openai` (enforced continuously by AST tests).

### 5. Deterministic Zero-PII Sanitization Firewall (`crew/sanitizer.py`)
- **Strict allowlist egress (`SanitizedQueryItem`):** Between Stage 1 and Stage 2, `build_sanitized_queries()` reduces findings to strictly validated public metadata (`service_name`, `package_version`, `os_distro`, `kernel_version`, `rule_id`, `cwe_id`).
- **Pre-flight leak assertion (`assert_no_host_leakage`):** Collects forbidden host-specific tokens (hostnames, FQDNs, non-loopback IPv4/IPv6 addresses, non-system usernames, home paths, and prompt-injection patterns) and raises `SanitizationLeakError` if any forbidden fragment appears in outbound Stage 2 query items.

### 6. Prompt-Injection Insulation & Safe Remediation Artifacts (`crew/skills_writer.py`)
- **Untrusted telemetry framing:** `wrap_untrusted_telemetry()` neutralizes `<untrusted_host_telemetry>` breakout tags in evidence JSON and wraps all host telemetry inside explicit passive-data boundaries.
- **Jailed non-executable artifact writer (`JailedSkillsWriter`):**
  - Enforces flat filenames matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$` with extensions `.sh`, `.py`, `.yml`, `.yaml`, or `.md` (`64 KiB` max).
  - Rejects symlinks on both the directory and target file, opens with `O_NOFOLLOW`, verifies containment via `resolve().is_relative_to(...)`, and sets non-executable permissions (`0o644`).
  - Records disk-verified `sha256` hashes with `approved=False` and supports `human_input=True` confirmation gating before completion.
- **Local storage permissions:** SQLite databases created by `AuditStore` restrict parent directories (`0o700`) and database files (`0o600`) on POSIX systems.
