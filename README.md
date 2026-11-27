<p align="center">
  <img src="assets/logo.gif" alt="host-audit-ai" width="600" />
</p>

# host-audit-ai

**Agentless Linux & Docker host security auditing with deterministic baseline diffing, pre-LLM attack-chain correlation, and air-gapped BYOM AI triage.**

`host-audit-ai` separates **verified deterministic detection** from **AI reasoning**. It streams a read-only POSIX collector (`collect.sh`) over SSH (or executes locally), parses 18 telemetry sections into a normalized `HostSnapshot`, evaluates 31 rules against a YAML baseline policy, builds deterministic attack graphs, tracks finding drift (`NEW`, `PERSISTENT`, `RESOLVED`, `REGRESSED`, `WAIVED`) in a `0o600` SQLite database, and optionally runs a 3-stage air-gapped CrewAI triage pipeline using your own local or enterprise LLM.

See [ARCHITECTURE.md](ARCHITECTURE.md) for module boundaries and schemas, and [SECURITY.md](SECURITY.md) for the full 6-layer threat model.

---

## Installation

### Core CLI (Zero AI Dependencies)

Run directly with `uvx` or install into an isolated environment (only `pydantic`, `typer`, `pyyaml`, and `rich`):

```bash
# Zero-install execution
uvx host-audit-ai scan --target local

# Persistent core CLI install
uv tool install host-audit-ai
```

### With Optional Air-Gapped AI Triage (`[crew]`)

To enable `host-audit triage` with CrewAI, FastMCP (`audit-ssh`), and web research adapters:

```bash
uv tool install "host-audit-ai[crew]"
```

### From Source (Development)

```bash
git clone https://github.com/0xTT-byte/Host-Audit-AI.git
cd Host-Audit-AI
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"          # Core + tests/linters (zero AI deps)
# or:
uv pip install -e ".[crew,dev]"     # Full environment including [crew]
```

---

## Quick Start & Subcommand Reference

`host-audit-ai` installs the `host-audit` (and `host-audit-ai`) CLI with 8 subcommands:

| Command | Purpose |
| :--- | :--- |
| `collect` | Run the ephemeral read-only collector and emit a raw dump or JSON envelope |
| `scan` | Collect, parse, evaluate baseline/waivers, correlate chains, persist to SQLite, and gate exit code |
| `runs` | List historical audit runs stored in local SQLite (`0o600`) |
| `diff` | Compute finding drift (`NEW`, `PERSISTENT`, `RESOLVED`, `REGRESSED`, `WAIVED`) between two runs |
| `export` | Export a saved run or offline JSON report to `json`, `sarif`, `markdown`, or `ai-bundle` |
| `rules` | List and filter the 31 built-in deterministic baseline rules |
| `init-target` | Generate an `ed25519` keypair and forced-command wrapper bundle for read-only SSH inspection |
| `triage` | Execute the 3-stage air-gapped BYOM CrewAI triage pipeline (or `--dry-run-sanitizer`) |

### Examples

```bash
# 1. Capture raw collector evidence without evaluating
host-audit collect --target ssh://audituser@192.0.2.10:22 --out capture.json

# 2. Scan a local or remote host and write SARIF 2.1.0
host-audit scan --target local
host-audit scan --target ssh://audituser@192.0.2.10:22 --identity ~/.ssh/id_ed25519 --fail-on high --format sarif --out results.sarif

# 3. Inspect run history and compute drift
host-audit runs --limit 10
host-audit diff --host prod-web-01
host-audit diff --base <run_1> --target <run_2> --fail-on-new high

# 4. Export an existing run
host-audit export <run_id> --format markdown --out summary.md
host-audit export <run_id> --format ai-bundle --redact --out ai_bundle.json

# 5. Inspect built-in rules
host-audit rules --category ssh --severity high

# 6. Provision hardened forced-command SSH inspection on a target
host-audit init-target --key-path ~/.ssh/host_audit_ed25519 --out-dir ./target-provisioning

# 7. Preview zero-PII sanitized queries or run full 3-stage BYOM triage
host-audit triage <run_id> --dry-run-sanitizer
host-audit triage <run_id> --llm-config examples/llm/ollama-4b-local.yaml --ssh-target ssh://auditmcp@192.0.2.10:22 --identity ~/.ssh/host_audit_ed25519
```

Pre-tuned BYOM LLM configuration profiles for Ollama (4B GGUF & 32B), vLLM, and LiteLLM proxies are provided in [examples/llm/](examples/llm/).

---

## Exit Codes

| Code | Meaning |
| :---: | :--- |
| `0` | Success: command completed cleanly and zero unwaived findings (or `NEW`/`REGRESSED` drift findings) met the threshold |
| `1` | Runtime, validation, transport, parsing, or configuration error |
| `2` | Policy gate violated: active findings in `scan --fail-on` (default: `high`) or new regressions in `diff --fail-on-new` met/exceeded threshold |

---

## Deterministic Rule Catalog (31 Rules)

| Category | Rule IDs | Coverage |
| :--- | :--- | :--- |
| **Exposure (`exposure`)** | `EXP-001` – `EXP-002` | Public/wildcard socket listeners and unauthorized/database port exposure |
| **SSH (`ssh`)** | `SSH-001` – `SSH-006` | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `MaxAuthTries`, `X11Forwarding`/TCP forwarding, deprecated `Protocol 1`/`PermitUserEnvironment` |
| **Identity (`identity`)** | `USR-001` – `USR-002` | Non-root UID `0` accounts and interactive shells on system accounts |
| **Containers (`containers`)** | `CNT-001` – `CNT-004` | Exposed Docker/Podman sockets, `--privileged` containers, host PID/network/IPC namespaces, sensitive host bind mounts |
| **Filesystem (`filesystem`)** | `FS-001` – `FS-003` | Permissive `/etc/shadow` / `/etc/gshadow`, world-writable critical configs, world-writable directories missing sticky bit |
| **Cron (`cron`)** | `CRN-001` | Scheduled cron tasks referencing `/tmp`, `/var/tmp`, or `/dev/shm` |
| **Privilege Escalation (`privesc`)** | `PRV-001` – `PRV-004` | Sudo `NOPASSWD: ALL`, GTFOBins sudo commands, unexpected SUID/SGID binaries, dangerous Linux file capabilities |
| **Firewall (`firewall`)** | `FW-001` – `FW-002` | Missing or inactive host firewall, Docker `DOCKER-USER` firewall bypass |
| **Kernel (`kernel`)** | `SYS-001` – `SYS-004` | IPv4 forwarding, ASLR (`randomize_va_space`), `kptr_restrict`/`dmesg_restrict`, Yama `ptrace_scope` |
| **IOCs (`ioc`)** | `IOC-001` – `IOC-003` | Processes executing deleted binaries, `/etc/ld.so.preload` hooks, executables staged in `/tmp` or `/dev/shm` |

---

## Testing & Verification

```bash
# Core unit & security suite (zero AI dependencies)
pytest -v -m "not e2e"

# Full suite including CrewAI/MCP orchestration (with [crew] extra installed)
pytest -v -m "not e2e"

# Live Docker SSH + forced-command wrapper E2E suite (requires Docker daemon)
pytest -v -m e2e
```
