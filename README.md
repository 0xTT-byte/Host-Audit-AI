<p align="center">
  <img src="assets/logo.gif" alt="host-audit-ai" width="600" />
</p>

# host-audit-ai

**Agentless Linux & Docker host security auditing with deterministic baseline diffing, attack-chain correlation, and scoped AI triage.**

`host-audit-ai` separates **verified detection** from **AI reasoning**. Instead of dumping noisy scanner logs into a cloud LLM, it streams a read-only POSIX collector over SSH (or runs locally), diffs the host against a strict YAML baseline on your local machine, correlates findings into multi-stage attack paths deterministically, tracks `NEW`, `PERSISTING`, and `RESOLVED` drift in an encrypted SQLite state store, and provides scoped, read-only MCP servers for hardened AI investigation.

---

## Why This Exists

* **Observed − Expected (Zero Noise):** Traditional security scanners output hundreds of generic warnings every run. `host-audit-ai` evaluates hosts against baseline policies (`engine/baselines/default.yaml`), eliminating alert fatigue through deterministic diffing and expiring waivers.
* **Agentless & Ephemeral:** Nothing permanent is installed on the target host. The POSIX collector streams over SSH, executes in a secure temp directory, streams framed evidence back over stdout, and cleanly wipes itself on exit via traps.
* **Deterministic Pre-LLM Correlator:** Attack graphs (public listener -> process -> service -> privilege, SSH weak auth, container escape, persistence IOCs) are correlated deterministically in pure Python without LLM hallucination risk.
* **Defense-in-Depth Provisioning:** For continuous auditing, `host-audit init-target` provisions a target-side POSIX forced-command wrapper (`host-audit-wrapper.sh`) restricting the auditor's SSH key strictly to 6 read-only verbs with canonical `realpath` allowlisting.
* **Multi-Format Export & Drift Tracking:** Exports directly to JSON, SARIF 2.1.0 (native GitHub Code Scanning import), Markdown, and context-bounded `ai-bundle` packages. Tracks finding lifecycle in local SQLite (`0o600`).

---

## Architecture

```text
[Target Server]                                   [Local Operator Machine]
collect.sh (read-only, ephemeral)  ──SSH/Local──▶   Framed Evidence Envelope
(or forced-command wrapper)                                  │
                                                             ▼
                                                    9 Pure Parsers
                                                             │
                                                             ▼
                                                    31 Deterministic Rules
                                                    (Observed vs Baseline)
                                                             │
                                                             ▼
                                                Pre-LLM Graph Correlator
                                                (4 Attack-Chain Classes)
                                                             │
                                     ┌───────────────────────┴───────────────────────┐
                                     ▼                                               ▼
                              SQLite Store                                     Exporters
                         (0o600, Schema v1)                         (JSON, SARIF 2.1.0, Markdown,
                      (NEW/PERSISTING/RESOLVED)                               ai-bundle)
                                                                                     │
                                                                                     ▼
                                                                        [Scoped MCP Server]
                                                                            audit-ssh
                                                                    (Read-only, parameterized)
```

---

## Repository Structure

```text
Host-Audit-AI/
├── src/
│   └── host_audit_ai/
│       ├── collectors/          # Read-only Bash collector & SSH/Local/Offline transports
│       │   └── scripts/         # collect.sh and host-audit-wrapper.sh
│       ├── parsers/             # 9 pure parsers extracting normalized host snapshot state
│       ├── models/              # Pydantic v2 schemas (findings, reports, snapshots, diffs)
│       ├── engine/              # 31 security rules, YAML baseline policy loader & correlator
│       │   └── baselines/       # default.yaml baseline policy
│       ├── storage/             # 0o600 SQLite audit store and 3-run drift diff engine
│       ├── exporters/           # JSON, SARIF 2.1.0, Markdown, AI-bundle exporters
│       ├── mcp_servers/         # Scoped read-only audit-ssh MCP server
│       ├── crew/                # Jailed skills writer & crew tools adapter
│       └── cli.py               # Typer CLI entrypoint (`host-audit`)
├── tests/                       # Unit, integration, parser, rules, and security test suites
├── pyproject.toml               # Package configuration & build specification
└── CHANGELOG.md                 # Project release history
```

---

## Installation

### Core Package (Zero AI Dependencies)

Install the core auditing and deterministic analysis engine:

```bash
git clone https://github.com/0xTT-byte/Host-Audit-AI.git
cd Host-Audit-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Optional AI / MCP Extensions

To include the FastMCP `audit-ssh` server and CrewAI tooling:

```bash
pip install -e ".[crew,dev]"
```

---

## Quick Start & CLI Reference

`host-audit-ai` provides a unified Typer CLI: `host-audit`.

### 1. Run a Security Scan

**Scan local machine:**
```bash
host-audit scan --target local
```

**Scan a remote server over SSH:**
```bash
host-audit scan --target ssh://audit-user@192.168.1.50:22 --out report.json
```

**Scan an existing raw evidence dump offline:**
```bash
host-audit scan --offline evidence.raw --format markdown --out report.md
```

**Fail CI/CD pipeline on High or Critical findings:**
```bash
host-audit scan --target local --fail-on high
```

### 2. Inspect Audit History & Drift

**List recent audit runs stored in SQLite:**
```bash
host-audit runs --limit 10
```

**Diff two audit runs to detect newly introduced, persisting, or resolved findings:**
```bash
host-audit diff <prior-run-id> <current-run-id>
```

### 3. Export Reports

Export any prior run into JSON, SARIF 2.1.0, Markdown, or an AI context bundle:

```bash
host-audit export <run-id> --format sarif --out results.sarif
host-audit export <run-id> --format markdown --out audit-summary.md
host-audit export <run-id> --format ai-bundle --out ai_context.json
```

### 4. Hardened Target Provisioning (`init-target`)

Provision an audit target with a restricted forced-command SSH wrapper (`host-audit-wrapper.sh`):

```bash
host-audit init-target --pubkey ~/.ssh/id_ed25519.pub --output-dir ./target-provisioning
```

This generates:
* `host-audit-wrapper.sh`: POSIX wrapper enforcing 6 read-only verbs (`ping`, `inspect-unit`, `read-config`, `journal-slice`, `inspect-process`, `list-connections`).
* `authorized_keys.snippet`: Hardened line restricting the key (`command="/usr/local/bin/host-audit-wrapper",restrict ...`).
* `INSTALL.md`: Deployment instructions.

---

## Deterministic Rule Set

The engine evaluates 31 security rules across 7 categories:

| Category | Rules | Description |
| :--- | :--- | :--- |
| **Exposure (`EXP`)** | `EXP-001` - `EXP-003` | Wildcard listeners, unauthorized public ports, non-loopback database binds |
| **SSH & Users (`SSH`, `USR`)** | `SSH-001` - `SSH-003`, `USR-001` - `USR-003` | Root login, password auth, non-standard port, UID 0 accounts, empty passwords |
| **Containers (`CNT`)** | `CNT-001` - `CNT-005` | Exposed Docker/Podman sockets, privileged mode, host namespace sharing, root mounts |
| **Filesystem & Cron (`FS`, `CRN`)** | `FS-001` - `FS-004`, `CRN-001` - `CRN-002` | World-writable shadow/passwd, SUID GTFOBins, writable cron jobs |
| **Privilege Escalation (`PRV`)** | `PRV-001` - `PRV-004` | Sudo NOPASSWD, wildcards in sudoers, file capabilities (cap_setuid) |
| **Kernel & Firewall (`KRN`, `FW`)** | `KRN-001` - `KRN-004`, `FW-001` - `FW-003` | IP forwarding, SYN cookies, ptrace scope, inactive firewall, Docker bypass |
| **Persistence & IOCs (`IOC`)** | `IOC-001` - `IOC-003` | Running unlinked/deleted binaries, execution from `/tmp` or `/dev/shm` |

---

## Running Tests

Verify the complete test suite:

```bash
# Core test suite (194 tests, zero AI dependencies)
pytest -v

# Architecture boundaries test
pytest -v tests/test_architecture_boundaries.py

# MCP & Crew security tests (with [crew] extra installed)
pytest -v tests/test_audit_ssh_security.py tests/test_mcp_tools_isolation.py tests/test_skills_writer.py
```

---

## License & Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on code style, rule development, and architecture guidelines.
