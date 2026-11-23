<p align="center">
  <img src="assets/logo.gif" alt="host-audit-ai" width="600" />
</p>

# host-audit-ai

**Agentless Linux & Docker host security auditing with deterministic baseline diffing and local AI attack-chain correlation.**

`host-audit-ai` separates **verified detection** from **AI reasoning**. Instead of dumping noisy scanner logs into a cloud LLM, it streams a read-only Bash collector over SSH, diffs the host against a strict YAML baseline on your local machine, tracks `new` vs. `persisting` vs. `resolved` findings in SQLite, and optionally uses a local **Ollama** model (`hf.co/mradermacher/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic-GGUF:Q4_K_M`) to correlate findings into realistic attack paths, verification commands, and concrete fixes.

---

## Why This Exists

* **Observed − Expected (Zero Noise):** Traditional security scanners output hundreds of generic warnings every run. `host-audit-ai` computes `finding = observed - expected` against your baseline policy (`baselines/docker-host.yml`), eliminating alert fatigue.
* **Agentless & Zero Server Footprint:** Nothing is installed on the target host. The collector (`collect/audit-collect.sh`) streams over SSH, runs in a `chmod 700` temp directory, streams evidence back over stdout into `./evidence/`, and completely wipes itself on exit via a bash `trap`.
* **100% Local & Private:** Your `sshd_config`, `docker inspect`, users, and internal network topology never leave your local operator workstation.
* **Deterministic First (No LLM Hallucinations):** Deterministic Python rules produce verified findings with exact evidence lines and read-only verification commands. The local LLM only correlates verified findings into multi-stage attack chains—and can be disabled at any time with `--no-llm`.

---

## Architecture

```text
[Target Server]                           [Local Operator Machine]
collect/audit-collect.sh (read-only)  ──SSH──▶  evidence/<host>-<timestamp>/
  (wiped on exit via EXIT trap)                      │
                                                     ▼
                                            Deterministic Rule Engine
                                            (observed - baseline.yml)
                                                     │
                             ┌───────────────────────┴───────────────────────┐
                             ▼                                               ▼
                      SQLite State Store                              Ollama (Local)
                 (new / persisting / resolved)            DeepSeek-V4-Pro-Qwen3.5-4B
                             │                              (JSON Schema Enforced)
                             └───────────────────────┬───────────────────────┘
                                                     ▼
                                        report.md + findings.json
```

---

## Repository Structure

```text
Host-Audit-AI/
├── baselines/
│   ├── docker-host.yml          # Production Docker host baseline policy
│   └── example.yml              # Standard Linux server baseline policy
├── collect/
│   └── audit-collect.sh         # Read-only, silent remote collector
├── scripts/
│   └── run-remote-audit.sh      # Remote SSH orchestration script
├── src/
│   └── host_audit/
│       ├── rules/               # Deterministic audit rule engines
│       │   ├── exposure.py      # Network listeners & Docker firewall bypasses
│       │   ├── ssh.py           # SSH configuration & unauthorized UID 0 accounts
│       │   ├── containers.py    # Docker privileged, socket, mount & capability checks
│       │   ├── privesc.py       # Sudoers, GTFOBins SUID, file capabilities
│       │   └── ioc.py           # Deleted binaries & temp-path execution
│       ├── schema.py            # Pydantic v2 data models (Finding, TriageReport)
│       ├── store.py             # SQLite state diff store
│       ├── llm_client.py        # Ollama client with strict Pydantic JSON schema
│       ├── report.py            # Jinja2 Markdown report generator
│       └── cli.py               # CLI entrypoint (host-audit analyze)
├── tests/                       # Pytest test suite & sanitized fixtures
└── pyproject.toml               # Package configuration & dependencies
```

---

## Quick Start

### 1. Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/0xTT-byte/Host-Audit-AI.git
cd Host-Audit-AI
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Run Remote Audit over SSH

Execute the agentless remote orchestrator:

```bash
./scripts/run-remote-audit.sh user@target-server.local baselines/docker-host.yml --no-llm
```

This will:
1. Stream `collect/audit-collect.sh` to the target server over SSH.
2. Execute the read-only collector in a temporary `chmod 700` directory.
3. Archive evidence over stdout back to `./evidence/<host>-<timestamp>/`.
4. Clean up all remote temp files automatically via an `EXIT` trap.
5. Execute `host-audit analyze` locally to generate `findings.json` and `report.md`.

### 3. Local Analysis of Existing Evidence

Analyze previously collected evidence locally:

```bash
host-audit analyze \
    --collect-dir evidence/target-server_20261123-120000 \
    --baseline baselines/docker-host.yml \
    --db audit_history.db \
    --out-dir ./output \
    --no-llm
```

---

## CLI Reference

```text
usage: host-audit analyze [-h] --collect-dir COLLECT_DIR [--baseline BASELINE]
                          [--db DB] [--out-dir OUT_DIR] [--no-llm]
                          [--model MODEL] [--ollama-url OLLAMA_URL]

options:
  -h, --help            Show this help message and exit
  --collect-dir DIR     Directory containing collector output files (net-listen.txt, sshd.txt, etc.)
  --baseline PATH       Path to expected baseline YAML policy (default: baselines/docker-host.yml)
  --db PATH             Path to SQLite audit history database (default: audit_history.db)
  --out-dir DIR         Directory to save findings.json, triage_report.json, and report.md
  --no-llm              Disable LLM correlation triage (deterministic findings and report only)
  --model MODEL         Ollama model tag (default: hf.co/mradermacher/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic-GGUF:Q4_K_M)
  --ollama-url URL      URL of the local Ollama instance (default: http://localhost:11434)
```

---

## Local AI Triage (Optional)

When run without `--no-llm`, `host-audit-ai` sends the top 25 compact findings to a local Ollama instance.

### Prerequisites

1. Install and start [Ollama](https://ollama.ai).
2. Pull the recommended local model:
   ```bash
   ollama pull hf.co/mradermacher/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic-GGUF:Q4_K_M
   ```
3. Run the audit:
   ```bash
   host-audit analyze --collect-dir ./evidence/host1 --baseline baselines/docker-host.yml
   ```

Findings are isolated inside `<FINDINGS_DATA>` tags to prevent prompt injection, and Ollama's `format` parameter constrains output to the exact Pydantic JSON schema (`TriageReport`).

---

## Running Tests

Run the test suite using `pytest`:

```bash
pytest -v
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on code style, rule development, and architecture guidelines.
