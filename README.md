# host-audit-ai

**Agentless Linux & Docker security auditing with deterministic baseline diffing and local AI attack-chain correlation.**

`host-audit-ai` separates **verified detection** from **AI reasoning**. Instead of dumping noisy scanner logs into a cloud LLM, it streams a read-only Bash collector over SSH, diffs the host against a strict YAML baseline on your local machine, tracks `new` vs. `resolved` findings in SQLite, and optionally uses a local **Ollama** model (`xtools-at/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic`) to correlate findings into realistic attack paths and concrete fixes.

---

## Why This Exists

* **Observed − Expected (Zero Noise):** Traditional scanners (Lynis, LinPEAS) output hundreds of generic warnings every run. `host-audit-ai` only flags deviations from your host's `expected.yml`.
* **Agentless & Zero Server Footprint:** Nothing is installed on production. The collector streams over SSH, runs in a `chmod 700` temp directory, streams evidence back over stdout, and wipes itself on exit via `trap`.
* **100% Local & Private:** Your `sshd_config`, `docker inspect`, and internal IPs never leave your machine.
* **No Hallucinated Findings:** Deterministic Python rules produce verified findings with exact evidence lines and read-only verification commands. The local LLM only correlates those verified findings into chains—and can be disabled anytime with `--no-llm`.

---

## Architecture

```text
[Target Server]                        [Your Local Machine]
audit-collect.sh (read-only)  ──SSH──▶  evidence/<host>-<date>/
  (wiped on exit via trap)                 │
                                           ▼
                                  Deterministic Python Engine
                                  (observed - expected.yml)
                                           │
                          ┌────────────────┴────────────────┐
                          ▼                                 ▼
                   SQLite History                    Ollama (Local)
              (new / open / resolved)         DeepSeek-V4-Pro-Qwen3.5-4B
                          │                    (JSON Schema Enforced)
                          └────────────────┬────────────────┘
                                           ▼
                                   report.md + JSON