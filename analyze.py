#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import yaml

from engine.rules.exposure import check_exposure
from engine.rules.ssh import check_ssh_and_users
from engine.rules.containers import check_containers
from engine.store import AuditStore


def main():
    parser = argparse.ArgumentParser(description="Deterministic Server Audit Analyzer")
    parser.add_argument("--collect-dir", required=True, type=Path, help="Directory with collector .txt/.json files")
    parser.add_argument("--baseline", default="baseline/expected.yml", type=Path, help="Baseline YAML path")
    parser.add_argument("--db", default="audit_history.db", type=Path, help="SQLite history DB")
    parser.add_argument("--out", default="findings.json", type=Path, help="Output JSON for LLM triage")
    args = parser.parse_args()

    baseline = yaml.safe_load(args.baseline.read_text())
    host = baseline.get("host", args.collect_dir.name)

    findings = []
    findings.extend(check_exposure(args.collect_dir, baseline))
    findings.extend(check_ssh_and_users(args.collect_dir, baseline))
    findings.extend(check_containers(args.collect_dir, baseline))

    # Highest priority score first
    findings.sort(key=lambda f: f.priority_score, reverse=True)

    store = AuditStore(args.db)
    diff = store.record_run(host, findings)

    output = {
        "host": host,
        "summary": {
            "total_open": len(findings),
            "new_this_run": len(diff["new"]),
            "persisting": len(diff["persisting"]),
            "resolved_since_last": len(diff["resolved_ids"]),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
        },
        "findings": [f.model_dump() for f in findings],
    }

    args.out.write_text(json.dumps(output, indent=2))
    print(f"[{host}] Open: {len(findings)} | New: {len(diff['new'])} | Resolved: {len(diff['resolved_ids'])}")
    for f in findings:
        print(f"  [{f.severity.upper():8}] (score={f.priority_score:2}) {f.rule_id}: {f.title}")


if __name__ == "__main__":
    main()