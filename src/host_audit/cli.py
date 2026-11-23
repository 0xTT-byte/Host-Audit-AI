#!/usr/bin/env python3
import argparse
import json
import logging
import sys
from pathlib import Path
import yaml

from host_audit.schema import Finding, TriageReport
from host_audit.store import AuditStore
from host_audit.rules.exposure import check_exposure
from host_audit.rules.ssh import check_ssh_and_users
from host_audit.rules.containers import check_containers
from host_audit.rules.privesc import check_privesc
from host_audit.rules.ioc import check_ioc
from host_audit.llm_client import call_ollama, DEFAULT_MODEL
from host_audit.report import generate_markdown_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("host-audit")


def run_analysis(
    collect_dir: Path,
    baseline_path: Path,
    db_path: Path,
    out_dir: Path,
    no_llm: bool = False,
    model: str = DEFAULT_MODEL,
    ollama_url: str = "http://localhost:11434",
) -> int:
    if not collect_dir.exists():
        logger.error(f"Collector directory does not exist: {collect_dir}")
        return 1

    if not baseline_path.exists():
        logger.error(f"Baseline YAML does not exist: {baseline_path}")
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        baseline = yaml.safe_load(baseline_path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        logger.error(f"Failed to parse baseline YAML {baseline_path}: {e}")
        return 1

    host = baseline.get("host") or collect_dir.name or "unknown-host"

    findings: list[Finding] = []
    findings.extend(check_exposure(collect_dir, baseline))
    findings.extend(check_ssh_and_users(collect_dir, baseline))
    findings.extend(check_containers(collect_dir, baseline))
    findings.extend(check_privesc(collect_dir, baseline))
    findings.extend(check_ioc(collect_dir, baseline))

    # Highest priority score first
    findings.sort(key=lambda f: f.priority_score, reverse=True)

    store = AuditStore(db_path)
    diff = store.record_run(host, findings)
    store.close()

    findings_payload = {
        "host": host,
        "summary": {
            "total_open": len(findings),
            "new_this_run": len(diff["new"]),
            "persisting": len(diff["persisting"]),
            "resolved_since_last": len(diff["resolved_ids"]),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "findings": [f.model_dump() for f in findings],
    }

    findings_file = out_dir / "findings.json"
    findings_file.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")
    logger.info(f"Wrote {len(findings)} deterministic findings to {findings_file}")

    triage: TriageReport | None = None
    if not no_llm and len(findings) > 0:
        logger.info(f"Invoking Ollama LLM triage with model '{model}' at {ollama_url}...")
        try:
            triage = call_ollama(model=model, findings_payload=findings_payload, ollama_url=ollama_url)
            triage_file = out_dir / "triage_report.json"
            triage_file.write_text(triage.model_dump_json(indent=2), encoding="utf-8")
            logger.info(f"Wrote AI triage report to {triage_file}")
        except Exception as e:
            logger.warning(f"Ollama triage skipped due to error: {e}")
    else:
        if no_llm:
            logger.info("Local LLM triage skipped (--no-llm flag specified)")
        else:
            logger.info("No open findings to triage")

    # Generate Markdown Report
    report_md = generate_markdown_report(host, findings, diff, triage)
    report_file = out_dir / "report.md"
    report_file.write_text(report_md, encoding="utf-8")
    logger.info(f"Generated human-readable report: {report_file}")

    # Terminal output summary
    print(f"\n{'='*70}")
    print(f"AUDIT SUMMARY: [{host}]")
    print(f"{'='*70}")
    print(
        f"Open Findings: {len(findings)} | "
        f"New: {len(diff['new'])} | "
        f"Persisting: {len(diff['persisting'])} | "
        f"Resolved: {len(diff['resolved_ids'])}"
    )
    print(
        f"Severities: {findings_payload['summary']['critical']} Critical, "
        f"{findings_payload['summary']['high']} High, "
        f"{findings_payload['summary']['medium']} Medium, "
        f"{findings_payload['summary']['low']} Low"
    )
    print(f"{'-'*70}")

    for f in findings:
        print(f"  [{f.severity.upper():8}] (score={f.priority_score:2}) {f.rule_id}: {f.title}")

    if triage and triage.attack_chains:
        print(f"\n{'-'*70}")
        print("SYNTHESIZED ATTACK CHAINS:")
        for idx, chain in enumerate(triage.attack_chains, 1):
            print(f"  {idx}. [{chain.severity.upper()}] {chain.name} ({', '.join(chain.involved_rule_ids)})")

    print(f"{'='*70}\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="host-audit",
        description="host-audit-ai: Agentless Linux & Docker Host Security Auditing Tool",
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze collected host configuration files")
    analyze_parser.add_argument(
        "--collect-dir",
        required=True,
        type=Path,
        help="Directory containing collector output files (net-listen.txt, sshd.txt, etc.)",
    )
    analyze_parser.add_argument(
        "--baseline",
        default=Path("baselines/docker-host.yml"),
        type=Path,
        help="Path to expected baseline YAML policy (default: baselines/docker-host.yml)",
    )
    analyze_parser.add_argument(
        "--db",
        default=Path("audit_history.db"),
        type=Path,
        help="Path to SQLite audit history database (default: audit_history.db)",
    )
    analyze_parser.add_argument(
        "--out-dir",
        default=Path("."),
        type=Path,
        help="Directory to save findings.json, triage_report.json, and report.md (default: current dir)",
    )
    analyze_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM correlation triage (deterministic findings and report only)",
    )
    analyze_parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model identifier (default: {DEFAULT_MODEL})",
    )
    analyze_parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="URL of the local Ollama instance (default: http://localhost:11434)",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        ret = run_analysis(
            collect_dir=args.collect_dir,
            baseline_path=args.baseline,
            db_path=args.db,
            out_dir=args.out_dir,
            no_llm=args.no_llm,
            model=args.model,
            ollama_url=args.ollama_url,
        )
        sys.exit(ret)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
