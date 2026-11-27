#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys
import warnings
from pathlib import Path
from typing import Any
import yaml

from host_audit.schema import Finding
from host_audit.store import AuditStore
from host_audit.rules.exposure import check_exposure
from host_audit.rules.ssh import check_ssh_and_users
from host_audit.rules.containers import check_containers
from host_audit.rules.privesc import check_privesc
from host_audit.rules.ioc import check_ioc
from host_audit.report import generate_markdown_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("host-audit")

DEFAULT_MODEL = os.environ.get(
    "OLLAMA_MODEL",
    "hf.co/mradermacher/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic-GGUF:Q4_K_M",
)
DEFAULT_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")


def run_analysis(
    collect_dir: Path,
    baseline_path: Path,
    db_path: Path,
    out_dir: Path,
    triage: bool = False,
    no_llm: bool = False,
    legacy_llm: bool = False,
    model: str = DEFAULT_MODEL,
    ollama_host: str = DEFAULT_OLLAMA_HOST,
    ollama_url: str | None = None,
    triage_timeout: float = 900.0,
) -> int:
    """Run deterministic audit analysis with optional local LLM triage."""
    if triage and no_llm:
        logger.error("Conflicting flags: cannot specify both --triage and --no-llm")
        return 2

    if ollama_url:
        warnings.warn("--ollama-url is deprecated; use --ollama-host instead.", DeprecationWarning, stacklevel=2)
        effective_host = ollama_url
    else:
        effective_host = ollama_host

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

    # Populate host on all findings so Finding.id incorporates host context
    for f in findings:
        if not f.host:
            f.host = host

    # Highest priority score first
    findings.sort(key=lambda f: f.priority_score, reverse=True)

    store = AuditStore(db_path)
    diff = store.record_run(host, findings)
    store.close()

    findings_payload: dict[str, Any] = {
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

    triage_payload: dict[str, Any] | None = None
    triage_obj: Any = None
    redaction_map: dict[str, str] = {}

    # Optional local LLM triage
    if triage and not no_llm:
        if len(findings) == 0:
            logger.info("No open findings to triage")
            triage_payload = {
                "status": "completed",
                "provenance": {
                    "model": model,
                    "digest": "none",
                    "prompt_version": "1.0.0",
                    "options": {},
                    "dropped_checks": 0,
                },
                "stats": {
                    "covered_count": 0,
                    "uncovered_count": 0,
                    "dropped_checks": 0,
                    "duplicate_assignments": 0,
                    "unknown_placeholders": 0,
                },
                "clusters": [],
                "unclustered": [],
            }
        else:
            logger.info(f"Invoking Ollama LLM triage with model '{model}' at {effective_host}...")
            try:
                from host_audit.llm import triage as execute_triage
                from host_audit.llm.redact import Redactor, extract_known_entities

                known_hosts, known_users, known_ips = extract_known_entities(findings, host=host)
                redactor = Redactor(known_hosts=known_hosts, known_users=known_users, known_ips=known_ips)

                triage_obj = execute_triage(
                    findings=findings,
                    model=model,
                    host=effective_host,
                    redactor=redactor,
                    timeout=triage_timeout,
                )
                redaction_map = getattr(triage_obj, "redaction_mapping", {})
                triage_payload = {
                    "status": triage_obj.status,
                    "provenance": getattr(triage_obj, "provenance", {}),
                    "stats": getattr(triage_obj, "stats", {}),
                    "clusters": [c.model_dump() for c in triage_obj.clusters],
                    "unclustered": triage_obj.unclustered,
                }
                logger.info(
                    f"LLM triage finished with status '{triage_obj.status}': "
                    f"{len(triage_obj.clusters)} clusters found, {len(triage_obj.unclustered)} unclustered"
                )
            except Exception as e:
                logger.warning(f"Ollama triage skipped due to error: {e}")
                triage_payload = {
                    "status": "skipped",
                    "reason": str(e),
                }

    if triage_payload is not None:
        findings_payload["triage"] = triage_payload

    # Legacy LLM path (Option b: explicitly separate under legacy_triage and triage_report.json)
    if legacy_llm and not no_llm:
        logger.info(f"Invoking legacy LLM triage with model '{model}'...")
        try:
            from host_audit.llm_client import call_ollama
            legacy_report = call_ollama(model=model, findings_payload=findings_payload, ollama_url=effective_host)
            findings_payload["legacy_triage"] = legacy_report.model_dump()
            triage_file = out_dir / "triage_report.json"
            triage_file.write_text(legacy_report.model_dump_json(indent=2), encoding="utf-8")
            logger.info(f"Wrote legacy AI triage report to {triage_file}")
        except Exception as e:
            logger.warning(f"Legacy LLM triage skipped due to error: {e}")

    findings_file = out_dir / "findings.json"
    findings_file.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")
    logger.info(f"Wrote {len(findings)} deterministic findings to {findings_file}")

    # Generate Markdown Report (de-redacts placeholders at render time)
    report_md = generate_markdown_report(
        host=host,
        findings=findings,
        diff=diff,
        triage=triage_obj if triage_obj is not None else triage_payload,
        redaction_mapping=redaction_map,
    )
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
        print(f"  [{f.severity.upper():8}] (id={f.id}) (score={f.priority_score:2}) {f.rule_id}: {f.title}")

    if triage_payload:
        print(f"\n{'-'*70}")
        status = triage_payload.get("status")
        if status in ("completed", "partial"):
            label = "COMPLETED" if status == "completed" else "PARTIAL"
            print(f"AI TRIAGE CLUSTERS [{label}] (Model: {model}):")
            clusters = triage_payload.get("clusters", [])
            for idx, cluster in enumerate(clusters, 1):
                fids = ", ".join(cluster.get("finding_ids", []))
                print(f"  {idx}. [{cluster.get('suggested_priority', '').upper()}] {cluster.get('hypothesis', '')} ({fids})")
        else:
            print(f"AI TRIAGE: SKIPPED ({triage_payload.get('reason', 'unknown')})")

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
        help="Directory to save findings.json and report.md (default: current dir)",
    )
    analyze_parser.add_argument(
        "--triage",
        action="store_true",
        help="Enable optional local LLM triage using Ollama",
    )
    analyze_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM correlation triage (deterministic findings and report only)",
    )
    analyze_parser.add_argument(
        "--legacy-llm",
        action="store_true",
        help="Run legacy attack-chain LLM correlation under separate report key",
    )
    analyze_parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model identifier (env OLLAMA_MODEL, default: {DEFAULT_MODEL})",
    )
    analyze_parser.add_argument(
        "--ollama-host",
        default=DEFAULT_OLLAMA_HOST,
        help=f"Ollama host URL (env OLLAMA_HOST, default: {DEFAULT_OLLAMA_HOST})",
    )
    analyze_parser.add_argument(
        "--ollama-url",
        default=None,
        help="Deprecated alias for --ollama-host",
    )
    analyze_parser.add_argument(
        "--triage-timeout",
        default=900.0,
        type=float,
        help="Wall-clock time budget for LLM triage in seconds (default: 900.0)",
    )

    args = parser.parse_args()

    if args.command == "analyze":
        if args.triage and args.no_llm:
            analyze_parser.error("Cannot use both --triage and --no-llm.")

        ret = run_analysis(
            collect_dir=args.collect_dir,
            baseline_path=args.baseline,
            db_path=args.db,
            out_dir=args.out_dir,
            triage=args.triage,
            no_llm=args.no_llm,
            legacy_llm=args.legacy_llm,
            model=args.model,
            ollama_host=args.ollama_host,
            ollama_url=args.ollama_url,
            triage_timeout=args.triage_timeout,
        )
        sys.exit(ret)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
