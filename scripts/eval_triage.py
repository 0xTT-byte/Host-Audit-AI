#!/usr/bin/env python3
"""Evaluation harness for testing LLM triage performance against golden benchmark datasets.

Computes and prints:
- Cluster Precision and Recall (pair-wise co-clustering)
- Schema-Failure Rate
- Hallucinated-ID Rate
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from pathlib import Path
from typing import Any

# Ensure project root is on PYTHONPATH
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from host_audit.schema import Finding
from host_audit.llm.triage import triage, Triage


def parse_findings(raw_findings: list[dict[str, Any]]) -> list[Finding]:
    """Parse finding dictionaries into validated Finding objects."""
    return [Finding.model_validate(f) for f in raw_findings]


def get_cluster_pairs(clusters: list[list[str]]) -> set[tuple[str, str]]:
    """Return all unordered 2-element tuples (u, v) co-occurring in the same cluster."""
    pairs: set[tuple[str, str]] = set()
    for cluster in clusters:
        unique_ids = sorted(set(cluster))
        for u, v in itertools.combinations(unique_ids, 2):
            pairs.add((u, v))
    return pairs


def evaluate_scenario(
    golden_data: dict[str, Any],
    model: str,
    ollama_host: str,
    mock: bool = False,
) -> dict[str, Any]:
    """Evaluate a single golden scenario."""
    findings = parse_findings(golden_data["findings"])
    valid_ids = {f.id for f in findings}

    expected_clusters_raw = [
        c["finding_ids"] for c in golden_data.get("expected_clusters", [])
    ]
    expected_pairs = get_cluster_pairs(expected_clusters_raw)

    schema_failure = False
    hallucinated_ids: list[str] = []
    total_predicted_ids: list[str] = []
    predicted_clusters_raw: list[list[str]] = []

    if mock:
        # Perfect mock baseline reproducing expected clusters
        predicted_clusters_raw = [list(c) for c in expected_clusters_raw]
    else:
        try:
            from host_audit.llm import get_ollama_client
            client = get_ollama_client(host=ollama_host)
            result: Triage = triage(
                findings=findings,
                model=model,
                host=ollama_host,
                client=client,
            )
            for c in result.clusters:
                predicted_clusters_raw.append(c.finding_ids)
                total_predicted_ids.extend(c.finding_ids)
                for fid in c.finding_ids:
                    if fid not in valid_ids:
                        hallucinated_ids.append(fid)
        except Exception as e:
            schema_failure = True
            print(f"  [ERROR] Execution failed for scenario '{golden_data.get('name')}': {e}")

    predicted_pairs = get_cluster_pairs(predicted_clusters_raw)

    tp = len(expected_pairs & predicted_pairs)
    fp = len(predicted_pairs - expected_pairs)
    fn = len(expected_pairs - predicted_pairs)

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if not expected_pairs else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    return {
        "name": golden_data.get("name", "Unnamed"),
        "schema_failure": schema_failure,
        "hallucinated_count": len(hallucinated_ids),
        "total_predicted_count": len(total_predicted_ids),
        "precision": precision,
        "recall": recall,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def run_evaluation(
    golden_dir: Path,
    model: str,
    ollama_host: str,
    mock: bool = False,
) -> int:
    """Run evaluation against all golden test sets in golden_dir."""
    golden_files = sorted(golden_dir.glob("*.json"))
    if not golden_files:
        print(f"No golden json files found in {golden_dir}")
        return 1

    print(f"\n{'='*72}")
    print(f"HOST-AUDIT-AI: LLM TRIAGE BENCHMARK EVALUATION")
    print(f"Model: {model} | Host: {ollama_host} | Mode: {'Mock' if mock else 'Live Ollama'}")
    print(f"{'='*72}\n")

    scenario_results: list[dict[str, Any]] = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_hallucinated = 0
    total_predicted = 0
    schema_failures = 0

    for g_path in golden_files:
        try:
            data = json.loads(g_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Failed to read {g_path}: {e}")
            continue

        res = evaluate_scenario(data, model=model, ollama_host=ollama_host, mock=mock)
        scenario_results.append(res)

        total_tp += res["tp"]
        total_fp += res["fp"]
        total_fn += res["fn"]
        total_hallucinated += res["hallucinated_count"]
        total_predicted += res["total_predicted_count"]
        if res["schema_failure"]:
            schema_failures += 1

        print(
            f"• {res['name'][:42]:42} | "
            f"P: {res['precision']*100:5.1f}% | "
            f"R: {res['recall']*100:5.1f}% | "
            f"Schema Error: {'YES' if res['schema_failure'] else 'NO':3}"
        )

    num_scenarios = len(scenario_results)
    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    f1 = (2 * overall_p * overall_r / (overall_p + overall_r)) if (overall_p + overall_r) > 0 else 0.0

    schema_failure_rate = (schema_failures / num_scenarios) * 100 if num_scenarios > 0 else 0.0
    hallucinated_id_rate = (
        (total_hallucinated / total_predicted) * 100 if total_predicted > 0 else 0.0
    )

    print(f"\n{'-'*72}")
    print("GLOBAL BENCHMARK METRICS:")
    print(f"{'-'*72}")
    print(f"Total Scenarios Evaluated: {num_scenarios}")
    print(f"Schema-Failure Rate:       {schema_failure_rate:.1f}% ({schema_failures}/{num_scenarios})")
    print(f"Hallucinated-ID Rate:      {hallucinated_id_rate:.1f}% ({total_hallucinated}/{total_predicted})")
    print(f"Cluster Precision:         {overall_p * 100:.1f}%")
    print(f"Cluster Recall:            {overall_r * 100:.1f}%")
    print(f"Cluster F1 Score:          {f1 * 100:.1f}%")
    print(f"{'='*72}\n")

    return 0 if schema_failures == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate LLM Triage on Golden Datasets")
    parser.add_argument(
        "--golden-dir",
        type=Path,
        default=REPO_ROOT / "tests" / "golden",
        help="Path to directory containing golden dataset JSON files",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("OLLAMA_MODEL", "hf.co/mradermacher/DeepSeek-V4-Pro-Qwen3.5-4B-UNCENSORED-heretic-GGUF:Q4_K_M"),
        help="Ollama model tag to evaluate",
    )
    parser.add_argument(
        "--ollama-host",
        default=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"),
        help="URL of Ollama server",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run against mock baseline for dry-run or testing without live Ollama",
    )

    args = parser.parse_args()
    ret = run_evaluation(
        golden_dir=args.golden_dir,
        model=args.model,
        ollama_host=args.ollama_host,
        mock=args.mock,
    )
    sys.exit(ret)


if __name__ == "__main__":
    main()
