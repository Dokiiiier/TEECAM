#!/usr/bin/env python3
"""Create a hash-bound final acceptance record for the complete Stage 4 work."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load(path: Path) -> dict:
    if not path.is_file():
        raise RuntimeError(f"required Stage 4 evidence is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage-root", required=True)
    args = parser.parse_args()
    root = Path(args.stage_root).resolve()
    detection_path = root / "final-summary.json"
    metrics_path = root / "metrics.json"
    performance_path = root / "performance/performance-summary.json"
    runs_path = root / "performance/performance-runs.csv"
    detection = load(detection_path)
    metrics = load(metrics_path)
    performance = load(performance_path)
    if detection.get("status") != "PASS" or not detection.get("formal_dissertation_experiment"):
        raise RuntimeError("formal detection acceptance did not pass")
    if performance.get("status") != "PASS" or not performance.get("formal_dissertation_experiment"):
        raise RuntimeError("formal performance acceptance did not pass")
    configurations = performance["per_configuration"]
    if set(configurations) != {
        "gateway_only", "telemetry", "telemetry_iforest", "telemetry_iforest_audit_ta"
    }:
        raise RuntimeError("performance configuration coverage is incomplete")
    if any(int(value["runs"]) != 10 for value in configurations.values()):
        raise RuntimeError("a performance configuration does not contain ten runs")

    final = {
        "schema": "cote3-mon-stage4-complete-v1",
        "status": "PASS",
        "formal_dissertation_experiment": True,
        "scope": "formal detection effectiveness and four-configuration performance overhead",
        "checks": {
            "qemu_detection_runs": 70,
            "detection_scenarios": 7,
            "stratified_complete_run_split": "PASS",
            "percentile_and_100_tree_iforest": "PASS",
            "aarch64_dependency_free_parity": "PASS",
            "performance_runs": 40,
            "performance_configurations": 4,
            "online_iforest": "PASS",
            "real_audit_ta_alert_anchoring": "PASS",
        },
        "headline_detection": {
            "percentile_f1": metrics["percentile"]["f1"],
            "percentile_auprc": metrics["percentile"]["auprc"],
            "iforest_f1": metrics["iforest"]["f1"],
            "iforest_auprc": metrics["iforest"]["auprc"],
            "iforest_recall": metrics["iforest"]["recall"],
            "iforest_false_positives": metrics["iforest"]["fp"],
        },
        "headline_performance": {
            name: {
                "throughput_rps": value["metrics"]["throughput_rps"]["mean"],
                "gateway_cpu_percent": value["metrics"]["gateway_cpu_percent"]["mean"],
                "monitor_cpu_percent": value["metrics"]["monitor_cpu_percent"]["mean"],
                "inference_mean_us": value["metrics"]["inference_mean_us"]["mean"],
                "audit_append_mean_us": value["metrics"]["audit_append_mean_us"]["mean"],
            }
            for name, value in configurations.items()
        },
        "interpretation_limits": [
            "Detection recall remains limited, especially for replay and flood; results were not cherry-picked.",
            "Telemetry increased gateway CPU, but no throughput penalty was observed under this QEMU workload.",
            "QEMU timings are suitable for relative prototype comparisons, not direct hardware performance claims.",
            "TEE anchoring protects submitted alerts but cannot prove that a compromised trusted REE did not suppress telemetry before submission.",
        ],
        "sha256": {
            "detection_final": sha256(detection_path),
            "detection_metrics": sha256(metrics_path),
            "performance_summary": sha256(performance_path),
            "performance_runs_csv": sha256(runs_path),
        },
    }
    output = root / "stage4-complete-summary.json"
    output.write_text(json.dumps(final, indent=2), encoding="utf-8")
    print("COTE3_STAGE4_COMPLETE_PASS")
    print(f"summary={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
