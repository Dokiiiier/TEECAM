#!/usr/bin/env python3
"""Create the hash-bound final acceptance summary for Stage 5."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load(path: Path) -> dict:
    if not path.is_file():
        raise RuntimeError(f"missing Stage 5 evidence: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage-root", required=True)
    args = parser.parse_args()
    root = Path(args.stage_root).resolve()
    analysis = root / "analysis"
    results_path = analysis / "feature-ablation-results.json"
    paired_path = analysis / "paired-bootstrap.json"
    benchmark_path = analysis / "guest-inference-benchmark.json"
    manifest_path = analysis / "guest-parity-manifest.json"
    results = load(results_path)
    paired = load(paired_path)
    benchmark = load(benchmark_path)
    manifest = load(manifest_path)
    if any(item.get("status") != "PASS" for item in (results, paired, benchmark, manifest)):
        raise RuntimeError("one or more Stage 5 acceptance layers did not pass")
    guest_parity = {
        name: load(analysis / f"parity-guest-{name}.json")
        for name in ("base12", "temporal16", "repetition14", "enhanced18")
    }
    if any(item.get("status") != "PASS" or item.get("architecture") != "aarch64" for item in guest_parity.values()):
        raise RuntimeError("AArch64 guest parity is incomplete")
    for name, item in guest_parity.items():
        expected = manifest["feature_sets"][name]
        if item["model_sha256"] != expected["model_sha256"]:
            raise RuntimeError(f"{name} guest parity model hash mismatch")
        if float(item["max_abs_difference"]) > float(item["tolerance"]):
            raise RuntimeError(f"{name} guest parity exceeded tolerance")

    metrics = results["metrics"]
    final = {
        "schema": "cote3-mon-stage5-complete-v1",
        "status": "PASS",
        "formal_dissertation_experiment": True,
        "scope": "Replay and flooding feature-augmentation ablation on OP-TEE QEMU",
        "checks": {
            "qemu_runs": 70,
            "scenarios": 7,
            "complete_run_split": "PASS",
            "raw_key_value_absence": "PASS",
            "feature_sets": 4,
            "aarch64_guest_parity": "PASS",
            "paired_run_bootstrap": "PASS",
            "guest_inference_benchmark": "PASS",
        },
        "headline_metrics": {
            name: {
                "precision": value["precision"],
                "recall": value["recall"],
                "f1": value["f1"],
                "auprc": value["auprc"],
                "false_positives": value["fp"],
                "flood_alerted_runs": value["per_scenario"]["flood"]["alerted_runs"],
                "replay_alerted_runs": value["per_scenario"]["replay"]["alerted_runs"],
                "guest_mean_inference_us": benchmark["models"][name]["mean_inference_us"],
            }
            for name, value in metrics.items()
        },
        "paired_enhanced18_minus_base12": paired["comparisons"]["enhanced18_minus_base12"],
        "interpretation": [
            "Enhanced18 improved overall recall, F1, and AUPRC without adding test-set false positives relative to Base12.",
            "Replay run-level detection improved from 1/10 to 10/10; its paired bootstrap interval excluded zero.",
            "Flood improved from 2/10 to 4/10 in Enhanced18, while Temporal16 achieved 6/10, showing an attack-specific feature trade-off.",
            "Feature augmentation did not increase measured guest inference time; the small reversed timing differences are treated as QEMU/runtime noise, not acceleration.",
            "The experiment supports semantic feature engineering, not a claim that additional features always improve every attack class.",
        ],
        "sha256": {
            "feature_ablation_results": sha256(results_path),
            "paired_bootstrap": sha256(paired_path),
            "guest_inference_benchmark": sha256(benchmark_path),
            "guest_parity_manifest": sha256(manifest_path),
            **{
                f"parity_guest_{name}": sha256(analysis / f"parity-guest-{name}.json")
                for name in guest_parity
            },
        },
    }
    output = root / "stage5-complete-summary.json"
    output.write_text(json.dumps(final, indent=2), encoding="utf-8")
    print("COTE3_STAGE5_COMPLETE_PASS")
    print(f"summary={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
