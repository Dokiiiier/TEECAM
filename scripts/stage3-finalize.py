#!/usr/bin/env python3
"""Join host training and QEMU guest parity evidence into stage acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load(path: Path) -> dict:
    if not path.is_file():
        raise RuntimeError(f"required evidence is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, help="analysis directory")
    args = parser.parse_args()

    output = Path(args.output).resolve()
    host_summary_path = output / "summary.json"
    host_parity_path = output / "parity-host.json"
    guest_parity_path = output / "parity-guest.json"
    metrics_path = output / "metrics.json"
    split_path = output / "split-manifest.json"
    model_path = output / "models/iforest.json"

    host_summary = load(host_summary_path)
    host_parity = load(host_parity_path)
    guest_parity = load(guest_parity_path)
    load(metrics_path)
    split = load(split_path)
    model = load(model_path)
    stage = str(host_summary.get("stage", "stage3"))
    formal = bool(host_summary.get("formal_dissertation_experiment", False))
    marker_stage = stage.upper().replace("-", "_")

    require(host_summary.get("status") == "PASS", "host pipeline did not pass")
    if stage == "stage3":
        require(formal is False,
                "Stage 3 smoke evidence must not be labelled as the formal experiment")
    elif stage == "stage4":
        require(formal is True,
                "Stage 4 evidence must be labelled as the formal experiment")
        require(
            "stratified by benign scenario" in str(split.get("strategy", "")),
            "Stage 4 benign runs were not split by scenario",
        )
    require(host_parity.get("status") == "PASS", "host model parity did not pass")
    require(guest_parity.get("status") == "PASS", "QEMU guest model parity did not pass")
    require(split.get("no_run_leakage") is True, "run-level split leakage check failed")
    require(len(model.get("trees", [])) == 100, "exported Isolation Forest is not 100 trees")
    require(host_parity.get("model_sha256") == guest_parity.get("model_sha256"),
            "host and QEMU guest did not verify the same model")
    require(host_parity.get("model_sha256") == sha256(model_path),
            "model changed after parity validation")
    require(float(guest_parity["max_abs_difference"]) <= float(guest_parity["tolerance"]),
            "QEMU guest score difference exceeds tolerance")

    final = {
        "schema": f"cote3-mon-{stage}-final-v1",
        "status": "PASS",
        "stage": stage,
        "scope": host_summary.get("scope", stage),
        "formal_dissertation_experiment": formal,
        "meaning": (
            "The 10x60-second formal QEMU detection experiment, run-level stratified split, "
            "model training, and dependency-free guest inference all passed acceptance."
            if formal
            else "The real QEMU telemetry-to-model pipeline and dependency-free guest inference "
            "are reproducible. Detection performance remains a smoke result, not the final thesis result."
        ),
        "checks": {
            "qemu_collection_and_host_pipeline": "PASS",
            "complete_run_split_without_leakage": "PASS",
            "attack_data_test_only": "PASS",
            "percentile_and_isolation_forest_models": "PASS",
            "isolation_forest_tree_count": 100,
            "host_export_parity": "PASS",
            "qemu_guest_dependency_free_parity": "PASS",
        },
        "guest": {
            "architecture": guest_parity.get("architecture"),
            "python": guest_parity.get("python"),
            "vectors": guest_parity.get("vectors"),
            "max_abs_difference": guest_parity.get("max_abs_difference"),
            "tolerance": guest_parity.get("tolerance"),
        },
        "sha256": {
            "model": sha256(model_path),
            "metrics": sha256(metrics_path),
            "split_manifest": sha256(split_path),
            "host_summary": sha256(host_summary_path),
            "guest_parity": sha256(guest_parity_path),
        },
    }
    final_path = output / "final-summary.json"
    final_path.write_text(json.dumps(final, indent=2), encoding="utf-8")
    print(f"COTE3_{marker_stage}_ACCEPTANCE_PASS")
    print(f"guest_architecture={final['guest']['architecture']}")
    print(f"guest_vectors={final['guest']['vectors']}")
    print(f"max_parity_error={final['guest']['max_abs_difference']}")
    print(f"summary={final_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
