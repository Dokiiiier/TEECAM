#!/usr/bin/env python3
"""Verify an exported Isolation Forest using only the QEMU guest Python runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
import time

from cote3mon.iforest_runtime import IsolationForestRuntime


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--vectors", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--stage", default="stage3")
    args = parser.parse_args()

    model_path = Path(args.model)
    vectors_path = Path(args.vectors)
    output_path = Path(args.output)
    vectors = json.loads(vectors_path.read_text(encoding="utf-8"))
    if vectors.get("schema") != "cote3-mon-iforest-parity-v1":
        raise RuntimeError("unsupported parity vector schema")
    model_hash = sha256(model_path)
    if model_hash != vectors["model_sha256"]:
        raise RuntimeError("model hash does not match parity vectors")

    runtime = IsolationForestRuntime.load(model_path)
    differences = []
    started = time.perf_counter_ns()
    for row in vectors["rows"]:
        observed = runtime.score(row["values"])
        differences.append(abs(observed - float(row["sklearn_score"])))
    elapsed_ns = time.perf_counter_ns() - started
    maximum = max(differences, default=0.0)
    tolerance = float(vectors["tolerance"])
    if maximum > tolerance:
        raise RuntimeError(f"guest parity failed: {maximum} > {tolerance}")

    result = {
        "schema": f"cote3-mon-{args.stage}-guest-parity-v1",
        "status": "PASS",
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "vectors": len(differences),
        "max_abs_difference": maximum,
        "elapsed_seconds": elapsed_ns / 1e9,
        "mean_inference_us": elapsed_ns / max(len(differences), 1) / 1000.0,
        "tolerance": tolerance,
        "model_sha256": model_hash,
        "dependencies": "Python standard library and cote3mon.iforest_runtime only",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    marker_stage = args.stage.upper().replace("-", "_")
    print(f"COTE3_{marker_stage}_GUEST_PARITY_PASS")
    print(f"architecture={result['architecture']}")
    print(f"vectors={result['vectors']}")
    print(f"max_parity_error={maximum:.17g}")
    print(f"mean_inference_us={result['mean_inference_us']:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
