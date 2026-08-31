#!/usr/bin/env python3
"""Create hash-bound guest parity vectors for every Stage 5 feature set."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cote3mon.features import aggregate_events, read_jsonl
from cote3mon.iforest_runtime import IsolationForestRuntime
from cote3mon.training import fit_isolation_forest, split_benign_runs_stratified
from stage5_feature_sets import FEATURE_SETS


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--analysis", required=True)
    args = parser.parse_args()
    raw = Path(args.raw).resolve()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    analysis = Path(args.analysis).resolve()

    events = read_jsonl(
        sorted(raw.glob("*-requests.jsonl")) + sorted(raw.glob("*-resources.jsonl"))
    )
    rows = aggregate_events(
        events,
        window_seconds=int(config["window_seconds"]),
        warmup_seconds=int(config["warmup_seconds"]),
    )
    training, validation, benign_test = split_benign_runs_stratified(
        rows,
        seed=int(config["seed"]),
        scenarios=config["benign_scenarios"],
    )
    test = list(benign_test) + [row for row in rows if int(row["is_attack"])]
    parity_rows = list(validation) + test
    tolerance = float(config["parity_tolerance"])

    output: dict[str, dict] = {}
    for name, features in FEATURE_SETS.items():
        model_path = analysis / "models" / f"iforest-{name}.json"
        runtime = IsolationForestRuntime.load(model_path)
        forest = fit_isolation_forest(training, seed=int(config["seed"]), features=features)
        sklearn_scores = [
            -float(score)
            for score in forest.score_samples(
                [[float(row[feature]) for feature in features] for row in parity_rows]
            )
        ]
        runtime_scores = [runtime.score(row) for row in parity_rows]
        maximum = max(
            abs(reference - observed)
            for reference, observed in zip(sklearn_scores, runtime_scores)
        )
        if maximum > tolerance:
            raise RuntimeError(f"{name} refit parity failed: {maximum} > {tolerance}")
        vectors = {
            "schema": "cote3-mon-iforest-parity-v1",
            "model_sha256": sha256(model_path),
            "tolerance": tolerance,
            "features": features,
            "rows": [
                {
                    "run_id": str(row["run_id"]),
                    "scenario": str(row["scenario"]),
                    "is_attack": int(row["is_attack"]),
                    "window_start_ns": int(row["window_start_ns"]),
                    "values": {feature: float(row[feature]) for feature in features},
                    "sklearn_score": score,
                }
                for row, score in zip(parity_rows, sklearn_scores)
            ],
        }
        vector_path = analysis / f"parity-vectors-{name}.json"
        vector_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
        output[name] = {
            "vectors": len(parity_rows),
            "max_abs_difference": maximum,
            "model_sha256": vectors["model_sha256"],
            "vectors_sha256": sha256(vector_path),
        }
    (analysis / "guest-parity-manifest.json").write_text(
        json.dumps(
            {
                "schema": "cote3-mon-stage5-guest-parity-manifest-v1",
                "status": "PASS",
                "feature_sets": output,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("COTE3_STAGE5_GUEST_PARITY_VECTORS_PASS")
    for name, value in output.items():
        print(f"{name}: vectors={value['vectors']} max_difference={value['max_abs_difference']:.17g}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
