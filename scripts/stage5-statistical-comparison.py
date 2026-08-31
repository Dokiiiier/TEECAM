#!/usr/bin/env python3
"""Paired, complete-run bootstrap comparisons for the Stage 5 ablation."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cote3mon.evaluation import classification_metrics
from cote3mon.features import ENHANCED_FEATURE_NAMES, read_feature_csv
from cote3mon.iforest_runtime import IsolationForestRuntime


def percentile(values: list[float], probability: float) -> float:
    values = sorted(values)
    position = int(probability * (len(values) - 1))
    return values[position]


def paired_metric_intervals(
    rows: list[dict],
    left: IsolationForestRuntime,
    right: IsolationForestRuntime,
    iterations: int,
    seed: int,
) -> dict:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        groups[str(row["run_id"])].append(index)
    run_ids = sorted(groups)
    labels = [int(row["is_attack"]) for row in rows]
    left_scores = [left.score(row) for row in rows]
    right_scores = [right.score(row) for row in rows]
    rng = random.Random(seed)
    differences = {name: [] for name in ("precision", "recall", "f1", "auprc")}
    for _ in range(iterations):
        sampled_runs = [run_ids[rng.randrange(len(run_ids))] for _ in run_ids]
        indices = [index for run_id in sampled_runs for index in groups[run_id]]
        sampled_labels = [labels[index] for index in indices]
        if not any(sampled_labels) or all(sampled_labels):
            continue
        left_metrics = classification_metrics(
            sampled_labels,
            [left_scores[index] for index in indices],
            left.threshold,
        )
        right_metrics = classification_metrics(
            sampled_labels,
            [right_scores[index] for index in indices],
            right.threshold,
        )
        for name in differences:
            differences[name].append(right_metrics[name] - left_metrics[name])
    point_left = classification_metrics(labels, left_scores, left.threshold)
    point_right = classification_metrics(labels, right_scores, right.threshold)
    return {
        name: {
            "difference": point_right[name] - point_left[name],
            "ci95": [percentile(values, 0.025), percentile(values, 0.975)],
        }
        for name, values in differences.items()
    }


def paired_run_detection_interval(
    rows: list[dict],
    left: IsolationForestRuntime,
    right: IsolationForestRuntime,
    scenario: str,
    iterations: int,
    seed: int,
) -> dict:
    scenario_rows = [row for row in rows if str(row["scenario"]) == scenario]
    run_ids = sorted({str(row["run_id"]) for row in scenario_rows})
    left_alert = {
        run_id: any(
            left.score(row) > left.threshold
            for row in scenario_rows
            if str(row["run_id"]) == run_id
        )
        for run_id in run_ids
    }
    right_alert = {
        run_id: any(
            right.score(row) > right.threshold
            for row in scenario_rows
            if str(row["run_id"]) == run_id
        )
        for run_id in run_ids
    }
    point = sum(right_alert[r] - left_alert[r] for r in run_ids) / len(run_ids)
    rng = random.Random(seed)
    differences = []
    for _ in range(iterations):
        sampled = [run_ids[rng.randrange(len(run_ids))] for _ in run_ids]
        differences.append(
            sum(right_alert[run_id] - left_alert[run_id] for run_id in sampled)
            / len(sampled)
        )
    return {
        "runs": len(run_ids),
        "left_alerted_runs": sum(left_alert.values()),
        "right_alerted_runs": sum(right_alert.values()),
        "difference": point,
        "ci95": [percentile(differences, 0.025), percentile(differences, 0.975)],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    analysis = Path(args.analysis).resolve()
    results = json.loads((analysis / "feature-ablation-results.json").read_text(encoding="utf-8"))
    rows = read_feature_csv(analysis / "features-enhanced-all.csv", ENHANCED_FEATURE_NAMES)
    test_ids = set(results["split_run_ids"]["benign_test"]) | set(
        results["split_run_ids"]["attack_test"]
    )
    test = [row for row in rows if str(row["run_id"]) in test_ids]
    models = {
        name: IsolationForestRuntime.load(analysis / "models" / f"iforest-{name}.json")
        for name in ("base12", "temporal16", "repetition14", "enhanced18")
    }
    comparisons = {
        "enhanced18_minus_base12": {
            "overall": paired_metric_intervals(
                test, models["base12"], models["enhanced18"], args.iterations, args.seed
            ),
            "replay_run_detection": paired_run_detection_interval(
                test, models["base12"], models["enhanced18"], "replay", args.iterations, args.seed
            ),
            "flood_run_detection": paired_run_detection_interval(
                test, models["base12"], models["enhanced18"], "flood", args.iterations, args.seed
            ),
        },
        "temporal16_minus_base12": {
            "overall": paired_metric_intervals(
                test, models["base12"], models["temporal16"], args.iterations, args.seed
            ),
            "flood_run_detection": paired_run_detection_interval(
                test, models["base12"], models["temporal16"], "flood", args.iterations, args.seed
            ),
        },
        "repetition14_minus_base12": {
            "overall": paired_metric_intervals(
                test, models["base12"], models["repetition14"], args.iterations, args.seed
            ),
            "replay_run_detection": paired_run_detection_interval(
                test, models["base12"], models["repetition14"], "replay", args.iterations, args.seed
            ),
        },
    }
    output = {
        "schema": "cote3-mon-stage5-paired-bootstrap-v1",
        "status": "PASS",
        "iterations": args.iterations,
        "seed": args.seed,
        "resampling_unit": "complete run",
        "interpretation": "Intervals crossing zero do not provide clear evidence of a positive paired difference under this sample.",
        "comparisons": comparisons,
    }
    (analysis / "paired-bootstrap.json").write_text(
        json.dumps(output, indent=2), encoding="utf-8"
    )
    print("COTE3_STAGE5_PAIRED_BOOTSTRAP_PASS")
    for name, comparison in comparisons.items():
        print(name, json.dumps(comparison, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
