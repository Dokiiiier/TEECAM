#!/usr/bin/env python3
"""Run a paired feature-set ablation on one fixed COTE3-Mon QEMU dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Mapping, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cote3mon.evaluation import (
    attack_detection_delays,
    bootstrap_run_metric_interval,
    classification_metrics,
)
from cote3mon.features import (
    ENHANCED_FEATURE_NAMES,
    aggregate_events,
    read_jsonl,
    write_csv,
)
from cote3mon.iforest_runtime import IsolationForestRuntime
from cote3mon.training import (
    export_isolation_forest,
    fit_isolation_forest,
    split_benign_runs_stratified,
)
from stage5_feature_sets import FEATURE_SETS


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_ids(rows: Sequence[Mapping]) -> set[str]:
    return {str(row["run_id"]) for row in rows}


def scenario_summary(
    rows: Sequence[Mapping], scores: Sequence[float], threshold: float
) -> dict[str, dict]:
    output: dict[str, dict] = {}
    for scenario in sorted({str(row["scenario"]) for row in rows}):
        indices = [i for i, row in enumerate(rows) if str(row["scenario"]) == scenario]
        scenario_rows = [rows[i] for i in indices]
        alerts = [float(scores[i]) > threshold for i in indices]
        scenario_runs = run_ids(scenario_rows)
        alerted_runs = {
            str(row["run_id"])
            for row, alerted in zip(scenario_rows, alerts)
            if alerted
        }
        output[scenario] = {
            "is_attack": bool(int(scenario_rows[0]["is_attack"])),
            "windows": len(indices),
            "alert_windows": sum(alerts),
            "window_alert_rate": sum(alerts) / len(alerts),
            "runs": len(scenario_runs),
            "alerted_runs": len(alerted_runs),
            "run_detection_rate": len(alerted_runs) / len(scenario_runs),
        }
    return output


def evaluate(
    rows: Sequence[Mapping],
    runtime: IsolationForestRuntime,
    window_seconds: int,
    bootstrap_iterations: int,
    seed: int,
) -> tuple[dict, list[float]]:
    labels = [int(row["is_attack"]) for row in rows]
    scores = [float(runtime.score(row)) for row in rows]
    metrics = classification_metrics(labels, scores, runtime.threshold)
    for metric in ("precision", "recall", "f1", "auprc"):
        low, high = bootstrap_run_metric_interval(
            rows,
            scores,
            runtime.threshold,
            metric,
            iterations=bootstrap_iterations,
            seed=seed,
        )
        metrics[f"{metric}_ci95"] = [low, high]
    benign_windows = sum(not int(row["is_attack"]) for row in rows)
    benign_hours = benign_windows * window_seconds / 3600.0
    metrics["false_alerts_per_hour"] = metrics["fp"] / benign_hours
    metrics["threshold"] = runtime.threshold
    metrics["per_scenario"] = scenario_summary(rows, scores, runtime.threshold)
    metrics["attack_detection_delay_seconds"] = attack_detection_delays(
        rows, scores, runtime.threshold
    )
    return metrics, scores


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", required=True)
    parser.add_argument(
        "--config", default=str(PROJECT_ROOT / "experiments/stage5-feature-ablation.json")
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=5000)
    args = parser.parse_args()

    raw = Path(args.raw).resolve()
    config_path = Path(args.config).resolve()
    output = Path(args.output).resolve()
    require(not output.exists(), f"refusing to overwrite experiment output: {output}")
    output.mkdir(parents=True)
    models = output / "models"
    models.mkdir()
    config = json.loads(config_path.read_text(encoding="utf-8"))

    request_paths = sorted(raw.glob("*-requests.jsonl"))
    resource_paths = sorted(raw.glob("*-resources.jsonl"))
    result_paths = sorted(raw.glob("*-result.json"))
    require(request_paths and resource_paths and result_paths, "raw experiment evidence is incomplete")
    results = [json.loads(path.read_text(encoding="utf-8")) for path in result_paths]
    require(all(result.get("status") == "PASS" for result in results), "one or more raw runs failed")
    expected_scenarios = set(config["benign_scenarios"]) | set(config["attack_scenarios"])
    require({str(result["scenario"]) for result in results} == expected_scenarios, "scenario coverage mismatch")
    require(
        len(results) == len(expected_scenarios) * int(config["repeats_per_scenario"]),
        "run count mismatch",
    )

    request_events = read_jsonl(request_paths)
    parsed_requests = [
        event
        for event in request_events
        if event.get("event_type", "request") == "request"
        and str(event.get("operation", "REJECT")).upper() != "REJECT"
    ]
    require(parsed_requests, "no parsed request telemetry found")
    require(
        all(event.get("key_fingerprint") and event.get("request_fingerprint") for event in parsed_requests),
        "enhanced request fingerprints are missing",
    )
    require(
        all("key" not in event and "value" not in event for event in request_events),
        "raw key or value appeared in telemetry",
    )

    rows = aggregate_events(
        request_events + read_jsonl(resource_paths),
        window_seconds=int(config["window_seconds"]),
        warmup_seconds=int(config["warmup_seconds"]),
    )
    training, validation, benign_test = split_benign_runs_stratified(
        rows,
        seed=int(config["seed"]),
        scenarios=config["benign_scenarios"],
    )
    attack_test = [row for row in rows if int(row["is_attack"])]
    test = list(benign_test) + attack_test
    split_sets = [run_ids(split) for split in (training, validation, benign_test, attack_test)]
    require(
        all(split_sets[i].isdisjoint(split_sets[j]) for i in range(4) for j in range(i + 1, 4)),
        "complete-run split leakage detected",
    )
    write_csv(rows, output / "features-enhanced-all.csv", ENHANCED_FEATURE_NAMES)

    seed = int(config["seed"])
    fpr = float(config["target_validation_fpr"])
    tolerance = float(config["parity_tolerance"])
    all_metrics: dict[str, dict] = {}
    parity: dict[str, dict] = {}
    for name, features in FEATURE_SETS.items():
        forest = fit_isolation_forest(training, seed=seed, features=features)
        model_path = models / f"iforest-{name}.json"
        exported = export_isolation_forest(
            forest,
            validation,
            model_path,
            false_positive_rate=fpr,
            seed=seed,
            features=features,
        )
        runtime = IsolationForestRuntime(exported)
        parity_rows = list(validation) + list(test)
        reference_scores = [
            -float(score)
            for score in forest.score_samples(
                [[float(row[feature]) for feature in features] for row in parity_rows]
            )
        ]
        runtime_scores = [runtime.score(row) for row in parity_rows]
        max_difference = max(
            abs(reference - observed)
            for reference, observed in zip(reference_scores, runtime_scores)
        )
        require(max_difference <= tolerance, f"{name} runtime parity failed")
        metrics, _ = evaluate(
            test,
            runtime,
            int(config["window_seconds"]),
            args.bootstrap_iterations,
            seed,
        )
        validation_alert_rate = sum(
            runtime.score(row) > runtime.threshold for row in validation
        ) / len(validation)
        metrics["features"] = features
        metrics["validation_window_alert_rate"] = validation_alert_rate
        all_metrics[name] = metrics
        parity[name] = {
            "vectors": len(parity_rows),
            "max_abs_difference": max_difference,
            "tolerance": tolerance,
            "model_sha256": sha256(model_path),
        }

    base = all_metrics["base12"]
    enhanced = all_metrics["enhanced18"]
    comparison = {
        "schema": "cote3-mon-feature-ablation-results-v1",
        "status": "PASS",
        "scope": config["scope"],
        "paired_design": "All feature sets use identical raw runs, complete-run splits, Isolation Forest parameters, and validation calibration.",
        "feature_sets": FEATURE_SETS,
        "windows": {
            "all": len(rows),
            "train": len(training),
            "validation": len(validation),
            "test": len(test),
        },
        "split_run_ids": {
            "train": sorted(split_sets[0]),
            "validation": sorted(split_sets[1]),
            "benign_test": sorted(split_sets[2]),
            "attack_test": sorted(split_sets[3]),
        },
        "metrics": all_metrics,
        "parity": parity,
        "base12_to_enhanced18": {
            "precision_change": enhanced["precision"] - base["precision"],
            "recall_change": enhanced["recall"] - base["recall"],
            "f1_change": enhanced["f1"] - base["f1"],
            "auprc_change": enhanced["auprc"] - base["auprc"],
            "false_positive_change": enhanced["fp"] - base["fp"],
            "flood_run_detection_change": enhanced["per_scenario"]["flood"]["run_detection_rate"] - base["per_scenario"]["flood"]["run_detection_rate"],
            "replay_run_detection_change": enhanced["per_scenario"]["replay"]["run_detection_rate"] - base["per_scenario"]["replay"]["run_detection_rate"],
        },
        "checks": [
            "all 70 QEMU runs passed",
            "raw keys and values were absent from telemetry",
            "keyed equality fingerprints were present for parsed requests",
            "complete-run train, validation, benign-test, and attack-test sets were disjoint",
            "the base and enhanced models used identical raw data and splits",
            "all exported dependency-free runtimes matched scikit-learn",
        ],
        "sha256": {
            "config": sha256(config_path),
            "features": sha256(output / "features-enhanced-all.csv"),
        },
    }
    (output / "feature-ablation-results.json").write_text(
        json.dumps(comparison, indent=2), encoding="utf-8"
    )
    print("COTE3_STAGE5_FEATURE_ABLATION_PASS")
    print(f"windows={len(rows)} test_windows={len(test)}")
    for name in FEATURE_SETS:
        metrics = all_metrics[name]
        print(
            f"{name}: precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
            f"f1={metrics['f1']:.4f} auprc={metrics['auprc']:.4f} fp={metrics['fp']} "
            f"flood_runs={metrics['per_scenario']['flood']['alerted_runs']}/10 "
            f"replay_runs={metrics['per_scenario']['replay']['alerted_runs']}/10"
        )
    print(f"results={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
