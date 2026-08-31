#!/usr/bin/env python3
"""Build a COTE3-Mon dataset, train both detectors, and verify exported inference."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
from typing import Mapping, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cote3mon.evaluation import (
    attack_detection_delays,
    bootstrap_run_metric_interval,
    classification_metrics,
)
from cote3mon.features import FEATURE_NAMES, aggregate_events, read_jsonl, write_csv
from cote3mon.iforest_runtime import IsolationForestRuntime
from cote3mon.threshold import PercentileModel
from cote3mon.training import (
    export_isolation_forest,
    fit_isolation_forest,
    split_benign_runs,
    split_benign_runs_stratified,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_ids(rows: Sequence[Mapping]) -> list[str]:
    return sorted({str(row["run_id"]) for row in rows})


def scenario_run_counts(rows: Sequence[Mapping]) -> dict[str, int]:
    return {
        scenario: len(
            {
                str(row["run_id"])
                for row in rows
                if str(row["scenario"]) == scenario
            }
        )
        for scenario in sorted({str(row["scenario"]) for row in rows})
    }


def evaluate_detector(
    name: str,
    model,
    rows: Sequence[Mapping],
    window_seconds: int,
    bootstrap_iterations: int,
    seed: int,
) -> tuple[dict, list[float]]:
    labels = [int(row["is_attack"]) for row in rows]
    scores = [float(model.score(row)) for row in rows]
    metrics = classification_metrics(labels, scores, float(model.threshold))
    for metric in ("precision", "recall", "f1", "auprc"):
        low, high = bootstrap_run_metric_interval(
            rows,
            scores,
            float(model.threshold),
            metric,
            iterations=bootstrap_iterations,
            seed=seed,
        )
        metrics[f"{metric}_ci95"] = [low, high]
    benign_windows = sum(not int(row["is_attack"]) for row in rows)
    benign_hours = benign_windows * window_seconds / 3600.0
    metrics["false_alerts_per_hour"] = metrics["fp"] / benign_hours if benign_hours else 0.0
    metrics["threshold"] = float(model.threshold)
    metrics["windows"] = len(rows)
    metrics["runs"] = len(run_ids(rows))
    metrics["attack_detection_delay_seconds"] = attack_detection_delays(
        rows, scores, float(model.threshold)
    )
    metrics["per_scenario"] = scenario_summary(rows, scores, float(model.threshold))
    metrics["detector"] = name
    return metrics, scores


def scenario_summary(rows: Sequence[Mapping], scores: Sequence[float], threshold: float) -> dict:
    result: dict[str, dict] = {}
    scenarios = sorted({str(row["scenario"]) for row in rows})
    for scenario in scenarios:
        indices = [index for index, row in enumerate(rows) if str(row["scenario"]) == scenario]
        scenario_rows = [rows[index] for index in indices]
        alerts = [float(scores[index]) > threshold for index in indices]
        attack = bool(int(scenario_rows[0]["is_attack"]))
        scenario_run_ids = sorted({str(row["run_id"]) for row in scenario_rows})
        alerted_runs = {
            str(row["run_id"]) for row, alerted in zip(scenario_rows, alerts) if alerted
        }
        result[scenario] = {
            "is_attack": attack,
            "windows": len(indices),
            "alert_windows": sum(alerts),
            "window_alert_rate": sum(alerts) / len(alerts) if alerts else 0.0,
            "runs": len(scenario_run_ids),
            "alerted_runs": len(alerted_runs),
            "run_detection_rate": len(alerted_runs) / len(scenario_run_ids) if scenario_run_ids else 0.0,
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", required=True, help="directory containing QEMU request/resource JSONL files")
    parser.add_argument("--config", default=str(PROJECT_ROOT / "experiments/stage3-smoke.json"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=1000)
    args = parser.parse_args()

    raw = Path(args.raw).resolve()
    config_path = Path(args.config).resolve()
    output = Path(args.output).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    stage = str(config.get("stage", "stage3"))
    formal = bool(config.get("formal_dissertation_experiment", False))
    marker_stage = stage.upper().replace("-", "_")
    output.mkdir(parents=True, exist_ok=True)
    models = output / "models"
    models.mkdir(parents=True, exist_ok=True)

    request_paths = sorted(raw.glob("*-requests.jsonl"))
    resource_paths = sorted(raw.glob("*-resources.jsonl"))
    result_paths = sorted(raw.glob("*-result.json"))
    require(request_paths, f"no request telemetry found in {raw}")
    require(result_paths, f"no run results found in {raw}")
    results = [json.loads(path.read_text(encoding="utf-8")) for path in result_paths]
    require(all(item.get("status") == "PASS" for item in results), "one or more QEMU runs failed")
    require(all(int(item.get("request_events", 0)) > 0 for item in results), "a run has no request events")
    require(all(int(item.get("resource_events", 0)) > 0 for item in results), "a run has no resource events")

    expected_scenarios = set(config["benign_scenarios"]) | set(config["attack_scenarios"])
    observed_scenarios = {str(item["scenario"]) for item in results}
    require(observed_scenarios == expected_scenarios, "scenario coverage does not match the config")
    expected_runs = len(expected_scenarios) * int(config["repeats_per_scenario"])
    require(len(results) == expected_runs, f"expected {expected_runs} runs, found {len(results)}")

    events = read_jsonl(request_paths + resource_paths)
    rows = aggregate_events(
        events,
        window_seconds=int(config["window_seconds"]),
        warmup_seconds=int(config["warmup_seconds"]),
    )
    require(rows, "feature aggregation produced no windows")
    write_csv(rows, output / "features-all.csv")

    if config.get("stratify_benign_scenarios", False):
        training, validation, benign_test = split_benign_runs_stratified(
            rows,
            seed=int(config["seed"]),
            scenarios=config["benign_scenarios"],
        )
    else:
        training, validation, benign_test = split_benign_runs(
            rows, seed=int(config["seed"])
        )
    attack_test = [row for row in rows if int(row["is_attack"])]
    test = list(benign_test) + attack_test
    train_ids, validation_ids, benign_test_ids = map(set, map(run_ids, (training, validation, benign_test)))
    attack_ids = set(run_ids(attack_test))
    require(train_ids.isdisjoint(validation_ids), "train/validation run leakage")
    require(train_ids.isdisjoint(benign_test_ids), "train/test run leakage")
    require(validation_ids.isdisjoint(benign_test_ids), "validation/test run leakage")
    require((train_ids | validation_ids | benign_test_ids).isdisjoint(attack_ids), "attack data leaked into benign splits")
    require({str(row["scenario"]) for row in attack_test} == set(config["attack_scenarios"]), "attack test coverage is incomplete")
    if config.get("stratify_benign_scenarios", False):
        expected_benign = set(config["benign_scenarios"])
        for name, split_rows in (
            ("training", training),
            ("validation", validation),
            ("benign test", benign_test),
        ):
            require(
                {str(row["scenario"]) for row in split_rows} == expected_benign,
                f"{name} split does not cover every benign scenario",
            )
    write_csv(training, output / "features-train.csv")
    write_csv(validation, output / "features-validation.csv")
    write_csv(test, output / "features-test.csv")

    fpr = float(config["target_validation_fpr"])
    seed = int(config["seed"])
    baseline = PercentileModel.fit(training, validation, fpr)
    baseline_path = models / "percentile.json"
    baseline.save(baseline_path)

    forest = fit_isolation_forest(training, seed=seed)
    iforest_path = models / "iforest.json"
    iforest_model = export_isolation_forest(
        forest, validation, iforest_path, false_positive_rate=fpr, seed=seed
    )
    require(len(iforest_model["trees"]) == 100, "Isolation Forest must contain exactly 100 trees")
    runtime = IsolationForestRuntime(iforest_model)
    parity_rows = list(validation) + list(test)
    x_parity = [[float(row[name]) for name in FEATURE_NAMES] for row in parity_rows]
    sklearn_scores = [-float(value) for value in forest.score_samples(x_parity)]
    runtime_scores = [runtime.score(row) for row in parity_rows]
    differences = [abs(reference - observed) for reference, observed in zip(sklearn_scores, runtime_scores)]
    max_difference = max(differences, default=0.0)
    tolerance = float(config["parity_tolerance"])
    require(max_difference <= tolerance, f"exported runtime parity failed: {max_difference} > {tolerance}")

    vectors = {
        "schema": "cote3-mon-iforest-parity-v1",
        "model_sha256": sha256(iforest_path),
        "tolerance": tolerance,
        "features": FEATURE_NAMES,
        "rows": [
            {
                "run_id": str(row["run_id"]),
                "scenario": str(row["scenario"]),
                "is_attack": int(row["is_attack"]),
                "window_start_ns": int(row["window_start_ns"]),
                "values": {name: float(row[name]) for name in FEATURE_NAMES},
                "sklearn_score": reference,
            }
            for row, reference in zip(parity_rows, sklearn_scores)
        ],
    }
    vectors_path = output / "parity-vectors.json"
    vectors_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    parity = {
        "schema": f"cote3-mon-{stage}-parity-v1",
        "status": "PASS",
        "vectors": len(parity_rows),
        "max_abs_difference": max_difference,
        "tolerance": tolerance,
        "model_sha256": vectors["model_sha256"],
    }
    (output / "parity-host.json").write_text(json.dumps(parity, indent=2), encoding="utf-8")

    validation_baseline_alert_rate = sum(baseline.score(row) > baseline.threshold for row in validation) / len(validation)
    validation_iforest_alert_rate = sum(runtime.score(row) > runtime.threshold for row in validation) / len(validation)
    baseline_metrics, _ = evaluate_detector(
        "percentile", baseline, test, int(config["window_seconds"]), args.bootstrap_iterations, seed
    )
    iforest_metrics, _ = evaluate_detector(
        "iforest", runtime, test, int(config["window_seconds"]), args.bootstrap_iterations, seed
    )
    metrics = {
        "schema": f"cote3-mon-{stage}-metrics-v1",
        "scope": config.get("scope", stage),
        "note": (
            "Formal 10x60-second dissertation detection results."
            if formal
            else "Smoke-stage metrics validate the pipeline and are not the final dissertation results."
        ),
        "validation_window_alert_rate": {
            "target": fpr,
            "percentile": validation_baseline_alert_rate,
            "iforest": validation_iforest_alert_rate,
        },
        "percentile": baseline_metrics,
        "iforest": iforest_metrics,
    }
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    split_manifest = {
        "schema": f"cote3-mon-{stage}-split-v1",
        "seed": seed,
        "strategy": (
            "stratified by benign scenario, then complete runs: 60% train, "
            "20% validation, 20% test; attacks test only"
            if config.get("stratify_benign_scenarios", False)
            else "whole benign runs: 60% train, 20% validation, 20% test; attacks test only"
        ),
        "train_run_ids": sorted(train_ids),
        "validation_run_ids": sorted(validation_ids),
        "benign_test_run_ids": sorted(benign_test_ids),
        "attack_test_run_ids": sorted(attack_ids),
        "windows": {
            "all": len(rows),
            "train": len(training),
            "validation": len(validation),
            "test": len(test),
        },
        "scenario_run_counts": {
            "train": scenario_run_counts(training),
            "validation": scenario_run_counts(validation),
            "benign_test": scenario_run_counts(benign_test),
            "attack_test": scenario_run_counts(attack_test),
        },
        "no_run_leakage": True,
    }
    (output / "split-manifest.json").write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")

    try:
        import numpy
        import sklearn
        dependency_versions = {"numpy": numpy.__version__, "scikit_learn": sklearn.__version__}
    except ImportError as exc:  # Training above should already have produced a clearer error.
        raise RuntimeError("training dependencies disappeared during the run") from exc

    summary = {
        "schema": f"cote3-mon-{stage}-summary-v1",
        "status": "PASS",
        "stage": stage,
        "scope": config.get("scope", stage),
        "formal_dissertation_experiment": formal,
        "experiment": {
            "repeats_per_scenario": int(config["repeats_per_scenario"]),
            "duration_seconds": float(config["duration_seconds"]),
            "warmup_seconds": int(config["warmup_seconds"]),
            "window_seconds": int(config["window_seconds"]),
            "config_sha256": sha256(config_path),
        },
        "checks": [
            "all configured QEMU runs passed",
            "request and resource telemetry present",
            "benign split by complete run with no leakage",
            "every benign scenario represented in train, validation, and test"
            if config.get("stratify_benign_scenarios", False)
            else "global benign run split retained for smoke compatibility",
            "attack data used only for testing",
            "percentile baseline exported",
            "100-tree Isolation Forest exported",
            "host dependency-free runtime matches scikit-learn within tolerance",
            "detection metrics and run-level bootstrap intervals generated",
        ],
        "versions": {
            "python": platform.python_version(),
            **dependency_versions,
        },
        "artifacts": {
            "percentile_sha256": sha256(baseline_path),
            "iforest_sha256": sha256(iforest_path),
            "features_sha256": sha256(output / "features-all.csv"),
            "parity_vectors_sha256": sha256(vectors_path),
        },
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"COTE3_{marker_stage}_HOST_PIPELINE_PASS")
    print(f"feature_windows={len(rows)}")
    print(f"train_runs={len(train_ids)} validation_runs={len(validation_ids)} benign_test_runs={len(benign_test_ids)} attack_test_runs={len(attack_ids)}")
    print(f"iforest_trees={len(iforest_model['trees'])}")
    print(f"max_parity_error={max_difference:.17g}")
    print(f"results={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
