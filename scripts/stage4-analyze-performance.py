#!/usr/bin/env python3
"""Validate and summarize the four-configuration Stage 4 overhead experiment."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics


def nested(item: dict, path: str) -> float | None:
    value = item
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return float(value) if value is not None else None


def mean_ci(values: list[float], iterations: int, seed: int) -> dict:
    if not values:
        return {"mean": None, "ci95": [None, None], "n": 0}
    generator = random.Random(seed)
    means = []
    for _ in range(iterations):
        sample = [values[generator.randrange(len(values))] for _ in values]
        means.append(statistics.fmean(sample))
    means.sort()
    low = means[int(0.025 * (len(means) - 1))]
    high = means[int(0.975 * (len(means) - 1))]
    return {"mean": statistics.fmean(values), "ci95": [low, high], "n": len(values)}


def paired_percent_change_ci(
    baseline: list[dict], current: list[dict], path: str, iterations: int, seed: int
) -> dict:
    baseline_by_repeat = {int(item["repeat"]): nested(item, path) for item in baseline}
    current_by_repeat = {int(item["repeat"]): nested(item, path) for item in current}
    changes = []
    for repeat in sorted(set(baseline_by_repeat) & set(current_by_repeat)):
        left = baseline_by_repeat[repeat]
        right = current_by_repeat[repeat]
        if left not in (None, 0) and right is not None:
            changes.append(100.0 * (right - left) / left)
    return mean_ci(changes, iterations, seed)


METRICS = {
    "throughput_rps": "gateway.throughput_rps",
    "latency_p50_us": "gateway.latency_p50_us",
    "latency_p95_us": "gateway.latency_p95_us",
    "latency_p99_us": "gateway.latency_p99_us",
    "gateway_cpu_percent": "resources.gateway.cpu_percent_mean",
    "gateway_rss_kb": "resources.gateway.rss_kb_mean",
    "container_cpu_percent": "resources.container.cpu_percent_mean",
    "container_rss_kb": "resources.container.rss_kb_mean",
    "monitor_cpu_percent": "resources.monitor.cpu_percent_mean",
    "monitor_rss_kb": "resources.monitor.rss_kb_mean",
    "inference_mean_us": "monitor.inference_latency.mean_us",
    "inference_p95_us": "monitor.inference_latency.p95_us",
    "audit_register_us": "monitor.audit_register_us",
    "audit_append_mean_us": "monitor.audit_append_latency.mean_us",
    "audit_append_p95_us": "monitor.audit_append_latency.p95_us",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=5000)
    args = parser.parse_args()
    raw = Path(args.raw)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    results = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(raw.glob("*-result.json"))
    ]
    configurations = list(config["configurations"])
    repeats = int(config["repeats_per_configuration"])
    expected = len(configurations) * repeats
    if len(results) != expected:
        raise RuntimeError(f"expected {expected} performance runs, found {len(results)}")
    if any(item.get("status") != "PASS" for item in results):
        raise RuntimeError("one or more performance runs did not pass")
    for configuration in configurations:
        group = [item for item in results if item["configuration"] == configuration]
        if len(group) != repeats or {int(item["repeat"]) for item in group} != set(range(repeats)):
            raise RuntimeError(f"repeat coverage is incomplete: {configuration}")
        expected_telemetry = configuration != "gateway_only"
        if any(bool(item["telemetry_enabled"]) != expected_telemetry for item in group):
            raise RuntimeError(f"telemetry state mismatch: {configuration}")
        expected_monitor = configuration in ("telemetry_iforest", "telemetry_iforest_audit_ta")
        if any(bool(item.get("monitor")) != expected_monitor for item in group):
            raise RuntimeError(f"monitor state mismatch: {configuration}")
        if configuration == "telemetry_iforest_audit_ta" and any(
            int(item["monitor"]["alerts"]) <= 0 for item in group
        ):
            raise RuntimeError("an audit run did not append any alert")

    per_configuration: dict[str, dict] = {}
    for config_index, configuration in enumerate(configurations):
        group = [item for item in results if item["configuration"] == configuration]
        summary = {
            "runs": len(group),
            "total_requests": sum(int(item["gateway"]["requests"]) for item in group),
            "total_alerts": sum(int(item["monitor"]["alerts"]) for item in group if item.get("monitor")),
            "metrics": {},
        }
        for metric_index, (name, path) in enumerate(METRICS.items()):
            values = [value for item in group if (value := nested(item, path)) is not None]
            summary["metrics"][name] = mean_ci(
                values, args.bootstrap_iterations, int(config["seed"]) + config_index * 100 + metric_index
            )
        per_configuration[configuration] = summary

    baseline = per_configuration["gateway_only"]["metrics"]
    baseline_runs = [item for item in results if item["configuration"] == "gateway_only"]
    overhead = {}
    previous = None
    for configuration in configurations:
        current = per_configuration[configuration]["metrics"]
        absolute = {}
        progressive = {}
        for metric in ("throughput_rps", "latency_p95_us", "gateway_cpu_percent", "gateway_rss_kb"):
            base_value = baseline[metric]["mean"]
            current_value = current[metric]["mean"]
            absolute[metric] = (
                100.0 * (current_value - base_value) / base_value
                if base_value not in (None, 0) and current_value is not None
                else None
            )
            if previous:
                previous_value = previous[metric]["mean"]
                progressive[metric] = (
                    100.0 * (current_value - previous_value) / previous_value
                    if previous_value not in (None, 0) and current_value is not None
                    else None
                )
        overhead[configuration] = {
            "percent_change_vs_gateway_only": absolute,
            "percent_change_vs_previous_configuration": progressive,
            "paired_percent_change_vs_gateway_only": {
                metric: paired_percent_change_ci(
                    baseline_runs,
                    [item for item in results if item["configuration"] == configuration],
                    METRICS[metric],
                    args.bootstrap_iterations,
                    int(config["seed"]) + 1000 + configurations.index(configuration) * 10 + index,
                )
                for index, metric in enumerate(
                    ("throughput_rps", "latency_p95_us", "gateway_cpu_percent", "gateway_rss_kb")
                )
            },
        }
        previous = current

    summary = {
        "schema": "cote3-mon-stage4-performance-summary-v1",
        "status": "PASS",
        "scope": config["scope"],
        "formal_dissertation_experiment": True,
        "method": {
            "scenario": config["scenario"],
            "repeats_per_configuration": repeats,
            "duration_seconds": config["duration_seconds"],
            "randomized_execution_order": True,
            "paired_comparison": "same repeat number and seed across configurations",
            "bootstrap_iterations": args.bootstrap_iterations,
            "gateway_latency_boundary": (
                "backend/protocol handling through response send; JSONL flush is excluded from the "
                "per-request latency timestamp but included in observed throughput and CPU"
            ),
            "audit_interpretation": (
                "malformed was selected because the formal detector alerted on every malformed window; "
                "this measures a controlled worst-case alert anchoring workload"
            ),
        },
        "per_configuration": per_configuration,
        "overhead": overhead,
    }
    (output / "performance-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    fieldnames = ["configuration", "repeat", "requests"] + list(METRICS)
    with (output / "performance-runs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(results, key=lambda value: (value["configuration"], value["repeat"])):
            row = {
                "configuration": item["configuration"],
                "repeat": item["repeat"],
                "requests": item["gateway"]["requests"],
            }
            row.update({name: nested(item, path) for name, path in METRICS.items()})
            writer.writerow(row)
    print("COTE3_STAGE4_PERFORMANCE_ANALYSIS_PASS")
    print(f"runs={len(results)}")
    for configuration in configurations:
        metrics = per_configuration[configuration]["metrics"]
        print(
            f"{configuration}: throughput={metrics['throughput_rps']['mean']:.3f} "
            f"p95_us={metrics['latency_p95_us']['mean']:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
