#!/usr/bin/env python3
"""Dependency-free repeated inference benchmark for Stage 5 guest models."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import platform
import random
from statistics import fmean, pstdev
import time

from cote3mon.iforest_runtime import IsolationForestRuntime


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--repeats", type=int, default=10)
    args = parser.parse_args()
    analysis = Path(args.analysis)
    names = ["base12", "temporal16", "repetition14", "enhanced18"]
    models = {
        name: IsolationForestRuntime.load(analysis / "models" / f"iforest-{name}.json")
        for name in names
    }
    vectors = {
        name: json.loads((analysis / f"parity-vectors-{name}.json").read_text(encoding="utf-8"))["rows"]
        for name in names
    }
    for name in names:
        for row in vectors[name][:20]:
            models[name].score(row["values"])
    timings = {name: [] for name in names}
    rng = random.Random(42)
    for _ in range(args.repeats):
        order = list(names)
        rng.shuffle(order)
        for name in order:
            started = time.perf_counter_ns()
            for row in vectors[name]:
                models[name].score(row["values"])
            elapsed_us = (time.perf_counter_ns() - started) / 1000.0
            timings[name].append(elapsed_us / len(vectors[name]))
    summary = {
        name: {
            "features": len(models[name].features),
            "vectors_per_repeat": len(vectors[name]),
            "repeats": args.repeats,
            "mean_inference_us": fmean(timings[name]),
            "sd_inference_us": pstdev(timings[name]),
            "p50_inference_us": percentile(timings[name], 0.5),
            "p95_inference_us": percentile(timings[name], 0.95),
            "per_repeat_mean_us": timings[name],
        }
        for name in names
    }
    output = {
        "schema": "cote3-mon-stage5-guest-inference-benchmark-v1",
        "status": "PASS",
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "dependencies": "Python standard library and cote3mon.iforest_runtime only",
        "randomised_model_order_per_repeat": True,
        "models": summary,
    }
    (analysis / "guest-inference-benchmark.json").write_text(
        json.dumps(output, indent=2), encoding="utf-8"
    )
    print("COTE3_STAGE5_GUEST_INFERENCE_BENCHMARK_PASS")
    for name, values in summary.items():
        print(
            f"{name}: features={values['features']} mean_us={values['mean_inference_us']:.3f} "
            f"sd_us={values['sd_inference_us']:.3f} p95_us={values['p95_inference_us']:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
