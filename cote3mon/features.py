"""Deterministic five-second feature aggregation for gateway telemetry."""

from __future__ import annotations

import csv
from collections import defaultdict
import json
import math
from pathlib import Path
from statistics import fmean, pstdev
from typing import Iterable, Mapping, Sequence


BASE_FEATURE_NAMES = [
    "request_rate",
    "put_ratio",
    "get_ratio",
    "delete_ratio",
    "reject_ratio",
    "error_ratio",
    "latency_mean_us",
    "latency_p95_us",
    "input_mean_bytes",
    "input_max_bytes",
    "cpu_percent_mean",
    "rss_kb_mean",
]

# Keep FEATURE_NAMES as the original 12-dimensional interface so the existing
# Stage 3/4 models and scripts remain reproducible.
FEATURE_NAMES = BASE_FEATURE_NAMES

REPETITION_FEATURE_NAMES = [
    "key_reuse_ratio",
    "request_reuse_ratio",
]

TEMPORAL_FEATURE_NAMES = [
    "operation_transition_ratio",
    "idle_mean_us",
    "idle_p95_us",
    "idle_cv",
]

ENHANCED_FEATURE_NAMES = (
    BASE_FEATURE_NAMES + REPETITION_FEATURE_NAMES + TEMPORAL_FEATURE_NAMES
)

META_NAMES = ["run_id", "scenario", "is_attack", "window_start_ns"]


def percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def read_jsonl(paths: Iterable[str | Path]) -> list[dict]:
    events: list[dict] = []
    for path in paths:
        with Path(path).open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
    return events


def aggregate_events(
    events: Iterable[Mapping], window_seconds: int = 5, warmup_seconds: int = 0
) -> list[dict]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if warmup_seconds < 0:
        raise ValueError("warmup_seconds cannot be negative")
    event_list = list(events)
    first_request: dict[str, int] = {}
    for event in event_list:
        if event.get("event_type", "request") != "request":
            continue
        run_id = str(event.get("run_id", "unknown"))
        timestamp = int(event["ts_unix_ns"])
        first_request[run_id] = min(first_request.get(run_id, timestamp), timestamp)
    window_ns = window_seconds * 1_000_000_000
    warmup_ns = warmup_seconds * 1_000_000_000
    buckets: dict[tuple[str, int], list[Mapping]] = defaultdict(list)
    for event in event_list:
        timestamp = int(event["ts_unix_ns"])
        run_id = str(event.get("run_id", "unknown"))
        if run_id in first_request and timestamp < first_request[run_id] + warmup_ns:
            continue
        start = timestamp - timestamp % window_ns
        buckets[(run_id, start)].append(event)

    rows: list[dict] = []
    for (run_id, start), bucket in sorted(buckets.items()):
        requests = [event for event in bucket if event.get("event_type", "request") == "request"]
        resources = [event for event in bucket if event.get("event_type") == "resource"]
        if not requests:
            continue
        requests.sort(key=lambda event: int(event["ts_unix_ns"]))
        count = len(requests)
        operations = [str(event.get("operation", "UNKNOWN")).upper() for event in requests]
        statuses = [str(event.get("result", "BACKEND_ERROR")).upper() for event in requests]
        latencies = [float(event.get("latency_us", 0.0)) for event in requests]
        sizes = [float(event.get("input_bytes", 0.0)) for event in requests]
        scenario = str(requests[0].get("scenario", "unknown"))
        is_attack = int(bool(requests[0].get("is_attack", False)))
        key_fingerprints = [
            str(event["key_fingerprint"])
            for event in requests
            if event.get("key_fingerprint")
        ]
        request_fingerprints = [
            str(event["request_fingerprint"])
            for event in requests
            if event.get("request_fingerprint")
        ]
        operation_transition_ratio = (
            sum(left != right for left, right in zip(operations, operations[1:]))
            / (count - 1)
            if count > 1
            else 0.0
        )
        idle_values: list[float] = []
        for previous, current in zip(requests, requests[1:]):
            previous_end_ns = int(previous["ts_unix_ns"])
            current_end_ns = int(current["ts_unix_ns"])
            current_start_ns = current_end_ns - int(
                round(float(current.get("latency_us", 0.0)) * 1000.0)
            )
            idle_values.append(max(0.0, (current_start_ns - previous_end_ns) / 1000.0))
        idle_mean = fmean(idle_values) if idle_values else 0.0
        row = {
            "run_id": run_id,
            "scenario": scenario,
            "is_attack": is_attack,
            "window_start_ns": start,
            "request_rate": count / float(window_seconds),
            "put_ratio": operations.count("PUT") / count,
            "get_ratio": operations.count("GET") / count,
            "delete_ratio": operations.count("DELETE") / count,
            "reject_ratio": operations.count("REJECT") / count,
            "error_ratio": sum(status != "OK" for status in statuses) / count,
            "latency_mean_us": fmean(latencies),
            "latency_p95_us": percentile(latencies, 0.95),
            "input_mean_bytes": fmean(sizes),
            "input_max_bytes": max(sizes),
            "cpu_percent_mean": fmean(
                float(event.get("cpu_percent", 0.0)) for event in resources
            ) if resources else 0.0,
            "rss_kb_mean": fmean(float(event.get("rss_kb", 0.0)) for event in resources)
            if resources else 0.0,
            "key_reuse_ratio": (
                1.0 - len(set(key_fingerprints)) / len(key_fingerprints)
                if key_fingerprints
                else 0.0
            ),
            "request_reuse_ratio": (
                1.0 - len(set(request_fingerprints)) / len(request_fingerprints)
                if request_fingerprints
                else 0.0
            ),
            "operation_transition_ratio": operation_transition_ratio,
            "idle_mean_us": idle_mean,
            "idle_p95_us": percentile(idle_values, 0.95),
            "idle_cv": pstdev(idle_values) / idle_mean
            if len(idle_values) > 1 and idle_mean > 0.0
            else 0.0,
        }
        rows.append(row)
    return rows


def write_csv(
    rows: Iterable[Mapping],
    path: str | Path,
    features: Sequence[str] = FEATURE_NAMES,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=META_NAMES + list(features))
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row[name] for name in writer.fieldnames})


def read_feature_csv(
    path: str | Path, features: Sequence[str] = FEATURE_NAMES
) -> list[dict]:
    rows: list[dict] = []
    with Path(path).open("r", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            converted = {name: float(row[name]) for name in features}
            converted.update(
                run_id=row["run_id"],
                scenario=row["scenario"],
                is_attack=int(row["is_attack"]),
                window_start_ns=int(row["window_start_ns"]),
            )
            rows.append(converted)
    return rows
