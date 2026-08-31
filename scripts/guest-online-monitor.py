#!/usr/bin/env python3
"""Stream completed telemetry windows through the guest Isolation Forest."""

from __future__ import annotations

import argparse
from collections import defaultdict
import errno
import json
from pathlib import Path
import statistics
import time

from cote3mon.features import aggregate_events, percentile
from cote3mon.iforest_runtime import IsolationForestRuntime
from cote3mon.monitor import OpteeAuditBackend


def latency_summary(values: list[float]) -> dict:
    return {
        "count": len(values),
        "mean_us": statistics.fmean(values) if values else 0.0,
        "p50_us": percentile(values, 0.50),
        "p95_us": percentile(values, 0.95),
        "p99_us": percentile(values, 0.99),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", required=True)
    parser.add_argument("--resources", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--done-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--window-seconds", type=int, default=5)
    parser.add_argument("--warmup-seconds", type=int, default=10)
    parser.add_argument("--audit-client")
    args = parser.parse_args()

    request_path = Path(args.requests)
    resource_path = Path(args.resources)
    done_path = Path(args.done_file)
    output_path = Path(args.output)
    alerts_path = Path(args.alerts)
    model_path = Path(args.model)
    model = IsolationForestRuntime.load(model_path)
    audit = OpteeAuditBackend(args.audit_client) if args.audit_client else None
    audit_register_us = 0.0
    if audit:
        started = time.perf_counter_ns()
        model_hash = audit.register_model(model_path)
        audit_register_us = (time.perf_counter_ns() - started) / 1000.0
    else:
        model_hash = None

    request_path.parent.mkdir(parents=True, exist_ok=True)
    request_path.touch(exist_ok=True)
    resource_path.touch(exist_ok=True)
    done_path.unlink(missing_ok=True)
    first_request_ns: int | None = None
    buckets: dict[int, list[dict]] = defaultdict(list)
    processed: set[int] = set()
    inference_latencies: list[float] = []
    audit_latencies: list[float] = []
    records: list[dict] = []
    window_ns = args.window_seconds * 1_000_000_000
    warmup_ns = args.warmup_seconds * 1_000_000_000

    def ingest(handle) -> int:
        nonlocal first_request_ns
        count = 0
        while True:
            try:
                line = handle.readline()
            except OSError as exc:
                if exc.errno == errno.ENODATA:
                    break
                raise
            if not line:
                break
            if not line.strip():
                continue
            event = json.loads(line)
            timestamp = int(event["ts_unix_ns"])
            if event.get("event_type", "request") == "request" and first_request_ns is None:
                first_request_ns = timestamp
            if first_request_ns is None or timestamp < first_request_ns + warmup_ns:
                continue
            buckets[timestamp - timestamp % window_ns].append(event)
            count += 1
        return count

    def score_ready(force: bool = False) -> None:
        now = time.time_ns()
        ready = sorted(
            start
            for start in buckets
            if start not in processed and (force or start + window_ns + 250_000_000 <= now)
        )
        for start in ready:
            rows = aggregate_events(buckets[start], window_seconds=args.window_seconds)
            processed.add(start)
            if not rows:
                continue
            row = rows[0]
            began = time.perf_counter_ns()
            score = model.score(row)
            inference_latencies.append((time.perf_counter_ns() - began) / 1000.0)
            if score <= model.threshold:
                continue
            alert = {
                "schema": "cote3-mon-alert-v1",
                "run_id": row["run_id"],
                "scenario": row["scenario"],
                "window_start_ns": row["window_start_ns"],
                "score": score,
                "threshold": model.threshold,
                "model_hash": model_hash,
                "features": {name: row[name] for name in model.features},
            }
            receipt = None
            if audit:
                began = time.perf_counter_ns()
                receipt = audit.append(alert)
                audit_latencies.append((time.perf_counter_ns() - began) / 1000.0)
            records.append({"alert": alert, "receipt": receipt})

    with request_path.open("r", encoding="utf-8") as requests, resource_path.open(
        "r", encoding="utf-8"
    ) as resources:
        quiet_after_done = 0
        while True:
            added = ingest(requests) + ingest(resources)
            score_ready()
            if done_path.exists():
                quiet_after_done = quiet_after_done + 1 if added == 0 else 0
                if quiet_after_done >= 3:
                    break
            time.sleep(0.2)
        score_ready(force=True)

    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    with alerts_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
    result = {
        "schema": "cote3-mon-online-monitor-v1",
        "status": "PASS",
        "windows": len(inference_latencies),
        "alerts": len(records),
        "model_sha256": model_hash,
        "audit_enabled": bool(audit),
        "inference_latency": latency_summary(inference_latencies),
        "audit_register_us": audit_register_us,
        "audit_append_latency": latency_summary(audit_latencies),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("COTE3_ONLINE_MONITOR_PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
