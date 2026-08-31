"""Command-line entry points for repeatable experiments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit_store import AuditStore
from .evaluation import bootstrap_metric_interval, classification_metrics
from .features import aggregate_events, read_feature_csv, read_jsonl, write_csv
from .iforest_runtime import IsolationForestRuntime
from .monitor import LocalAuditBackend, OpteeAuditBackend, monitor_batch
from .resource import sample_to_jsonl
from .threshold import PercentileModel
from .training import split_benign_runs, train_and_export
from .workload import ALL_SCENARIOS, run_workload


def features_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate COTE3-Mon JSONL telemetry")
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--output", required=True)
    parser.add_argument("--window-seconds", type=int, default=5)
    parser.add_argument("--warmup-seconds", type=int, default=10)
    args = parser.parse_args(argv)
    rows = aggregate_events(
        read_jsonl(args.inputs), args.window_seconds, args.warmup_seconds
    )
    write_csv(rows, args.output)
    print(f"wrote {len(rows)} feature windows to {args.output}")
    return 0


def train_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train baseline and Isolation Forest models")
    parser.add_argument("features")
    parser.add_argument("--output-directory", default="artifacts/models")
    parser.add_argument("--fpr", type=float, default=0.01)
    parser.add_argument("--baseline-only", action="store_true")
    args = parser.parse_args(argv)
    rows = read_feature_csv(args.features)
    training, validation, _ = split_benign_runs(rows)
    output = Path(args.output_directory)
    output.mkdir(parents=True, exist_ok=True)
    baseline = PercentileModel.fit(training, validation, args.fpr)
    baseline.save(output / "percentile.json")
    if not args.baseline_only:
        train_and_export(training, validation, output / "iforest.json", args.fpr)
    print(f"models written to {output}")
    return 0


def evaluate_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a COTE3-Mon detector")
    parser.add_argument("features")
    parser.add_argument("model")
    args = parser.parse_args(argv)
    rows = read_feature_csv(args.features)
    model_data = json.loads(Path(args.model).read_text(encoding="utf-8"))
    if model_data.get("schema") == "cote3-mon-iforest-v1":
        model = IsolationForestRuntime(model_data)
    elif model_data.get("schema") == "cote3-mon-percentile-v1":
        model = PercentileModel.load(args.model)
    else:
        raise ValueError("unsupported model")
    labels = [int(row["is_attack"]) for row in rows]
    scores = [model.score(row) for row in rows]
    metrics = classification_metrics(labels, scores, model.threshold)
    for name in ("f1", "auprc"):
        low, high = bootstrap_metric_interval(labels, scores, model.threshold, name)
        metrics[f"{name}_ci95"] = [low, high]
    print(json.dumps(metrics, indent=2))
    return 0


def workload_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a synthetic COTE3-Mon workload")
    parser.add_argument("scenario", choices=ALL_SCENARIOS)
    parser.add_argument("--socket", default="/run/cote3-mon/gateway.sock")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    count = run_workload(args.socket, args.scenario, args.duration, args.seed)
    print(f"sent {count} requests")
    return 0


def audit_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Use the local audit-TA reference backend")
    parser.add_argument("--state", default="artifacts/audit/state.json")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register = subparsers.add_parser("register")
    register.add_argument("model")
    append = subparsers.add_parser("append")
    append.add_argument("alert_json")
    verify = subparsers.add_parser("verify")
    verify.add_argument("records_jsonl")
    args = parser.parse_args(argv)
    store = AuditStore(args.state)
    if args.command == "register":
        print(store.register_model(Path(args.model)))
    elif args.command == "append":
        alert = json.loads(Path(args.alert_json).read_text(encoding="utf-8"))
        print(json.dumps(store.append(alert), indent=2))
    else:
        records = [json.loads(line) for line in Path(args.records_jsonl).read_text(encoding="utf-8").splitlines() if line]
        valid = store.verify_chain(records)
        print("valid" if valid else "invalid")
        return 0 if valid else 1
    return 0


def monitor_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score telemetry and create TEE-anchored alerts")
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--model", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--window-seconds", type=int, default=5)
    parser.add_argument("--warmup-seconds", type=int, default=10)
    parser.add_argument("--audit-backend", choices=("local", "optee"), default="local")
    parser.add_argument("--audit-state", default="artifacts/audit/state.json")
    parser.add_argument("--audit-client", default="audit-client")
    args = parser.parse_args(argv)
    backend = (
        LocalAuditBackend(args.audit_state)
        if args.audit_backend == "local"
        else OpteeAuditBackend(args.audit_client)
    )
    result = monitor_batch(
        args.inputs,
        args.model,
        args.alerts,
        backend,
        args.window_seconds,
        args.warmup_seconds,
    )
    print(json.dumps(result, indent=2))
    return 0


def resource_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sample Linux process CPU and RSS")
    parser.add_argument("pid", type=int)
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--attack", action="store_true")
    parser.add_argument("--duration", type=float, default=60.0)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args(argv)
    count = sample_to_jsonl(
        args.pid,
        args.output,
        args.run_id,
        args.scenario,
        args.attack,
        args.duration,
        args.interval,
    )
    print(f"wrote {count} resource samples")
    return 0
