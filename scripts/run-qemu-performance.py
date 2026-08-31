#!/usr/bin/env python3
"""Run the four fixed Stage 4 performance configurations in the QEMU guest."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import sys
import threading
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cote3mon.features import percentile
from cote3mon.resource import ProcessSampler

RUNNER_PATH = Path(__file__).with_name("run-qemu-experiments.py")
SPEC = importlib.util.spec_from_file_location("cote3_qemu_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(RUNNER)


def resource_summary(path: Path) -> dict:
    groups: dict[str, dict[str, list[float]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        event = json.loads(line)
        group = groups.setdefault(event["component"], {"cpu": [], "rss": []})
        group["cpu"].append(float(event["cpu_percent"]))
        group["rss"].append(float(event["rss_kb"]))
    return {
        name: {
            "samples": len(values["cpu"]),
            "cpu_percent_mean": statistics.fmean(values["cpu"]),
            "cpu_percent_p95": percentile(values["cpu"], 0.95),
            "rss_kb_mean": statistics.fmean(values["rss"]),
            "rss_kb_p95": percentile(values["rss"], 0.95),
        }
        for name, values in groups.items()
        if values["cpu"]
    }


def sample_processes(
    processes: dict[str, int], output: Path, duration: float, errors: list[str]
) -> None:
    samplers = {name: ProcessSampler(pid) for name, pid in processes.items()}
    deadline = time.monotonic() + duration
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        while time.monotonic() < deadline:
            for name, sampler in list(samplers.items()):
                try:
                    cpu, rss = sampler.sample()
                except (FileNotFoundError, ProcessLookupError):
                    samplers.pop(name, None)
                    continue
                event = {
                    "schema": "cote3-mon-performance-resource-v1",
                    "ts_unix_ns": time.time_ns(),
                    "component": name,
                    "cpu_percent": cpu,
                    "rss_kb": rss,
                }
                handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
                handle.flush()
            time.sleep(1.0)
    if not output.exists() or not output.stat().st_size:
        errors.append("resource sampler produced no events")


def result_is_reusable(output: Path, configuration: str, repeat: int, duration: float) -> bool:
    run_id = f"{configuration}-{repeat:02d}"
    path = output / f"{run_id}-result.json"
    if not path.exists():
        return False
    result = json.loads(path.read_text(encoding="utf-8"))
    checks = (
        result.get("status") == "PASS",
        result.get("configuration") == configuration,
        int(result.get("repeat", -1)) == repeat,
        float(result.get("duration_seconds", -1)) == duration,
        int(result.get("gateway", {}).get("requests", 0)) > 0,
        (output / f"{run_id}-gateway-summary.json").is_file(),
        (output / f"{run_id}-resources.jsonl").is_file(),
    )
    if not all(checks):
        raise RuntimeError(f"existing performance evidence is invalid: {run_id}")
    return True


def execute_run(
    configuration: str,
    repeat: int,
    config: dict,
    gateway: str,
    bundle: Path,
    output: Path,
    model: Path,
) -> None:
    duration = float(config["duration_seconds"])
    scenario = str(config["scenario"])
    seed = int(config["seed"]) + repeat
    run_id = f"{configuration}-{repeat:02d}"
    container_id = f"c3m-perf-{repeat:02d}-{configuration.replace('_', '-')[:20]}"
    paths = {
        "requests": output / f"{run_id}-requests.jsonl",
        "resources": output / f"{run_id}-resources.jsonl",
        "gateway_log": output / f"{run_id}-gateway.log",
        "gateway_summary": output / f"{run_id}-gateway-summary.json",
        "monitor_log": output / f"{run_id}-monitor.log",
        "monitor_summary": output / f"{run_id}-monitor-summary.json",
        "alerts": output / f"{run_id}-alerts.jsonl",
        "done": Path("/tmp") / f"{run_id}.done",
        "result": output / f"{run_id}-result.json",
    }
    for path in paths.values():
        path.unlink(missing_ok=True)
    paths["requests"].touch()
    paths["resources"].touch()
    RUNNER.write_bundle_config(bundle, scenario, duration, seed)
    socket_path = Path("/run/cote3-mon/gateway.sock")
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment.update(
        COTE3_RUN_ID=run_id,
        COTE3_CONTAINER_ID=container_id,
        COTE3_SCENARIO=scenario,
        COTE3_IS_ATTACK="1",
    )
    gateway_args = [
        gateway,
        "--backend", "optee",
        "--socket", str(socket_path),
        "--summary", str(paths["gateway_summary"]),
    ]
    telemetry = configuration != "gateway_only"
    if telemetry:
        gateway_args += ["--telemetry", str(paths["requests"])]
    else:
        gateway_args.append("--no-telemetry")
    gateway_handle = paths["gateway_log"].open("w", encoding="utf-8")
    gateway_process = subprocess.Popen(
        gateway_args,
        env=environment,
        stdout=gateway_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    monitor_process: subprocess.Popen | None = None
    monitor_handle = None
    sampler_thread: threading.Thread | None = None
    sampler_errors: list[str] = []
    started = time.monotonic()
    try:
        RUNNER.wait_for_socket(socket_path, gateway_process)
        subprocess.run(
            ["runc", "delete", "--force", container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["runc", "run", "--no-pivot", "--detach", "--bundle", str(bundle), container_id],
            check=True,
        )
        state = RUNNER.runc_state(container_id)
        if not state or not state.get("pid"):
            raise RuntimeError("runc did not report a container PID")
        container_pid = int(state["pid"])

        if configuration in ("telemetry_iforest", "telemetry_iforest_audit_ta"):
            monitor_handle = paths["monitor_log"].open("w", encoding="utf-8")
            monitor_args = [
                sys.executable,
                str(Path(__file__).with_name("guest-online-monitor.py")),
                "--requests", str(paths["requests"]),
                "--resources", str(paths["resources"]),
                "--model", str(model),
                "--done-file", str(paths["done"]),
                "--output", str(paths["monitor_summary"]),
                "--alerts", str(paths["alerts"]),
                "--window-seconds", str(config["window_seconds"]),
                "--warmup-seconds", str(config["warmup_seconds"]),
            ]
            if configuration == "telemetry_iforest_audit_ta":
                monitor_args += ["--audit-client", "/usr/bin/audit-client"]
            monitor_process = subprocess.Popen(
                monitor_args,
                stdout=monitor_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )

        processes = {"container": container_pid, "gateway": gateway_process.pid}
        if monitor_process:
            processes["monitor"] = monitor_process.pid
        sampler_thread = threading.Thread(
            target=sample_processes,
            args=(processes, paths["resources"], duration, sampler_errors),
            daemon=True,
        )
        sampler_thread.start()
        deadline = time.monotonic() + duration + 15.0
        while time.monotonic() < deadline:
            state = RUNNER.runc_state(container_id)
            if not state or state.get("status") == "stopped":
                break
            time.sleep(0.2)
        else:
            raise TimeoutError(f"container did not stop: {container_id}")
        paths["done"].touch()
        if sampler_thread:
            sampler_thread.join(timeout=5.0)
        if sampler_errors:
            raise RuntimeError("; ".join(sampler_errors))
        if monitor_process:
            if monitor_process.wait(timeout=30.0) != 0:
                raise RuntimeError(f"online monitor failed: {run_id}")

        gateway_process.terminate()
        gateway_process.wait(timeout=10.0)
        gateway_handle.close()
        gateway_summary = json.loads(paths["gateway_summary"].read_text(encoding="utf-8"))
        if int(gateway_summary["requests"]) <= 0:
            raise RuntimeError(f"gateway recorded no requests: {run_id}")
        request_events = RUNNER.count_jsonl(paths["requests"])
        if telemetry and request_events != int(gateway_summary["requests"]):
            raise RuntimeError(
                f"gateway/telemetry request count mismatch: {run_id} "
                f"{gateway_summary['requests']} != {request_events}"
            )
        monitor_summary = None
        if monitor_process:
            monitor_summary = json.loads(paths["monitor_summary"].read_text(encoding="utf-8"))
            if monitor_summary.get("status") != "PASS" or int(monitor_summary.get("windows", 0)) <= 0:
                raise RuntimeError(f"online monitor produced no valid windows: {run_id}")
            if configuration == "telemetry_iforest_audit_ta" and int(monitor_summary.get("alerts", 0)) <= 0:
                raise RuntimeError(f"audit configuration produced no anchored alert: {run_id}")
        resources = resource_summary(paths["resources"])
        result = {
            "schema": "cote3-mon-stage4-performance-run-v1",
            "status": "PASS",
            "run_id": run_id,
            "configuration": configuration,
            "repeat": repeat,
            "scenario": scenario,
            "seed": seed,
            "duration_seconds": duration,
            "elapsed_seconds": time.monotonic() - started,
            "telemetry_enabled": telemetry,
            "request_events": request_events,
            "gateway": gateway_summary,
            "resources": resources,
            "monitor": monitor_summary,
        }
        paths["result"].write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(
            f"completed {run_id}: requests={gateway_summary['requests']} "
            f"throughput={gateway_summary['throughput_rps']:.3f}",
            flush=True,
        )
    finally:
        paths["done"].touch()
        subprocess.run(
            ["runc", "delete", "--force", container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if monitor_process and monitor_process.poll() is None:
            monitor_process.terminate()
            try:
                monitor_process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                monitor_process.kill()
                monitor_process.wait(timeout=5.0)
        if monitor_handle and not monitor_handle.closed:
            monitor_handle.close()
        if gateway_process.poll() is None:
            gateway_process.terminate()
            try:
                gateway_process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                gateway_process.kill()
                gateway_process.wait(timeout=5.0)
        if not gateway_handle.closed:
            gateway_handle.close()
        socket_path.unlink(missing_ok=True)
        paths["done"].unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--gateway", default="/usr/bin/cote3-gateway-optee")
    parser.add_argument("--bundle", default="/mnt/host/cote3-bundle")
    parser.add_argument("--runtime-bundle", default="/tmp/cote3-performance-bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--duration", type=float)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.repeats is not None:
        if args.repeats <= 0:
            raise SystemExit("repeats must be positive")
        config["repeats_per_configuration"] = args.repeats
    if args.duration is not None:
        if args.duration <= float(config["warmup_seconds"]):
            raise SystemExit("duration must be greater than warmup_seconds")
        config["duration_seconds"] = args.duration
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(config, indent=2, sort_keys=True) + "\n"
    snapshot = output / "performance-config.json"
    if snapshot.exists() and snapshot.read_text(encoding="utf-8") != canonical:
        raise SystemExit("performance output belongs to a different config")
    snapshot.write_text(canonical, encoding="utf-8")
    model = Path("/mnt/host") / str(config["model"])
    if not model.is_file():
        raise SystemExit(f"formal model is missing: {model}")
    matrix = [
        (configuration, repeat)
        for repeat in range(int(config["repeats_per_configuration"]))
        for configuration in config["configurations"]
    ]
    random.Random(int(config["seed"])).shuffle(matrix)
    runtime = Path(args.runtime_bundle)
    RUNNER.ensure_cgroup_v2()
    RUNNER.stage_runtime_bundle(Path(args.bundle), runtime)
    try:
        for configuration, repeat in matrix:
            if args.resume and result_is_reusable(
                output, configuration, repeat, float(config["duration_seconds"])
            ):
                print(f"skipping {configuration}-{repeat:02d}: validated existing PASS", flush=True)
                continue
            print(f"running {configuration} repeat {repeat + 1}", flush=True)
            execute_run(configuration, repeat, config, args.gateway, runtime, output, model)
    finally:
        RUNNER.remove_runtime_bundle(runtime)
    print("COTE3_STAGE4_PERFORMANCE_COLLECTION_PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
