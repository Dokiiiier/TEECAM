#!/usr/bin/env python3
"""Execute the fixed COTE3-Mon scenario matrix inside the QEMU REE guest."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cote3mon.resource import sample_to_jsonl


def wait_for_socket(path: Path, process: subprocess.Popen, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError("gateway exited before creating its socket")
        time.sleep(0.05)
    raise TimeoutError(f"gateway socket did not appear: {path}")


def write_bundle_config(bundle: Path, scenario: str, duration: float, seed: int) -> None:
    path = bundle / "config.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    config["process"]["args"] = [
        "/bin/cote3-workload",
        scenario,
        "--duration",
        str(duration),
        "--seed",
        str(seed),
    ]
    config["root"]["path"] = str((bundle / "rootfs").resolve())
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def is_mounted(path: Path) -> bool:
    target = str(path.resolve())
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == target:
            return True
    return False


def ensure_cgroup_v2() -> None:
    target = Path("/sys/fs/cgroup")
    if is_mounted(target):
        return
    filesystems = Path("/proc/filesystems").read_text(encoding="utf-8")
    if "cgroup2" not in filesystems:
        raise RuntimeError("guest kernel does not support cgroup v2")
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(["mount", "-t", "cgroup2", "cgroup2", str(target)], check=True)


def stage_runtime_bundle(source: Path, runtime: Path) -> None:
    """Copy a 9P-visible bundle to guest tmpfs and make its rootfs a mount point."""
    source = source.resolve()
    if not (source / "config.json").is_file() or not (source / "rootfs").is_dir():
        raise RuntimeError(f"invalid OCI bundle: {source}")
    if (source / "rootfs/dev/tee0").exists() or (source / "rootfs/dev/teepriv0").exists():
        raise RuntimeError("source bundle exposes a TEE device")
    if is_mounted(runtime / "rootfs"):
        subprocess.run(["umount", str(runtime / "rootfs")], check=True)
    shutil.rmtree(runtime, ignore_errors=True)
    runtime.mkdir(parents=True)
    shutil.copy2(source / "config.json", runtime / "config.json")
    shutil.copytree(source / "rootfs", runtime / "rootfs", symlinks=True)
    subprocess.run(["mount", "--bind", str(runtime / "rootfs"), str(runtime / "rootfs")], check=True)


def remove_runtime_bundle(runtime: Path) -> None:
    if is_mounted(runtime / "rootfs"):
        subprocess.run(["umount", str(runtime / "rootfs")], check=False)
    shutil.rmtree(runtime, ignore_errors=True)


def count_jsonl(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line)


def reusable_passed_run(
    output: Path,
    scenario: str,
    attack: bool,
    repeat: int,
    duration: float,
    seed: int,
) -> bool:
    """Validate a completed run before a long collection safely skips it."""
    run_id = f"{scenario}-{repeat:02d}"
    result_path = output / f"{run_id}-result.json"
    if not result_path.exists():
        return False
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"existing result is unreadable; refusing to overwrite {run_id}") from exc

    request_count = count_jsonl(output / f"{run_id}-requests.jsonl")
    resource_count = count_jsonl(output / f"{run_id}-resources.jsonl")
    checks = {
        "status": result.get("status") == "PASS",
        "run_id": result.get("run_id") == run_id,
        "scenario": result.get("scenario") == scenario,
        "is_attack": result.get("is_attack") is attack,
        "seed": int(result.get("seed", -1)) == seed,
        "duration": float(result.get("duration_seconds", -1)) == float(duration),
        "request_events": request_count > 0
        and int(result.get("request_events", -1)) == request_count,
        "resource_events": resource_count > 0
        and int(result.get("resource_events", -1)) == resource_count,
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise RuntimeError(
            f"existing PASS evidence for {run_id} failed resume validation "
            f"({', '.join(failures)}); refusing to overwrite it"
        )
    return True


def runc_state(container_id: str) -> dict | None:
    completed = subprocess.run(
        ["runc", "state", container_id], text=True, capture_output=True
    )
    return json.loads(completed.stdout) if completed.returncode == 0 else None


def execute_run(
    gateway: str,
    bundle: Path,
    output: Path,
    scenario: str,
    attack: bool,
    repeat: int,
    duration: float,
    seed: int,
    backend: str,
    stage: str,
) -> None:
    run_id = f"{scenario}-{repeat:02d}"
    container_id = f"c3m-{scenario.replace('_', '-')}-{repeat:02d}"
    request_log = output / f"{run_id}-requests.jsonl"
    resource_log = output / f"{run_id}-resources.jsonl"
    gateway_log = output / f"{run_id}-gateway.log"
    result_path = output / f"{run_id}-result.json"
    for path in (request_log, resource_log, gateway_log, result_path):
        path.unlink(missing_ok=True)
    socket_path = Path("/run/cote3-mon/gateway.sock")
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    write_bundle_config(bundle, scenario, duration, seed)
    environment = os.environ.copy()
    environment.update(
        COTE3_RUN_ID=run_id,
        COTE3_CONTAINER_ID=container_id,
        COTE3_SCENARIO=scenario,
        COTE3_IS_ATTACK="1" if attack else "0",
    )
    gateway_handle = gateway_log.open("w", encoding="utf-8")
    gateway_process = subprocess.Popen(
        [gateway, "--backend", backend, "--socket", str(socket_path), "--telemetry", str(request_log)],
        env=environment,
        stdout=gateway_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    sampler_thread: threading.Thread | None = None
    sampler_result: dict[str, object] = {}
    started = time.monotonic()
    try:
        wait_for_socket(socket_path, gateway_process)
        subprocess.run(["runc", "delete", "--force", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            ["runc", "run", "--no-pivot", "--detach", "--bundle", str(bundle), container_id],
            check=True,
        )
        state = runc_state(container_id)
        if not state or not state.get("pid"):
            raise RuntimeError("runc did not report the container init PID")
        container_pid = int(state["pid"])

        def sample_resources() -> None:
            try:
                sampler_result["count"] = sample_to_jsonl(
                    container_pid, resource_log, run_id, scenario, attack, duration, 1.0
                )
            except Exception as exc:  # Preserve a thread failure for the main experiment result.
                sampler_result["error"] = repr(exc)

        sampler_thread = threading.Thread(
            target=sample_resources,
            daemon=True,
        )
        sampler_thread.start()
        deadline = time.monotonic() + duration + 15
        while time.monotonic() < deadline:
            state = runc_state(container_id)
            if not state or state.get("status") == "stopped":
                break
            time.sleep(0.2)
        else:
            raise TimeoutError(f"container did not stop: {container_id}")
        if sampler_thread:
            sampler_thread.join(timeout=5.0)
            if sampler_thread.is_alive():
                raise TimeoutError(f"resource sampler did not stop: {run_id}")
        if "error" in sampler_result:
            raise RuntimeError(f"resource sampler failed: {sampler_result['error']}")
        request_count = count_jsonl(request_log)
        resource_count = count_jsonl(resource_log)
        if request_count == 0:
            raise RuntimeError(f"run produced no request telemetry: {run_id}")
        result_path.write_text(
            json.dumps(
                {
                    "schema": f"cote3-mon-{stage}-run-v1",
                    "status": "PASS",
                    "run_id": run_id,
                    "scenario": scenario,
                    "is_attack": attack,
                    "seed": seed,
                    "duration_seconds": duration,
                    "elapsed_seconds": time.monotonic() - started,
                    "request_events": request_count,
                    "resource_events": resource_count,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(
            f"completed {run_id}: requests={request_count} resources={resource_count}",
            flush=True,
        )
    finally:
        subprocess.run(["runc", "delete", "--force", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gateway_process.terminate()
        try:
            gateway_process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            gateway_process.kill()
            gateway_process.wait(timeout=5.0)
        gateway_handle.close()
        socket_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(PROJECT_ROOT / "experiments/default.json"))
    parser.add_argument("--gateway", default="/usr/bin/cote3-gateway-optee")
    parser.add_argument("--bundle", default="/mnt/host/cote3-bundle")
    parser.add_argument("--runtime-bundle", default="/tmp/cote3-experiment-bundle")
    parser.add_argument("--output", default="/mnt/host/cote3-stage3/raw")
    parser.add_argument("--backend", choices=("mock", "optee"), default="optee")
    parser.add_argument("--smoke", action="store_true", help="three 15-second runs per scenario")
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--duration", type=float)
    parser.add_argument("--stage", help="evidence stage label; defaults to the config value")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip only completed runs whose result and telemetry counts validate",
    )
    args = parser.parse_args()
    if not shutil.which("runc"):
        raise SystemExit("runc is not installed in the guest")
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    stage = str(args.stage or config.get("stage", "stage3"))
    if not stage.replace("-", "").replace("_", "").isalnum():
        raise SystemExit("stage must contain only letters, digits, hyphens, or underscores")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    config_snapshot = output / "experiment-config.json"
    canonical_config = json.dumps(config, indent=2, sort_keys=True) + "\n"
    if config_snapshot.exists():
        if config_snapshot.read_text(encoding="utf-8") != canonical_config:
            raise SystemExit(
                f"output directory belongs to a different experiment config: {config_snapshot}"
            )
    else:
        config_snapshot.write_text(canonical_config, encoding="utf-8")
    repeats = args.repeats if args.repeats is not None else (3 if args.smoke else int(config["repeats_per_scenario"]))
    duration = args.duration if args.duration is not None else (15.0 if args.smoke else float(config["duration_seconds"]))
    if repeats <= 0 or duration <= 0:
        raise SystemExit("repeats and duration must be positive")
    scenarios = [(name, False) for name in config["benign_scenarios"]]
    scenarios += [(name, True) for name in config["attack_scenarios"]]
    runtime_bundle = Path(args.runtime_bundle)
    ensure_cgroup_v2()
    stage_runtime_bundle(Path(args.bundle), runtime_bundle)
    try:
        for scenario, attack in scenarios:
            for repeat in range(repeats):
                run_seed = int(config["seed"]) + repeat
                if args.resume and reusable_passed_run(
                    output, scenario, attack, repeat, duration, run_seed
                ):
                    print(f"skipping {scenario}-{repeat:02d}: validated existing PASS", flush=True)
                    continue
                print(f"running {scenario} repeat {repeat + 1}/{repeats}", flush=True)
                execute_run(
                    args.gateway,
                    runtime_bundle,
                    output,
                    scenario,
                    attack,
                    repeat,
                    duration,
                    run_seed,
                    args.backend,
                    stage,
                )
    finally:
        remove_runtime_bundle(runtime_bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
