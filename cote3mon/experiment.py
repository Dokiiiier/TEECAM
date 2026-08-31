"""Local smoke experiment that exercises the same protocol and data path as QEMU."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .features import aggregate_events, read_jsonl, write_csv
from .mock_gateway import MockGateway
from .workload import ALL_SCENARIOS, ATTACK_SCENARIOS, run_workload


def run_mock_experiment(
    output_directory: str | Path,
    repeats: int = 2,
    duration_seconds: float = 0.25,
    window_seconds: int = 1,
) -> Path:
    output = Path(output_directory)
    telemetry = output / "telemetry.jsonl"
    output.mkdir(parents=True, exist_ok=True)
    telemetry.unlink(missing_ok=True)
    socket_path = str(Path(tempfile.gettempdir()) / f"c3m-{os.getpid()}.sock")
    for scenario in ALL_SCENARIOS:
        for repeat in range(repeats):
            run_id = f"{scenario}-{repeat:02d}"
            with MockGateway(
                socket_path,
                telemetry,
                run_id,
                scenario,
                scenario in ATTACK_SCENARIOS,
            ):
                run_workload(
                    socket_path,
                    scenario,
                    duration_seconds=duration_seconds,
                    seed=42 + repeat,
                    sleep_scale=0.05,
                )
    feature_path = output / "features.csv"
    write_csv(aggregate_events(read_jsonl([telemetry]), window_seconds), feature_path)
    return feature_path

