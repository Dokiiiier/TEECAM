"""Low-overhead Linux /proc resource sampler for a container init process."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time


class ProcessSampler:
    def __init__(self, pid: int):
        self.pid = int(pid)
        self.clock_ticks = os.sysconf("SC_CLK_TCK")
        self.previous_cpu: int | None = None
        self.previous_time: int | None = None

    def sample(self) -> tuple[float, int]:
        stat = Path(f"/proc/{self.pid}/stat").read_text(encoding="ascii").split()
        cpu_ticks = int(stat[13]) + int(stat[14])
        now = time.monotonic_ns()
        cpu_percent = 0.0
        if self.previous_cpu is not None and self.previous_time is not None:
            cpu_seconds = (cpu_ticks - self.previous_cpu) / self.clock_ticks
            wall_seconds = (now - self.previous_time) / 1_000_000_000
            cpu_percent = 100.0 * cpu_seconds / wall_seconds if wall_seconds else 0.0
        self.previous_cpu = cpu_ticks
        self.previous_time = now
        rss_kb = 0
        for line in Path(f"/proc/{self.pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
                break
        return cpu_percent, rss_kb


def sample_to_jsonl(
    pid: int,
    output_path: str | Path,
    run_id: str,
    scenario: str,
    is_attack: bool,
    duration_seconds: float,
    interval_seconds: float = 1.0,
) -> int:
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    sampler = ProcessSampler(pid)
    deadline = time.monotonic() + duration_seconds
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("a", encoding="utf-8") as handle:
        while time.monotonic() < deadline:
            try:
                cpu, rss = sampler.sample()
            except (FileNotFoundError, ProcessLookupError):
                # The container process may exit between runc state and /proc sampling.
                break
            event = {
                "event_type": "resource",
                "ts_unix_ns": time.time_ns(),
                "run_id": run_id,
                "scenario": scenario,
                "is_attack": is_attack,
                "cpu_percent": cpu,
                "rss_kb": rss,
            }
            handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
            handle.flush()
            count += 1
            time.sleep(interval_seconds)
    return count
