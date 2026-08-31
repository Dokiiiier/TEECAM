"""Deterministic benign and attack workloads for the gateway."""

from __future__ import annotations

import random
import socket
import struct
import time
from typing import Callable

from .protocol import MAGIC, VERSION, MAX_VALUE_BYTES, Operation, Request, Status, call


BENIGN_SCENARIOS = ("steady", "bursty", "large_value")
ATTACK_SCENARIOS = ("flood", "malformed", "error_storm", "replay")
ALL_SCENARIOS = BENIGN_SCENARIOS + ATTACK_SCENARIOS


def _request(socket_path: str, request_id: int, op: Operation, key: bytes, value: bytes = b"") -> Status:
    return call(socket_path, Request(request_id, op, key, value)).status


def _malformed(socket_path: str, request_id: int) -> None:
    # Declares an over-limit value without sending it. The gateway must reject before allocation/read.
    header = struct.pack(
        "!IHHQII", MAGIC, VERSION, int(Operation.PUT), request_id, 1, MAX_VALUE_BYTES + 1
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(0.2)
        client.connect(socket_path)
        client.sendall(header + b"k")
        try:
            client.recv(1)
        except (socket.timeout, ConnectionError):
            pass


def run_workload(
    socket_path: str,
    scenario: str,
    duration_seconds: float = 60.0,
    seed: int = 42,
    sleep_scale: float = 1.0,
) -> int:
    if scenario not in ALL_SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")
    rng = random.Random(seed)
    deadline = time.monotonic() + duration_seconds
    request_id = 1
    replay_value = b"R" * 128
    while time.monotonic() < deadline:
        key = f"key-{rng.randrange(32):02d}".encode("ascii")
        if scenario == "steady":
            operation = (Operation.PUT, Operation.GET, Operation.GET, Operation.DELETE)[request_id % 4]
            value = rng.randbytes(64) if operation is Operation.PUT else b""
            _request(socket_path, request_id, operation, key, value)
            time.sleep(0.01 * sleep_scale)
        elif scenario == "bursty":
            for _ in range(8):
                if time.monotonic() >= deadline:
                    break
                _request(socket_path, request_id, Operation.PUT, key, rng.randbytes(96))
                request_id += 1
            time.sleep(0.08 * sleep_scale)
            continue
        elif scenario == "large_value":
            _request(socket_path, request_id, Operation.PUT, key, rng.randbytes(3072))
            time.sleep(0.02 * sleep_scale)
        elif scenario == "flood":
            _request(socket_path, request_id, Operation.PUT, key, b"F" * 32)
        elif scenario == "malformed":
            _malformed(socket_path, request_id)
            time.sleep(0.002 * sleep_scale)
        elif scenario == "error_storm":
            _request(socket_path, request_id, Operation.GET, b"never-created")
            time.sleep(0.002 * sleep_scale)
        elif scenario == "replay":
            _request(socket_path, request_id, Operation.PUT, b"replayed-key", replay_value)
            time.sleep(0.002 * sleep_scale)
        request_id += 1
    return request_id - 1

