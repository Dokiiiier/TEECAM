"""Portable development gateway used when OP-TEE/QEMU is not available."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import socket
import threading
import time

from .protocol import Operation, Request, Response, Status, recv_request


class MockGateway:
    def __init__(
        self,
        socket_path: str,
        telemetry_path: str | Path,
        run_id: str,
        scenario: str,
        is_attack: bool,
    ):
        self.socket_path = socket_path
        self.telemetry_path = Path(telemetry_path)
        self.run_id = run_id
        self.scenario = scenario
        self.is_attack = is_attack
        self.storage: dict[bytes, bytes] = {}
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._listener: socket.socket | None = None
        self._telemetry_lock = threading.Lock()
        self._fingerprint_key = os.urandom(16)

    def _fingerprint(self, *parts: bytes) -> str:
        digest = hashlib.blake2b(key=self._fingerprint_key, digest_size=8)
        for part in parts:
            digest.update(len(part).to_bytes(4, "big"))
            digest.update(part)
        return digest.hexdigest()

    def start(self) -> None:
        self.telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        self._thread = threading.Thread(target=self._serve, name="mock-gateway", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5.0):
            raise TimeoutError("mock gateway did not start")

    def stop(self) -> None:
        self._stop.set()
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5.0)
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def __enter__(self) -> "MockGateway":
        self.start()
        return self

    def __exit__(self, *_args) -> None:
        self.stop()

    def _serve(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener = listener
        listener.bind(self.socket_path)
        listener.listen(32)
        listener.settimeout(0.1)
        self._ready.set()
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                self._handle(connection)

    def _handle(self, connection: socket.socket) -> None:
        start = time.perf_counter_ns()
        request: Request | None = None
        operation = "REJECT"
        input_bytes = 0
        status = Status.PROTOCOL_ERROR
        response_value = b""
        key_fingerprint = ""
        request_fingerprint = ""
        try:
            request = recv_request(connection)
            operation = request.operation.name
            input_bytes = len(request.key) + len(request.value)
            operation_bytes = int(request.operation).to_bytes(2, "big")
            key_fingerprint = self._fingerprint(request.key)
            request_fingerprint = self._fingerprint(
                operation_bytes, request.key, request.value
            )
            if request.operation is Operation.PUT:
                self.storage[request.key] = request.value
                status = Status.OK
            elif request.operation is Operation.GET:
                if request.key in self.storage:
                    response_value = self.storage[request.key]
                    status = Status.OK
                else:
                    status = Status.NOT_FOUND
            elif request.operation is Operation.DELETE:
                if request.key in self.storage:
                    del self.storage[request.key]
                    status = Status.OK
                else:
                    status = Status.NOT_FOUND
            connection.sendall(Response(request.request_id, status, response_value).encode())
        except (EOFError, ValueError, OSError):
            # Malformed clients are intentionally disconnected without reflecting data.
            status = Status.PROTOCOL_ERROR
        latency_us = (time.perf_counter_ns() - start) / 1000.0
        self._emit(
            {
                "event_type": "request",
                "ts_unix_ns": time.time_ns(),
                "run_id": self.run_id,
                "container_id": "mock-container",
                "scenario": self.scenario,
                "is_attack": self.is_attack,
                "request_id": request.request_id if request else 0,
                "operation": operation,
                "input_bytes": input_bytes,
                "result": status.name,
                "error_origin": "gateway" if status is not Status.OK else "none",
                "latency_us": latency_us,
                "key_fingerprint": key_fingerprint,
                "request_fingerprint": request_fingerprint,
            }
        )

    def _emit(self, event: dict) -> None:
        encoded = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self._telemetry_lock, self.telemetry_path.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
