"""Versioned local protocol shared by the container client and CA gateway."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import socket
import struct
from typing import BinaryIO


MAGIC = 0x43334D31  # ASCII "C3M1"
VERSION = 1
MAX_KEY_BYTES = 64
MAX_VALUE_BYTES = 4096

REQUEST_STRUCT = struct.Struct("!IHHQII")
RESPONSE_STRUCT = struct.Struct("!IHHQI")


class Operation(IntEnum):
    PUT = 1
    GET = 2
    DELETE = 3


class Status(IntEnum):
    OK = 0
    INVALID = 1
    NOT_FOUND = 2
    BACKEND_ERROR = 3
    TOO_LARGE = 4
    PROTOCOL_ERROR = 5


@dataclass(frozen=True)
class Request:
    request_id: int
    operation: Operation
    key: bytes
    value: bytes = b""

    def encode(self) -> bytes:
        validate_request(self.operation, self.key, self.value)
        header = REQUEST_STRUCT.pack(
            MAGIC,
            VERSION,
            int(self.operation),
            self.request_id,
            len(self.key),
            len(self.value),
        )
        return header + self.key + self.value


@dataclass(frozen=True)
class Response:
    request_id: int
    status: Status
    value: bytes = b""

    def encode(self) -> bytes:
        if len(self.value) > MAX_VALUE_BYTES:
            raise ValueError("response value exceeds protocol limit")
        return RESPONSE_STRUCT.pack(
            MAGIC, VERSION, int(self.status), self.request_id, len(self.value)
        ) + self.value


def validate_request(operation: Operation, key: bytes, value: bytes) -> None:
    if not key or len(key) > MAX_KEY_BYTES:
        raise ValueError(f"key length must be between 1 and {MAX_KEY_BYTES} bytes")
    if len(value) > MAX_VALUE_BYTES:
        raise ValueError(f"value exceeds {MAX_VALUE_BYTES} bytes")
    if operation in (Operation.GET, Operation.DELETE) and value:
        raise ValueError("GET and DELETE do not accept a value")


def recv_exact(stream: socket.socket | BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining) if isinstance(stream, socket.socket) else stream.read(remaining)
        if not chunk:
            raise EOFError(f"connection closed with {remaining} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_request(stream: socket.socket | BinaryIO) -> Request:
    raw = recv_exact(stream, REQUEST_STRUCT.size)
    magic, version, operation_raw, request_id, key_len, value_len = REQUEST_STRUCT.unpack(raw)
    if magic != MAGIC or version != VERSION:
        raise ValueError("unsupported protocol magic or version")
    try:
        operation = Operation(operation_raw)
    except ValueError as exc:
        raise ValueError("unknown operation") from exc
    if key_len == 0 or key_len > MAX_KEY_BYTES or value_len > MAX_VALUE_BYTES:
        raise ValueError("declared payload length is outside protocol bounds")
    payload = recv_exact(stream, key_len + value_len)
    request = Request(request_id, operation, payload[:key_len], payload[key_len:])
    validate_request(request.operation, request.key, request.value)
    return request


def recv_response(stream: socket.socket | BinaryIO) -> Response:
    raw = recv_exact(stream, RESPONSE_STRUCT.size)
    magic, version, status_raw, request_id, value_len = RESPONSE_STRUCT.unpack(raw)
    if magic != MAGIC or version != VERSION:
        raise ValueError("unsupported response magic or version")
    if value_len > MAX_VALUE_BYTES:
        raise ValueError("declared response exceeds protocol bounds")
    try:
        status = Status(status_raw)
    except ValueError as exc:
        raise ValueError("unknown response status") from exc
    return Response(request_id, status, recv_exact(stream, value_len) if value_len else b"")


def call(socket_path: str, request: Request, timeout: float = 5.0) -> Response:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(socket_path)
        client.sendall(request.encode())
        response = recv_response(client)
    if response.request_id != request.request_id:
        raise ValueError("gateway returned a mismatched request identifier")
    return response

