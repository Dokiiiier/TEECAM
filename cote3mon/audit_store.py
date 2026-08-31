"""Reference implementation of the audit TA's HMAC receipt-chain semantics."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
from typing import Iterable, Mapping


DOMAIN = b"C3MAUDIT1"
ZERO_HASH = bytes(32)


def canonical_json(value: Mapping) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class AuditStore:
    def __init__(self, state_path: str | Path):
        self.path = Path(state_path)
        if self.path.exists():
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.state = {
                "schema": "cote3-mon-audit-state-v1",
                "key": base64.b64encode(os.urandom(32)).decode("ascii"),
                "model_hash": None,
                "sequence": 0,
                "head": ZERO_HASH.hex(),
            }
            self._persist()

    @property
    def key(self) -> bytes:
        return base64.b64decode(self.state["key"])

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def register_model(self, model: bytes | str | Path) -> str:
        if isinstance(model, Path) or (isinstance(model, str) and Path(model).exists()):
            payload = Path(model).read_bytes()
        elif isinstance(model, str):
            payload = model.encode("utf-8")
        else:
            payload = model
        digest = hashlib.sha256(payload).hexdigest()
        current = self.state["model_hash"]
        if self.state["sequence"] and current != digest:
            raise ValueError("model cannot change after alerts have been appended")
        self.state["model_hash"] = digest
        self._persist()
        return digest

    def append(self, alert: Mapping) -> dict:
        if not self.state["model_hash"]:
            raise ValueError("register a model before appending alerts")
        sequence = int(self.state["sequence"]) + 1
        previous = bytes.fromhex(self.state["head"])
        alert_hash = hashlib.sha256(canonical_json(alert)).digest()
        model_hash = bytes.fromhex(self.state["model_hash"])
        message = DOMAIN + struct.pack("!Q", sequence) + previous + alert_hash + model_hash
        head = hmac.new(self.key, message, hashlib.sha256).digest()
        receipt = {
            "sequence": sequence,
            "previous_head": previous.hex(),
            "alert_hash": alert_hash.hex(),
            "model_hash": model_hash.hex(),
            "head": head.hex(),
        }
        self.state["sequence"] = sequence
        self.state["head"] = head.hex()
        self._persist()
        return receipt

    def verify_receipt(self, alert: Mapping, receipt: Mapping) -> bool:
        try:
            sequence = int(receipt["sequence"])
            previous = bytes.fromhex(str(receipt["previous_head"]))
            alert_hash = hashlib.sha256(canonical_json(alert)).digest()
            model_hash = bytes.fromhex(str(receipt["model_hash"]))
            claimed = bytes.fromhex(str(receipt["head"]))
        except (KeyError, TypeError, ValueError):
            return False
        if alert_hash.hex() != receipt.get("alert_hash"):
            return False
        message = DOMAIN + struct.pack("!Q", sequence) + previous + alert_hash + model_hash
        expected = hmac.new(self.key, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, claimed)

    def verify_chain(self, records: Iterable[Mapping], require_current_head: bool = True) -> bool:
        previous = ZERO_HASH.hex()
        sequence = 0
        last_head = previous
        for record in records:
            receipt = record.get("receipt", {})
            sequence += 1
            if receipt.get("sequence") != sequence or receipt.get("previous_head") != previous:
                return False
            if receipt.get("model_hash") != self.state["model_hash"]:
                return False
            if not self.verify_receipt(record.get("alert", {}), receipt):
                return False
            previous = str(receipt["head"])
            last_head = previous
        if require_current_head:
            return sequence == self.state["sequence"] and last_head == self.state["head"]
        return True

