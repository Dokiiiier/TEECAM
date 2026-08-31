"""Window scoring and alert receipt creation for the REE monitor."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Iterable, Mapping, Protocol

from .audit_store import AuditStore, canonical_json
from .features import aggregate_events, read_jsonl
from .iforest_runtime import IsolationForestRuntime
from .threshold import PercentileModel


class Detector(Protocol):
    threshold: float
    features: list[str]

    def score(self, row: Mapping) -> float: ...


class AuditBackend(Protocol):
    def register_model(self, model_path: Path) -> str: ...
    def append(self, alert: Mapping) -> dict: ...


class LocalAuditBackend:
    def __init__(self, state_path: str | Path):
        self.store = AuditStore(state_path)

    def register_model(self, model_path: Path) -> str:
        return self.store.register_model(model_path)

    def append(self, alert: Mapping) -> dict:
        return self.store.append(alert)


class OpteeAuditBackend:
    def __init__(self, executable: str = "audit-client"):
        self.executable = executable

    def _run(self, *arguments: str) -> str:
        completed = subprocess.run(
            [self.executable, *arguments], check=True, text=True, capture_output=True
        )
        return completed.stdout.strip()

    def register_model(self, model_path: Path) -> str:
        digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
        self._run("register", digest)
        return digest

    def append(self, alert: Mapping) -> dict:
        digest = hashlib.sha256(canonical_json(alert)).hexdigest()
        return json.loads(self._run("append", digest))

    def get_head(self) -> dict:
        return json.loads(self._run("head"))

    def verify_receipt(self, receipt: Mapping) -> bool:
        try:
            output = self._run(
                "verify",
                str(int(receipt["sequence"])),
                str(receipt["previous_head"]),
                str(receipt["alert_hash"]),
                str(receipt["model_hash"]),
                str(receipt["head"]),
            )
        except (KeyError, TypeError, ValueError, subprocess.CalledProcessError):
            return False
        return output == "VALID"

    def verify_chain(
        self, records: Iterable[Mapping], require_current_head: bool = True
    ) -> bool:
        previous = "00" * 32
        sequence = 0
        model_hash: str | None = None
        for record in records:
            try:
                receipt = record["receipt"]
                sequence += 1
                alert_hash = hashlib.sha256(
                    canonical_json(record["alert"])
                ).hexdigest()
                fields = (
                    str(receipt["previous_head"]),
                    str(receipt["alert_hash"]),
                    str(receipt["model_hash"]),
                    str(receipt["head"]),
                )
                if any(len(value) != 64 for value in fields):
                    return False
                if any(any(character not in "0123456789abcdef" for character in value)
                       for value in fields):
                    return False
                if int(receipt["sequence"]) != sequence:
                    return False
                if fields[0] != previous or fields[1] != alert_hash:
                    return False
                if model_hash is None:
                    model_hash = fields[2]
                elif fields[2] != model_hash:
                    return False
                if not self.verify_receipt(receipt):
                    return False
                previous = fields[3]
            except (KeyError, TypeError, ValueError):
                return False
        if not require_current_head:
            return True
        try:
            current = self.get_head()
            return (
                int(current["sequence"]) == sequence
                and str(current["head"]) == previous
                and (sequence == 0 or str(current["model_hash"]) == model_hash)
            )
        except (KeyError, TypeError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError):
            return False


def load_detector(model_path: str | Path) -> Detector:
    path = Path(model_path)
    model = json.loads(path.read_text(encoding="utf-8"))
    if model.get("schema") == "cote3-mon-iforest-v1":
        return IsolationForestRuntime(model)
    if model.get("schema") == "cote3-mon-percentile-v1":
        return PercentileModel.load(path)
    raise ValueError("unsupported detector model")


def monitor_batch(
    telemetry_paths: list[str | Path],
    model_path: str | Path,
    alerts_path: str | Path,
    audit_backend: AuditBackend,
    window_seconds: int = 5,
    warmup_seconds: int = 10,
) -> dict:
    detector = load_detector(model_path)
    model_path = Path(model_path)
    model_hash = audit_backend.register_model(model_path)
    rows = aggregate_events(
        read_jsonl(telemetry_paths), window_seconds, warmup_seconds
    )
    alerts_path = Path(alerts_path)
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    alert_count = 0
    with alerts_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            score = detector.score(row)
            if score <= detector.threshold:
                continue
            alert = {
                "schema": "cote3-mon-alert-v1",
                "run_id": row["run_id"],
                "scenario": row["scenario"],
                "window_start_ns": row["window_start_ns"],
                "score": score,
                "threshold": detector.threshold,
                "model_hash": model_hash,
                "features": {name: row[name] for name in detector.features},
            }
            receipt = audit_backend.append(alert)
            record = {"alert": alert, "receipt": receipt}
            handle.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
            alert_count += 1
    return {"windows": len(rows), "alerts": alert_count, "model_hash": model_hash}
