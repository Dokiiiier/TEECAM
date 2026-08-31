#!/usr/bin/env python3
"""Exercise the real audit TA and verify receipt-chain tamper detection."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from cote3mon.monitor import OpteeAuditBackend


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-client", default="/usr/bin/audit-client")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    model_path = output / "acceptance-model.json"
    records_path = output / "audit-records.jsonl"
    model_path.write_text(
        json.dumps({"schema": "cote3-mon-acceptance-model-v1", "version": 1}),
        encoding="utf-8",
    )

    backend = OpteeAuditBackend(args.audit_client)
    model_hash = backend.register_model(model_path)
    alerts = [
        {"schema": "cote3-mon-alert-v1", "window": 1, "score": 0.91},
        {"schema": "cote3-mon-alert-v1", "window": 2, "score": 0.97},
        {"schema": "cote3-mon-alert-v1", "window": 3, "score": 0.99},
    ]
    records = [
        {"alert": alert, "receipt": backend.append(alert)} for alert in alerts
    ]
    records_path.write_text(
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )

    require(backend.verify_chain(records), "valid audit chain was rejected")

    modified = copy.deepcopy(records)
    modified[1]["alert"]["score"] = 99
    require(not backend.verify_chain(modified), "modified alert was accepted")

    deleted = copy.deepcopy(records[:-1])
    require(not backend.verify_chain(deleted), "deleted alert was accepted")

    reordered = copy.deepcopy(records)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    require(not backend.verify_chain(reordered), "reordered alerts were accepted")

    forged = copy.deepcopy(records)
    original_head = forged[1]["receipt"]["head"]
    forged[1]["receipt"]["head"] = (
        ("0" if original_head[0] != "0" else "1") + original_head[1:]
    )
    require(not backend.verify_chain(forged), "forged TEE receipt was accepted")

    result = {
        "status": "PASS",
        "records": len(records),
        "model_hash": model_hash,
        "checks": ["valid", "modified", "deleted", "reordered", "forged"],
    }
    (output / "audit-result.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    print("AUDIT_CHAIN_VALID")
    print("AUDIT_MODIFICATION_REJECTED")
    print("AUDIT_DELETION_REJECTED")
    print("AUDIT_REORDER_REJECTED")
    print("AUDIT_FORGERY_REJECTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
