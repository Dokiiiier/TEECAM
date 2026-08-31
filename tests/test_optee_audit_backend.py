import copy
import hashlib
import json
import unittest

from cote3mon.audit_store import canonical_json
from cote3mon.monitor import OpteeAuditBackend


class FakeOpteeAuditBackend(OpteeAuditBackend):
    def __init__(self, current_head):
        super().__init__("fake-audit-client")
        self.current_head = current_head

    def _run(self, *arguments: str) -> str:
        if arguments[0] == "verify":
            return "VALID"
        if arguments[0] == "head":
            return json.dumps(self.current_head)
        raise AssertionError(arguments)


def make_records():
    model_hash = "11" * 32
    previous = "00" * 32
    records = []
    for sequence in range(1, 4):
        alert = {"sequence": sequence, "score": sequence / 10}
        alert_hash = hashlib.sha256(canonical_json(alert)).hexdigest()
        head = f"{sequence:02x}" * 32
        records.append(
            {
                "alert": alert,
                "receipt": {
                    "sequence": sequence,
                    "previous_head": previous,
                    "alert_hash": alert_hash,
                    "model_hash": model_hash,
                    "head": head,
                },
            }
        )
        previous = head
    current = {"sequence": 3, "model_hash": model_hash, "head": previous}
    return records, current


class OpteeAuditBackendTests(unittest.TestCase):
    def test_valid_chain(self):
        records, current = make_records()
        self.assertTrue(FakeOpteeAuditBackend(current).verify_chain(records))

    def test_modified_alert_fails(self):
        records, current = make_records()
        records[1]["alert"]["score"] = 99
        self.assertFalse(FakeOpteeAuditBackend(current).verify_chain(records))

    def test_deleted_record_fails_against_ta_head(self):
        records, current = make_records()
        self.assertFalse(FakeOpteeAuditBackend(current).verify_chain(records[:-1]))

    def test_reordered_records_fail(self):
        records, current = make_records()
        swapped = copy.deepcopy(records)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        self.assertFalse(FakeOpteeAuditBackend(current).verify_chain(swapped))


if __name__ == "__main__":
    unittest.main()
