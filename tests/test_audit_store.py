import copy
from pathlib import Path
import tempfile
import unittest

from cote3mon.audit_store import AuditStore


class AuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state_path = Path(self.directory.name) / "state.json"
        self.store = AuditStore(self.state_path)
        self.store.register_model(b"model-v1")

    def tearDown(self):
        self.directory.cleanup()

    def make_records(self):
        records = []
        for index in range(3):
            alert = {"window": index, "score": index / 10, "detector": "iforest"}
            records.append({"alert": alert, "receipt": self.store.append(alert)})
        return records

    def test_valid_chain(self):
        self.assertTrue(self.store.verify_chain(self.make_records()))

    def test_modified_alert_fails(self):
        records = self.make_records()
        records[1]["alert"]["score"] = 99
        self.assertFalse(self.store.verify_chain(records))

    def test_deleted_suffix_fails_against_current_head(self):
        records = self.make_records()
        self.assertFalse(self.store.verify_chain(records[:-1]))

    def test_reordered_records_fail(self):
        records = self.make_records()
        records[0], records[1] = records[1], records[0]
        self.assertFalse(self.store.verify_chain(records))

    def test_model_change_after_alert_fails(self):
        self.make_records()
        with self.assertRaises(ValueError):
            self.store.register_model(b"different-model")


if __name__ == "__main__":
    unittest.main()

