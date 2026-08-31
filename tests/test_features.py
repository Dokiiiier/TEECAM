import unittest

from cote3mon.features import (
    ENHANCED_FEATURE_NAMES,
    FEATURE_NAMES,
    aggregate_events,
    percentile,
)


class FeatureTests(unittest.TestCase):
    def test_percentile_interpolates(self):
        self.assertEqual(percentile([0, 10], 0.5), 5)

    def test_aggregate_request_and_resource_events(self):
        events = [
            {
                "event_type": "request",
                "ts_unix_ns": 1_000_000_000,
                "run_id": "run-1",
                "scenario": "steady",
                "is_attack": False,
                "operation": "PUT",
                "result": "OK",
                "latency_us": 10,
                "input_bytes": 100,
                "key_fingerprint": "key-a",
                "request_fingerprint": "request-a",
            },
            {
                "event_type": "request",
                "ts_unix_ns": 2_000_000_000,
                "run_id": "run-1",
                "scenario": "steady",
                "is_attack": False,
                "operation": "GET",
                "result": "NOT_FOUND",
                "latency_us": 30,
                "input_bytes": 10,
                "key_fingerprint": "key-a",
                "request_fingerprint": "request-b",
            },
            {
                "event_type": "resource",
                "ts_unix_ns": 2_500_000_000,
                "run_id": "run-1",
                "cpu_percent": 12.5,
                "rss_kb": 256,
            },
        ]
        rows = aggregate_events(events, 5)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["request_rate"], 0.4)
        self.assertEqual(row["put_ratio"], 0.5)
        self.assertEqual(row["get_ratio"], 0.5)
        self.assertEqual(row["error_ratio"], 0.5)
        self.assertEqual(row["latency_mean_us"], 20)
        self.assertEqual(row["input_max_bytes"], 100)
        self.assertEqual(row["cpu_percent_mean"], 12.5)
        self.assertEqual(row["key_reuse_ratio"], 0.5)
        self.assertEqual(row["request_reuse_ratio"], 0.0)
        self.assertEqual(row["operation_transition_ratio"], 1.0)
        self.assertGreater(row["idle_mean_us"], 0.0)
        for name in FEATURE_NAMES:
            self.assertIn(name, row)
        for name in ENHANCED_FEATURE_NAMES:
            self.assertIn(name, row)

    def test_replay_and_flood_signals_are_derived_without_raw_objects(self):
        events = []
        for index in range(4):
            events.append(
                {
                    "event_type": "request",
                    "ts_unix_ns": 1_000_000_000 + index * 2_000_000,
                    "run_id": "replay-0",
                    "scenario": "replay",
                    "is_attack": True,
                    "operation": "PUT",
                    "result": "OK",
                    "latency_us": 1_000,
                    "input_bytes": 140,
                    "key_fingerprint": "same-key",
                    "request_fingerprint": "same-request",
                }
            )
        row = aggregate_events(events, 5)[0]
        self.assertEqual(row["key_reuse_ratio"], 0.75)
        self.assertEqual(row["request_reuse_ratio"], 0.75)
        self.assertEqual(row["operation_transition_ratio"], 0.0)
        self.assertEqual(row["idle_mean_us"], 1_000.0)


if __name__ == "__main__":
    unittest.main()
