import unittest

from cote3mon.evaluation import (
    attack_detection_delays,
    average_precision,
    bootstrap_run_metric_interval,
    classification_metrics,
)


class EvaluationTests(unittest.TestCase):
    def test_perfect_classifier(self):
        labels = [0, 0, 1, 1]
        scores = [0.1, 0.2, 0.8, 0.9]
        metrics = classification_metrics(labels, scores, 0.5)
        self.assertEqual(metrics["precision"], 1)
        self.assertEqual(metrics["recall"], 1)
        self.assertEqual(metrics["f1"], 1)
        self.assertEqual(metrics["auprc"], 1)

    def test_run_bootstrap_and_detection_delay(self):
        rows = [
            {"run_id": "benign-1", "is_attack": 0, "window_start_ns": 0},
            {"run_id": "benign-1", "is_attack": 0, "window_start_ns": 5_000_000_000},
            {"run_id": "attack-1", "is_attack": 1, "window_start_ns": 0},
            {"run_id": "attack-1", "is_attack": 1, "window_start_ns": 5_000_000_000},
        ]
        scores = [0.1, 0.2, 0.4, 0.9]
        low, high = bootstrap_run_metric_interval(
            rows, scores, 0.5, "f1", iterations=100, seed=42
        )
        self.assertGreaterEqual(low, 0)
        self.assertLessEqual(high, 1)
        self.assertEqual(
            attack_detection_delays(rows, scores, 0.5), {"attack-1": 5.0}
        )


if __name__ == "__main__":
    unittest.main()
