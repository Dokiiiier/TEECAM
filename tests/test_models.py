import tempfile
from pathlib import Path
import unittest

from cote3mon.features import FEATURE_NAMES
from cote3mon.iforest_runtime import IsolationForestRuntime, average_path_length
from cote3mon.threshold import PercentileModel
from cote3mon.training import split_benign_runs, split_benign_runs_stratified


def row(value, run_id="run-0", attack=0, scenario="test"):
    result = {name: float(value) for name in FEATURE_NAMES}
    result.update(run_id=run_id, scenario=scenario, is_attack=attack, window_start_ns=0)
    return result


class ModelTests(unittest.TestCase):
    def test_average_path_length_boundaries(self):
        self.assertEqual(average_path_length(1), 0)
        self.assertEqual(average_path_length(2), 1)
        self.assertGreater(average_path_length(10), 1)

    def test_dependency_free_tree_traversal(self):
        model = {
            "schema": "cote3-mon-iforest-v1",
            "features": ["request_rate"],
            "max_samples": 4,
            "threshold": 0.6,
            "trees": [
                {
                    "left": [1, -1, -1],
                    "right": [2, -1, -1],
                    "feature": [0, -2, -2],
                    "threshold": [5.0, -2.0, -2.0],
                    "samples": [4, 3, 1],
                    "depth": [0, 1, 1],
                    "feature_map": [0],
                }
            ],
        }
        runtime = IsolationForestRuntime(model)
        self.assertGreater(runtime.score({"request_rate": 10}), runtime.score({"request_rate": 1}))

    def test_percentile_model_round_trip(self):
        training = [row(value) for value in range(20)]
        validation = [row(value) for value in range(5, 15)]
        model = PercentileModel.fit(training, validation)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            model.save(path)
            loaded = PercentileModel.load(path)
        self.assertEqual(model.to_dict(), loaded.to_dict())
        self.assertGreater(loaded.score(row(100)), loaded.score(row(10)))

    def test_split_is_by_whole_run(self):
        rows = [row(value, f"run-{run}") for run in range(6) for value in range(2)]
        training, validation, testing = split_benign_runs(rows)
        groups = [{item["run_id"] for item in split} for split in (training, validation, testing)]
        self.assertTrue(groups[0].isdisjoint(groups[1]))
        self.assertTrue(groups[0].isdisjoint(groups[2]))
        self.assertTrue(groups[1].isdisjoint(groups[2]))

    def test_stratified_split_covers_every_benign_scenario_without_leakage(self):
        scenarios = ["steady", "bursty", "large_value"]
        rows = [
            row(value, f"{scenario}-{run:02d}", scenario=scenario)
            for scenario in scenarios
            for run in range(10)
            for value in range(2)
        ]
        training, validation, testing = split_benign_runs_stratified(
            rows, seed=42, scenarios=scenarios
        )
        split_groups = [
            {item["run_id"] for item in split}
            for split in (training, validation, testing)
        ]
        self.assertEqual([len(group) for group in split_groups], [18, 6, 6])
        self.assertTrue(split_groups[0].isdisjoint(split_groups[1]))
        self.assertTrue(split_groups[0].isdisjoint(split_groups[2]))
        self.assertTrue(split_groups[1].isdisjoint(split_groups[2]))
        for split in (training, validation, testing):
            self.assertEqual({item["scenario"] for item in split}, set(scenarios))


if __name__ == "__main__":
    unittest.main()
