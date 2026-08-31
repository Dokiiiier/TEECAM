import importlib.util
import tempfile
from pathlib import Path
import unittest

from cote3mon.features import FEATURE_NAMES
from cote3mon.iforest_runtime import IsolationForestRuntime
from cote3mon.training import export_isolation_forest, fit_isolation_forest


SKLEARN_AVAILABLE = importlib.util.find_spec("sklearn") is not None


def make_row(index, run_id):
    row = {
        name: float(((index + 1) * (feature_index + 3)) % 37) / (feature_index + 1)
        for feature_index, name in enumerate(FEATURE_NAMES)
    }
    row.update(run_id=run_id, scenario="steady", is_attack=0, window_start_ns=index)
    return row


@unittest.skipUnless(SKLEARN_AVAILABLE, "scikit-learn is required for export parity")
class TrainingExportTests(unittest.TestCase):
    def test_exported_runtime_matches_fitted_sklearn_forest(self):
        training = [make_row(index, f"train-{index // 10}") for index in range(60)]
        validation = [make_row(100 + index, f"validation-{index // 10}") for index in range(20)]
        testing = [make_row(200 + index, f"test-{index // 10}") for index in range(30)]
        forest = fit_isolation_forest(training, seed=42)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "iforest.json"
            exported = export_isolation_forest(forest, validation, path, seed=42)
            runtime = IsolationForestRuntime.load(path)
        reference = [
            -float(value)
            for value in forest.score_samples(
                [[float(row[name]) for name in FEATURE_NAMES] for row in testing]
            )
        ]
        observed = [runtime.score(row) for row in testing]
        self.assertEqual(len(exported["trees"]), 100)
        self.assertLessEqual(
            max(abs(left - right) for left, right in zip(reference, observed)),
            1e-12,
        )


if __name__ == "__main__":
    unittest.main()
