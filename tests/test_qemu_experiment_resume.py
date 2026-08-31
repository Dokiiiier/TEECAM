import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run-qemu-experiments.py"
SPEC = importlib.util.spec_from_file_location("run_qemu_experiments", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class QemuExperimentResumeTests(unittest.TestCase):
    def make_passed_run(self, output: Path) -> None:
        (output / "steady-00-requests.jsonl").write_text("{}\n{}\n", encoding="utf-8")
        (output / "steady-00-resources.jsonl").write_text("{}\n", encoding="utf-8")
        (output / "steady-00-result.json").write_text(
            json.dumps(
                {
                    "status": "PASS",
                    "run_id": "steady-00",
                    "scenario": "steady",
                    "is_attack": False,
                    "seed": 42,
                    "duration_seconds": 60.0,
                    "request_events": 2,
                    "resource_events": 1,
                }
            ),
            encoding="utf-8",
        )

    def test_resume_accepts_matching_passed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.make_passed_run(output)
            self.assertTrue(
                MODULE.reusable_passed_run(output, "steady", False, 0, 60.0, 42)
            )

    def test_resume_rejects_truncated_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.make_passed_run(output)
            (output / "steady-00-requests.jsonl").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "request_events"):
                MODULE.reusable_passed_run(output, "steady", False, 0, 60.0, 42)


if __name__ == "__main__":
    unittest.main()
