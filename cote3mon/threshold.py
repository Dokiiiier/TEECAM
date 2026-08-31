"""Interpretable percentile baseline calibrated on benign validation runs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping, Sequence

from .features import FEATURE_NAMES, percentile


@dataclass
class PercentileModel:
    features: list[str]
    centres: list[float]
    scales: list[float]
    threshold: float

    @classmethod
    def fit(
        cls,
        training_rows: Sequence[Mapping],
        validation_rows: Sequence[Mapping],
        false_positive_rate: float = 0.01,
        features: Sequence[str] = FEATURE_NAMES,
    ) -> "PercentileModel":
        if not training_rows or not validation_rows:
            raise ValueError("training and validation rows are required")
        if not 0.0 < false_positive_rate < 1.0:
            raise ValueError("false_positive_rate must be between zero and one")
        centres: list[float] = []
        scales: list[float] = []
        for feature in features:
            values = [float(row[feature]) for row in training_rows]
            centre = percentile(values, 0.5)
            low = percentile(values, 0.01)
            high = percentile(values, 0.99)
            centres.append(centre)
            scales.append(max(centre - low, high - centre, 1e-9))
        provisional = cls(list(features), centres, scales, 0.0)
        validation_scores = [provisional.score(row) for row in validation_rows]
        provisional.threshold = percentile(validation_scores, 1.0 - false_positive_rate)
        return provisional

    def score(self, row: Mapping) -> float:
        return max(
            abs(float(row[feature]) - centre) / scale
            for feature, centre, scale in zip(self.features, self.centres, self.scales)
        )

    def is_anomaly(self, row: Mapping) -> bool:
        return self.score(row) > self.threshold

    def to_dict(self) -> dict:
        return {
            "schema": "cote3-mon-percentile-v1",
            "features": self.features,
            "centres": self.centres,
            "scales": self.scales,
            "threshold": self.threshold,
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "PercentileModel":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema") != "cote3-mon-percentile-v1":
            raise ValueError("unsupported percentile model schema")
        return cls(data["features"], data["centres"], data["scales"], data["threshold"])

