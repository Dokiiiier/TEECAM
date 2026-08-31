"""Dependency-free inference for exported scikit-learn Isolation Forests."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Mapping


def average_path_length(sample_count: int) -> float:
    if sample_count <= 1:
        return 0.0
    if sample_count == 2:
        return 1.0
    return 2.0 * (math.log(sample_count - 1.0) + 0.5772156649015329) - 2.0 * (
        sample_count - 1.0
    ) / sample_count


class IsolationForestRuntime:
    def __init__(self, model: Mapping):
        if model.get("schema") != "cote3-mon-iforest-v1":
            raise ValueError("unsupported Isolation Forest model schema")
        self.model = dict(model)
        self.features = list(model["features"])
        self.threshold = float(model["threshold"])
        self.max_samples = int(model["max_samples"])
        self.trees = list(model["trees"])
        if not self.trees:
            raise ValueError("model does not contain any trees")

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForestRuntime":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def score(self, row: Mapping) -> float:
        values = [float(row[name]) for name in self.features]
        total_path = 0.0
        for tree in self.trees:
            node = 0
            while tree["left"][node] != -1:
                local_feature = tree["feature"][node]
                source_feature = tree["feature_map"][local_feature]
                node = (
                    tree["left"][node]
                    if values[source_feature] <= tree["threshold"][node]
                    else tree["right"][node]
                )
            total_path += tree["depth"][node] + average_path_length(tree["samples"][node])
        denominator = len(self.trees) * average_path_length(self.max_samples)
        return 1.0 if denominator == 0.0 else 2.0 ** (-total_path / denominator)

    def is_anomaly(self, row: Mapping) -> bool:
        return self.score(row) > self.threshold

