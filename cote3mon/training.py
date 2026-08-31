"""Run-level splitting and export of an Isolation Forest for guest inference."""

from __future__ import annotations

import json
from pathlib import Path
import random
from typing import Any, Mapping, Sequence

from .features import FEATURE_NAMES, percentile


def split_benign_runs(
    rows: Sequence[Mapping], seed: int = 42
) -> tuple[list[Mapping], list[Mapping], list[Mapping]]:
    benign = [row for row in rows if not int(row["is_attack"])]
    run_ids = sorted({str(row["run_id"]) for row in benign})
    if len(run_ids) < 5:
        raise ValueError("at least five benign runs are required for run-level splitting")
    random.Random(seed).shuffle(run_ids)
    train_end = max(1, int(len(run_ids) * 0.6))
    validation_end = max(train_end + 1, int(len(run_ids) * 0.8))
    train_ids = set(run_ids[:train_end])
    validation_ids = set(run_ids[train_end:validation_end])
    test_ids = set(run_ids[validation_end:])
    return (
        [row for row in benign if str(row["run_id"]) in train_ids],
        [row for row in benign if str(row["run_id"]) in validation_ids],
        [row for row in benign if str(row["run_id"]) in test_ids],
    )


def split_benign_runs_stratified(
    rows: Sequence[Mapping],
    seed: int = 42,
    scenarios: Sequence[str] | None = None,
) -> tuple[list[Mapping], list[Mapping], list[Mapping]]:
    """Split complete benign runs within each scenario using a 60/20/20 ratio.

    Stage 4 has several legitimate workload shapes.  Stratifying by scenario
    ensures that every split contains steady, bursty, and large-value runs,
    while retaining the no-leakage guarantee of the original run-level split.
    """
    benign = [row for row in rows if not int(row["is_attack"])]
    observed = {str(row["scenario"]) for row in benign}
    expected = set(scenarios) if scenarios is not None else observed
    if observed != expected:
        raise ValueError(
            f"benign scenario coverage mismatch: expected {sorted(expected)}, "
            f"observed {sorted(observed)}"
        )

    train_ids: set[str] = set()
    validation_ids: set[str] = set()
    test_ids: set[str] = set()
    for scenario in sorted(expected):
        run_ids = sorted(
            {
                str(row["run_id"])
                for row in benign
                if str(row["scenario"]) == scenario
            }
        )
        if len(run_ids) < 5:
            raise ValueError(
                f"at least five benign runs are required for scenario {scenario!r}"
            )
        random.Random(f"{seed}:{scenario}").shuffle(run_ids)
        train_end = max(1, int(len(run_ids) * 0.6))
        validation_end = max(train_end + 1, int(len(run_ids) * 0.8))
        if validation_end >= len(run_ids):
            raise ValueError(f"scenario {scenario!r} has no test run after splitting")
        train_ids.update(run_ids[:train_end])
        validation_ids.update(run_ids[train_end:validation_end])
        test_ids.update(run_ids[validation_end:])

    return (
        [row for row in benign if str(row["run_id"]) in train_ids],
        [row for row in benign if str(row["run_id"]) in validation_ids],
        [row for row in benign if str(row["run_id"]) in test_ids],
    )


def train_and_export(
    training_rows: Sequence[Mapping],
    validation_rows: Sequence[Mapping],
    output_path: str | Path,
    false_positive_rate: float = 0.01,
    seed: int = 42,
    features: Sequence[str] = FEATURE_NAMES,
) -> dict:
    forest = fit_isolation_forest(training_rows, seed=seed, features=features)
    return export_isolation_forest(
        forest,
        validation_rows,
        output_path,
        false_positive_rate=false_positive_rate,
        seed=seed,
        features=features,
    )


def fit_isolation_forest(
    training_rows: Sequence[Mapping],
    seed: int = 42,
    features: Sequence[str] = FEATURE_NAMES,
) -> Any:
    """Fit scikit-learn's forest while keeping export and parity on one estimator."""
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise RuntimeError("install the 'ml' optional dependency to train the model") from exc

    x_train = [[float(row[name]) for name in features] for row in training_rows]
    if not x_train:
        raise ValueError("training rows are required")
    forest = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination="auto",
        random_state=seed,
        n_jobs=-1,
    )
    forest.fit(x_train)
    return forest


def export_isolation_forest(
    forest: Any,
    validation_rows: Sequence[Mapping],
    output_path: str | Path,
    false_positive_rate: float = 0.01,
    seed: int = 42,
    features: Sequence[str] = FEATURE_NAMES,
) -> dict:
    """Export a fitted forest and calibrate its alert threshold on benign validation runs."""
    if not 0.0 < false_positive_rate < 1.0:
        raise ValueError("false_positive_rate must be between zero and one")
    x_validation = [[float(row[name]) for name in features] for row in validation_rows]
    if not x_validation:
        raise ValueError("validation rows are required")
    validation_scores = [-float(score) for score in forest.score_samples(x_validation)]
    model: dict = {
        "schema": "cote3-mon-iforest-v1",
        "features": list(features),
        "max_samples": int(forest.max_samples_),
        "threshold": percentile(validation_scores, 1.0 - false_positive_rate),
        "seed": seed,
        "trees": [],
    }
    for estimator, feature_map in zip(forest.estimators_, forest.estimators_features_):
        tree = estimator.tree_
        depths = [0] * tree.node_count
        stack = [(0, 0)]
        while stack:
            node, depth = stack.pop()
            depths[node] = depth
            if tree.children_left[node] != -1:
                stack.append((int(tree.children_left[node]), depth + 1))
                stack.append((int(tree.children_right[node]), depth + 1))
        model["trees"].append(
            {
                "left": [int(value) for value in tree.children_left],
                "right": [int(value) for value in tree.children_right],
                "feature": [int(value) for value in tree.feature],
                "threshold": [float(value) for value in tree.threshold],
                "samples": [int(value) for value in tree.n_node_samples],
                "depth": depths,
                "feature_map": [int(value) for value in feature_map],
            }
        )
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(model, separators=(",", ":")), encoding="utf-8")
    return model
