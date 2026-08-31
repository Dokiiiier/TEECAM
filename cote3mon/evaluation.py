"""Dependency-free detection metrics and deterministic bootstrap intervals."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Iterable, Mapping, Sequence


def classification_metrics(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict:
    if len(labels) != len(scores) or not labels:
        raise ValueError("labels and scores must be non-empty and have equal length")
    predictions = [int(score > threshold) for score in scores]
    tp = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    tn = sum(label == 0 and prediction == 0 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    benign_windows = tn + fp
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / benign_windows if benign_windows else 0.0,
        "auprc": average_precision(labels, scores),
    }


def average_precision(labels: Sequence[int], scores: Sequence[float]) -> float:
    positives = sum(labels)
    if positives == 0:
        return 0.0
    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    true_positives = 0
    area = 0.0
    previous_recall = 0.0
    for rank, (_, label) in enumerate(ranked, 1):
        if label:
            true_positives += 1
            recall = true_positives / positives
            precision = true_positives / rank
            area += (recall - previous_recall) * precision
            previous_recall = recall
    return area


def bootstrap_metric_interval(
    labels: Sequence[int],
    scores: Sequence[float],
    threshold: float,
    metric: str,
    iterations: int = 1000,
    seed: int = 42,
) -> tuple[float, float]:
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(iterations):
        indices = [rng.randrange(len(labels)) for _ in labels]
        sampled_labels = [labels[index] for index in indices]
        if not any(sampled_labels) or all(sampled_labels):
            continue
        sampled_scores = [scores[index] for index in indices]
        values.append(float(classification_metrics(sampled_labels, sampled_scores, threshold)[metric]))
    if not values:
        return (0.0, 0.0)
    values.sort()
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]


def bootstrap_run_metric_interval(
    rows: Sequence[Mapping],
    scores: Sequence[float],
    threshold: float,
    metric: str,
    iterations: int = 1000,
    seed: int = 42,
) -> tuple[float, float]:
    """Bootstrap complete runs so neighbouring windows are never sampled independently."""
    if len(rows) != len(scores) or not rows:
        raise ValueError("rows and scores must be non-empty and have equal length")
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        groups[str(row["run_id"])].append(index)
    run_ids = sorted(groups)
    if len(run_ids) < 2:
        raise ValueError("at least two runs are required for run-level bootstrap")
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(iterations):
        sampled_runs = [run_ids[rng.randrange(len(run_ids))] for _ in run_ids]
        indices = [index for run_id in sampled_runs for index in groups[run_id]]
        labels = [int(rows[index]["is_attack"]) for index in indices]
        if not any(labels) or all(labels):
            continue
        sampled_scores = [float(scores[index]) for index in indices]
        values.append(float(classification_metrics(labels, sampled_scores, threshold)[metric]))
    if not values:
        return (0.0, 0.0)
    values.sort()
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]


def attack_detection_delays(
    rows: Sequence[Mapping], scores: Sequence[float], threshold: float
) -> dict[str, float | None]:
    """Return seconds from the first retained attack window to the first alert per run."""
    if len(rows) != len(scores):
        raise ValueError("rows and scores must have equal length")
    grouped: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for row, score in zip(rows, scores):
        if int(row["is_attack"]):
            grouped[str(row["run_id"])].append((int(row["window_start_ns"]), float(score)))
    delays: dict[str, float | None] = {}
    for run_id, values in sorted(grouped.items()):
        ordered = sorted(values)
        first_timestamp = ordered[0][0]
        first_alert = next((timestamp for timestamp, score in ordered if score > threshold), None)
        delays[run_id] = None if first_alert is None else (first_alert - first_timestamp) / 1_000_000_000
    return delays
