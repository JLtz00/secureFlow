"""Statistical helpers for benchmark reporting."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from analyzer.metrics import ConfusionMatrix


@dataclass(frozen=True)
class MetricCI:
    value: float
    low: float
    high: float

    def format(self) -> str:
        return f"{self.value:.3f} [{self.low:.3f}, {self.high:.3f}]"


def confusion_from_labels(pairs: list[tuple[str, str]]) -> ConfusionMatrix:
    cm = ConfusionMatrix()
    for prediction, truth in pairs:
        if prediction == "VULNERABLE" and truth == "VULNERABLE":
            cm.tp += 1
        elif prediction == "VULNERABLE" and truth == "SAFE":
            cm.fp += 1
        elif prediction == "SAFE" and truth == "SAFE":
            cm.tn += 1
        elif prediction == "SAFE" and truth == "VULNERABLE":
            cm.fn += 1
    return cm


def bootstrap_ci(
    pairs: list[tuple[str, str]],
    metric: Callable[[ConfusionMatrix], float],
    iterations: int = 1000,
    seed: int = 42,
) -> MetricCI:
    if not pairs:
        return MetricCI(0.0, 0.0, 0.0)

    rng = random.Random(seed)
    observed = metric(confusion_from_labels(pairs))
    values: list[float] = []
    n = len(pairs)
    for _ in range(iterations):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        values.append(metric(confusion_from_labels(sample)))

    values.sort()
    low = values[int(0.025 * (iterations - 1))]
    high = values[int(0.975 * (iterations - 1))]
    return MetricCI(observed, low, high)


def metric_intervals(
    pairs: list[tuple[str, str]],
    iterations: int = 1000,
    seed: int = 42,
) -> dict[str, MetricCI]:
    return {
        "precision": bootstrap_ci(pairs, lambda cm: cm.precision, iterations, seed),
        "recall": bootstrap_ci(pairs, lambda cm: cm.recall, iterations, seed + 1),
        "f1": bootstrap_ci(pairs, lambda cm: cm.f1_score, iterations, seed + 2),
        "accuracy": bootstrap_ci(pairs, lambda cm: cm.accuracy, iterations, seed + 3),
    }

