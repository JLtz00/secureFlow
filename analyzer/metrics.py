"""Detection metrics: precision, recall, F1 score, and confusion matrix."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    tp: int = 0   # true positives:  correctly detected vulnerabilities
    fp: int = 0   # false positives: clean code flagged as vulnerable
    tn: int = 0   # true negatives:  clean code correctly ignored
    fn: int = 0   # false negatives: vulnerabilities missed

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate: FP / (FP + TN)"""
        return self.fp / (self.fp + self.tn) if self.fp + self.tn > 0 else 0.0

    @property
    def fnr(self) -> float:
        """False Negative Rate: FN / (FN + TP)"""
        return self.fn / (self.fn + self.tp) if self.fn + self.tp > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"TP={self.tp}  FP={self.fp}  TN={self.tn}  FN={self.fn}\n"
            f"Precision={self.precision:.3f}  "
            f"Recall={self.recall:.3f}  "
            f"F1={self.f1_score:.3f}  "
            f"Accuracy={self.accuracy:.3f}  "
            f"FPR={self.fpr:.3f}  FNR={self.fnr:.3f}"
        )


def evaluate(
    predicted: set[str],
    actual: set[str],
    universe: set[str] | None = None,
) -> ConfusionMatrix:
    """Compare predicted vulnerability IDs against the ground truth.

    Args:
        predicted: set of identifiers flagged as vulnerable by the tool.
        actual:    ground-truth vulnerable identifiers.
        universe:  complete set of identifiers (predicted ∪ actual if omitted).
    """
    if universe is None:
        universe = predicted | actual

    tp = len(predicted & actual)
    fp = len(predicted - actual)
    fn = len(actual - predicted)
    tn = len(universe - predicted - actual)
    return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)
