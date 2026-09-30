"""Binary evaluation metrics with explicit confusion counts and score quality."""

from __future__ import annotations

from typing import Sequence

from sklearn.metrics import average_precision_score, roc_auc_score


def binary_metrics(
    truth: Sequence[int], predictions: Sequence[int], scores: Sequence[float]
) -> dict[str, object]:
    if not (len(truth) == len(predictions) == len(scores)) or not truth:
        raise ValueError("truth, predictions, and scores must have equal non-zero length")
    tp = sum(actual == 1 and predicted == 1 for actual, predicted in zip(truth, predictions))
    fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(truth, predictions))
    tn = sum(actual == 0 and predicted == 0 for actual, predicted in zip(truth, predictions))
    fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(truth, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    result: dict[str, object] = {
        "samples": len(truth), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }
    if len(set(truth)) == 2:
        result["pr_auc"] = float(average_precision_score(truth, scores))
        result["roc_auc"] = float(roc_auc_score(truth, scores))
    else:
        result["pr_auc"] = None
        result["roc_auc"] = None
    return result


def select_threshold(
    truth: Sequence[int], scores: Sequence[float], *, maximum_fpr: float = 0.01
) -> tuple[float, dict[str, object]]:
    candidates = sorted({0.05, 0.95, *(round(value, 4) for value in scores)})
    evaluated: list[tuple[bool, float, float, dict[str, object]]] = []
    for threshold in candidates:
        metrics = binary_metrics(
            truth, [int(value >= threshold) for value in scores], scores
        )
        evaluated.append((
            float(metrics["false_positive_rate"]) <= maximum_fpr,
            float(metrics["f1"]), threshold, metrics,
        ))
    feasible = [item for item in evaluated if item[0]]
    pool = feasible or evaluated
    _, _, threshold, metrics = max(
        pool,
        key=lambda item: (
            item[1], -float(item[3]["false_positive_rate"]),
            float(item[3]["recall"]), item[2],
        ),
    )
    return threshold, metrics
