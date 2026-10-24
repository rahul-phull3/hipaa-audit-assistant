"""Scores for predicted statuses against known ones.

Rows of the confusion matrix are the true status, columns the predicted one. ``error`` is a column only: a control the backend
could not assess is a miss for its true status, never a correct answer.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

LABELS = ("met", "partial", "gap")
COLUMNS = (*LABELS, "error")
ORDINAL = {"gap": 0, "partial": 1, "met": 2}  # how much support a status claims; used for the size of an error

Matrix = dict[str, dict[str, int]]


def empty_matrix() -> Matrix:
    return {truth: dict.fromkeys(COLUMNS, 0) for truth in LABELS}


def confusion(pairs: Iterable[tuple[str, str]]) -> Matrix:
    matrix = empty_matrix()
    for truth, predicted in pairs:
        matrix[truth][predicted if predicted in COLUMNS else "error"] += 1
    return matrix


def merge(matrices: Iterable[Matrix]) -> Matrix:
    total = empty_matrix()
    for matrix in matrices:
        for truth in LABELS:
            for column in COLUMNS:
                total[truth][column] += matrix[truth][column]
    return total


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def class_metrics(matrix: Matrix) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for label in LABELS:
        true_positive = matrix[label][label]
        support = sum(matrix[label].values())
        predicted = sum(matrix[truth][label] for truth in LABELS)
        precision = _ratio(true_positive, predicted)
        recall = _ratio(true_positive, support)
        if support == 0:
            f1 = None  # the label does not occur, so it says nothing about the backend
        elif not precision or not recall:
            f1 = 0.0
        else:
            f1 = 2 * precision * recall / (precision + recall)
        result[label] = {"precision": precision, "recall": recall, "f1": f1, "support": support}
    return result


def summarize(matrix: Matrix) -> dict[str, Any]:
    classes = class_metrics(matrix)
    total = sum(sum(row.values()) for row in matrix.values())
    correct = sum(matrix[label][label] for label in LABELS)
    scored = [(t, p, n) for t in LABELS for p in LABELS if (n := matrix[t][p])]
    answered = sum(n for _t, _p, n in scored)
    f1s = [m["f1"] for m in classes.values() if m["f1"] is not None]
    gaps = sum(matrix["gap"].values())
    mets = sum(matrix["met"].values())
    return {
        "total": total,
        "accuracy": _ratio(correct, total),
        "macro_f1": sum(f1s) / len(f1s) if f1s else None,
        "mean_ordinal_error": _ratio(sum(abs(ORDINAL[t] - ORDINAL[p]) * n for t, p, n in scored), answered),
        "errors": sum(matrix[t]["error"] for t in LABELS),
        "classes": classes,
        # The mistakes that matter most when someone relies on the result: reporting support that is not there ...
        "gap_called_met": {"count": matrix["gap"]["met"], "of": gaps, "rate": _ratio(matrix["gap"]["met"], gaps)},
        "gap_called_met_or_partial": {
            "count": matrix["gap"]["met"] + matrix["gap"]["partial"],
            "of": gaps,
            "rate": _ratio(matrix["gap"]["met"] + matrix["gap"]["partial"], gaps),
        },
        # ... and, less dangerous but noisy, missing support that is there.
        "met_called_gap": {"count": matrix["met"]["gap"], "of": mets, "rate": _ratio(matrix["met"]["gap"], mets)},
    }
