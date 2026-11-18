"""Binary detection metrics; per-category recall uses each row's ground truth."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from agentsentinel.corpus import CATEGORIES, CorpusRow


@dataclass(frozen=True)
class Metrics:
    rows: int
    malicious: int
    benign: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    fpr: float
    category_recall: dict[str, float]
    category_support: dict[str, int]


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def evaluate(
    rows: Sequence[CorpusRow], predict: Callable[[dict[str, object]], bool]
) -> Metrics:
    tp = fp = tn = fn = 0
    category_hits = dict.fromkeys(CATEGORIES, 0)
    category_support = dict.fromkeys(CATEGORIES, 0)
    for row in rows:
        flagged = predict(row.trace)
        malicious = row.label == "malicious"
        tp += int(malicious and flagged)
        fp += int(not malicious and flagged)
        tn += int(not malicious and not flagged)
        fn += int(malicious and not flagged)
        if malicious:
            category_support[row.category] += 1
            category_hits[row.category] += int(flagged)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return Metrics(
        len(rows),
        tp + fn,
        tn + fp,
        tp,
        fp,
        tn,
        fn,
        precision,
        recall,
        _ratio(2 * precision * recall, precision + recall),
        _ratio(fp, fp + tn),
        {
            category: _ratio(category_hits[category], category_support[category])
            for category in CATEGORIES
        },
        category_support,
    )


def format_metrics(metrics: Metrics) -> str:
    lines = [
        f"Rows: {metrics.rows} "
        f"(malicious={metrics.malicious}, benign={metrics.benign})",
        f"Precision: {metrics.precision:.4f}",
        f"Recall: {metrics.recall:.4f}",
        f"F1: {metrics.f1:.4f}",
        f"FPR: {metrics.fpr:.4f}",
        f"TP={metrics.true_positive} FP={metrics.false_positive} "
        f"TN={metrics.true_negative} FN={metrics.false_negative}",
    ]
    lines.extend(
        f"Recall[{category}]: {metrics.category_recall[category]:.4f} "
        f"(n={metrics.category_support[category]})"
        for category in CATEGORIES
    )
    return "\n".join(lines)
