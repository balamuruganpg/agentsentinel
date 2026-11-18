"""Public scanner API combining deterministic rules and learned sequence evidence."""

import math
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from agentsentinel.classifier import LogisticModel
from agentsentinel.rules import evaluate_rules
from agentsentinel.trace import normalize_trace


@dataclass(frozen=True)
class TraceReport:
    score: float
    flagged: bool
    categories: tuple[str, ...]
    signals: tuple[str, ...]


@lru_cache(maxsize=1)
def _default_model() -> LogisticModel:
    artifact = files("agentsentinel").joinpath("data/default_model.json")
    return LogisticModel.from_json(artifact.read_text(encoding="utf-8"))


class Sentinel:
    def __init__(self, threshold: float = 0.5) -> None:
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be in [0, 1]")
        self.threshold = threshold
        self._model = _default_model()

    @classmethod
    def from_model(cls, path: str | Path, threshold: float = 0.5) -> "Sentinel":
        """Use a locally trained artifact, with the same rule policy."""
        scanner = cls(threshold)
        scanner._model = LogisticModel.load(path)
        return scanner

    def scan(self, trace: dict[str, object]) -> TraceReport:
        if not isinstance(trace, dict):
            raise ValueError("trace must be a dict")
        steps = normalize_trace(trace)
        if not steps:
            return TraceReport(0.0, self.threshold <= 0.0, (), ())
        hits = evaluate_rules(steps)
        rule_score = min(1.0, sum(hit.weight for hit in hits))
        score = max(rule_score, self._model.predict_probability(steps))
        signals = {hit.signal for hit in hits}
        signals.update(self._model.positive_signals(steps))
        return TraceReport(
            score,
            score >= self.threshold,
            tuple(sorted({hit.category for hit in hits})),
            tuple(sorted(signals)),
        )
