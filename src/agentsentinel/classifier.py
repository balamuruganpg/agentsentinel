"""Deterministic stdlib logistic regression on standardized binary features."""

import json
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from agentsentinel.corpus import CorpusRow
from agentsentinel.rules import (
    _sensitive_read,
    is_destructive,
    is_escalation,
    is_read,
    is_send,
)
from agentsentinel.trace import Step, normalize_trace

ITERATIONS = 600
LEARNING_RATE = 0.15
L2 = 0.02
SEED = 0


def _feature_tool(step: Step) -> str:
    """Stored tool name. A benign ``exec`` is scored as ``shell``.

    ``tool:exec`` was fit on destructive and privileged commands, so an
    innocent ``exec`` crosses 0.5 by itself. The model is not refit. This is
    a predict-time feature interaction: the stored name stays ``exec``, and
    a risky exec (sensitive read, destruction, or high-privilege escalation)
    keeps ``tool:exec``. ``functions.exec`` is a different stored string.
    """
    if step.tool != "exec":
        return step.tool
    if _sensitive_read(step) or is_destructive(step) or is_escalation(step):
        return step.tool
    return "shell"


def _classifier_steps(steps: Sequence[Step]) -> Sequence[Step]:
    """Hide one step that sits between ``file_write`` and ``http_post``.

    The bundled model learned that pair only as an adjacent bigram. At
    prediction time a single intervening step is left out of the feature
    view, so the trained bigram still applies. Training and
    ``extract_features`` are unchanged. Two intervening steps are not bridged.
    """
    names = [_feature_tool(step) for step in steps]
    hidden = {
        index + 1
        for index in range(len(names) - 2)
        if names[index] == "file_write" and names[index + 2] == "http_post"
    }
    if not hidden:
        return steps
    return [step for index, step in enumerate(steps) if index not in hidden]


def extract_features(steps: Sequence[Step]) -> frozenset[str]:
    """Binary tool unigrams/bigrams, rule-family presence, and one length bucket."""
    names = [_feature_tool(step) for step in steps]
    features = {f"tool:{name}" for name in names}
    features.update(
        "bigram:" + json.dumps([first, second], separators=(",", ":"))
        for first, second in zip(names, names[1:], strict=False)
    )
    for family, predicate in (
        ("read", is_read),
        ("send", is_send),
        ("destructive", is_destructive),
        ("escalation", is_escalation),
    ):
        if any(predicate(step) for step in steps):
            features.add(f"family:{family}")
    length = len(steps)
    bucket = (
        str(length)
        if length < 2
        else "2-3"
        if length < 4
        else "4-7"
        if length < 8
        else "8+"
    )
    features.add(f"length:{bucket}")
    return frozenset(features)


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-value))
    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


@dataclass(frozen=True)
class LogisticModel:
    vocabulary: tuple[str, ...]
    weights: tuple[float, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    bias: float
    threshold: float = 0.5
    training_rows: int = 0

    def predict_probability(self, steps: Sequence[Step]) -> float:
        features = extract_features(_classifier_steps(steps))
        logit = self.bias + sum(
            weight * ((float(name in features) - mean) / scale)
            for name, weight, mean, scale in zip(
                self.vocabulary, self.weights, self.means, self.scales, strict=True
            )
        )
        return min(1.0, max(0.0, _sigmoid(logit)))

    def positive_signals(self, steps: Sequence[Step]) -> tuple[str, ...]:
        """Present features with positive standardized contributions, if positive."""
        if self.predict_probability(steps) < self.threshold:
            return ()
        viewed = extract_features(_classifier_steps(steps))
        return tuple(
            f"feature:{name}"
            for name, weight, mean in zip(
                self.vocabulary, self.weights, self.means, strict=True
            )
            if name in viewed and weight > 0.0 and mean < 1.0
        )

    def to_json(self) -> str:
        artifact: dict[str, object] = {
            "format_version": 1,
            "algorithm": "standardized-binary-logistic-regression",
            "vocabulary": self.vocabulary,
            "weights": self.weights,
            "means": self.means,
            "scales": self.scales,
            "bias": self.bias,
            "threshold": self.threshold,
            "training": {
                "rows": self.training_rows,
                "iterations": ITERATIONS,
                "learning_rate": LEARNING_RATE,
                "l2": L2,
                "seed": SEED,
            },
        }
        return json.dumps(artifact, sort_keys=True, indent=2, allow_nan=False) + "\n"

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_json(cls, text: str) -> "LogisticModel":
        value: object = json.loads(text)
        if not isinstance(value, dict) or value.get("format_version") != 1:
            raise ValueError("model must be an object with format_version 1")
        if value.get("algorithm") != "standardized-binary-logistic-regression":
            raise ValueError("unsupported model algorithm")
        vocabulary = value.get("vocabulary")
        if (
            not isinstance(vocabulary, list)
            or not all(isinstance(name, str) for name in vocabulary)
            or len(set(vocabulary)) != len(vocabulary)
        ):
            raise ValueError("model vocabulary must contain unique strings")
        # Rebuild typed tuples rather than returning untyped JSON arrays.
        names = tuple(name for name in vocabulary if isinstance(name, str))

        def numbers(key: str) -> tuple[float, ...]:
            raw = value.get(key)
            if not isinstance(raw, list) or len(raw) != len(names):
                raise ValueError(f"model {key} length must match vocabulary")
            result: list[float] = []
            for number in raw:
                if (
                    isinstance(number, bool)
                    or not isinstance(number, (int, float))
                    or abs(number) > 1e6
                    or not math.isfinite(number)
                ):
                    raise ValueError(f"model {key} must contain finite numbers <= 1e6")
                result.append(float(number))
            return tuple(result)

        weights, means, scales = numbers("weights"), numbers("means"), numbers("scales")
        if any(not 0.0 <= mean <= 1.0 for mean in means):
            raise ValueError("model means must be in [0, 1]")
        if any(scale < 1e-12 for scale in scales):
            raise ValueError("model scales must be >= 1e-12")
        bias = value.get("bias")
        threshold = value.get("threshold")
        if (
            isinstance(bias, bool)
            or not isinstance(bias, (float, int))
            or abs(bias) > 1e6
            or not math.isfinite(bias)
        ):
            raise ValueError("model bias must be finite and <= 1e6 in magnitude")
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (float, int))
            or not 0.0 <= threshold <= 1.0
        ):
            raise ValueError("model threshold must be in [0, 1]")
        training = value.get("training")
        rows = training.get("rows", 0) if isinstance(training, dict) else 0
        if isinstance(rows, bool) or not isinstance(rows, int) or rows < 0:
            raise ValueError("model training rows must be a nonnegative integer")
        return cls(names, weights, means, scales, float(bias), float(threshold), rows)

    @classmethod
    def load(cls, path: str | Path) -> "LogisticModel":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


def train(rows: Sequence[CorpusRow]) -> LogisticModel:
    """Train in canonical row order, so input permutations also reproduce bytes."""
    if not rows or {row.label for row in rows} != {"malicious", "benign"}:
        raise ValueError("training requires at least one malicious and one benign row")
    samples = sorted(
        (
            tuple(sorted(extract_features(normalize_trace(row.trace)))),
            float(row.label == "malicious"),
        )
        for row in rows
    )
    vocabulary = tuple(sorted({name for features, _ in samples for name in features}))
    count = len(samples)
    means = tuple(
        sum(name in features for features, _ in samples) / count for name in vocabulary
    )
    scales = tuple(math.sqrt(mean * (1.0 - mean)) or 1.0 for mean in means)
    matrix = [
        tuple(
            (float(name in features) - mean) / scale
            for name, mean, scale in zip(vocabulary, means, scales, strict=True)
        )
        for features, _ in samples
    ]
    rng = random.Random(SEED)
    weights = [rng.uniform(-0.01, 0.01) for _ in vocabulary]
    bias = 0.0
    for _ in range(ITERATIONS):
        gradient = [0.0] * len(vocabulary)
        bias_gradient = 0.0
        for vector, (_, label) in zip(matrix, samples, strict=True):
            error = (
                _sigmoid(
                    bias + sum(w * x for w, x in zip(weights, vector, strict=True))
                )
                - label
            )
            bias_gradient += error
            for index, feature in enumerate(vector):
                gradient[index] += error * feature
        bias -= LEARNING_RATE * bias_gradient / count
        for index, weight in enumerate(weights):
            weights[index] -= LEARNING_RATE * (gradient[index] / count + L2 * weight)
    return LogisticModel(
        vocabulary, tuple(weights), means, scales, bias, training_rows=count
    )
