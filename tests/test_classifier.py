"""Feature and combination tests for the learned sequence component."""

import json
import math
from pathlib import Path

import pytest

from agentsentinel import Sentinel
from agentsentinel.classifier import LogisticModel, extract_features, train
from agentsentinel.corpus import CorpusRow
from agentsentinel.trace import normalize_trace


def trace(*tools: str) -> dict[str, object]:
    return {"steps": [{"tool": tool} for tool in tools]}


def test_binary_sequence_features_and_order() -> None:
    forward = extract_features(normalize_trace(trace("read_file", "upload", "upload")))
    reverse = extract_features(normalize_trace(trace("upload", "read_file")))
    assert {
        "tool:read_file",
        "tool:upload",
        "family:read",
        "family:send",
        "length:2-3",
    } <= forward
    assert 'bigram:["read_file","upload"]' in forward
    assert 'bigram:["upload","read_file"]' not in forward
    assert 'bigram:["upload","read_file"]' in reverse


def test_vocabulary_is_training_only_and_constant_features_are_finite() -> None:
    rows = (
        CorpusRow(trace("safe"), "benign", "benign"),
        CorpusRow(trace("danger"), "malicious", "destruction"),
    )
    model = train(rows)
    assert "tool:unseen" not in model.vocabulary
    for tools in [(), ("safe",), ("danger",), ("unseen",)]:
        probability = model.predict_probability(normalize_trace(trace(*tools)))
        assert 0 <= probability <= 1
    assert model.predict_probability(normalize_trace(trace("safe"))) < 0.5
    assert model.predict_probability(normalize_trace(trace("danger"))) > 0.5
    assert LogisticModel.from_json(model.to_json()) == model


def test_empty_and_single_class_training_are_rejected() -> None:
    with pytest.raises(ValueError):
        train(())
    with pytest.raises(ValueError):
        train((CorpusRow(trace("safe"), "benign", "benign"),))


@pytest.mark.parametrize("bias", [-1000.0, 1000.0])
def test_stable_sigmoid(bias: float) -> None:
    model = LogisticModel((), (), (), (), bias)
    assert 0 <= model.predict_probability(()) <= 1


def test_scanner_combines_by_max_and_classifier_abstains_on_categories() -> None:
    scanner = Sentinel()
    scanner._model = LogisticModel((), (), (), (), -1000.0)
    destructive: dict[str, object] = {
        "steps": [{"tool": "rm", "args": {"path": "/etc"}}]
    }
    assert scanner.scan(destructive).score == pytest.approx(0.95)
    scanner._model = LogisticModel((), (), (), (), 2.0)
    report = scanner.scan(trace("unknown_tool"))
    assert report.score == pytest.approx(1 / (1 + math.exp(-2.0)))
    assert report.flagged and report.categories == ()
    saturated = scanner.scan(
        {"steps": [{"tool": "grant_role"}, {"tool": "rm", "args": {"path": "/etc"}}]}
    )
    assert saturated.score == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("weights", [float("nan")]),
        ("scales", [0]),
        ("means", [2]),
        ("bias", 10**400),
        ("threshold", 1.1),
        ("vocabulary", ["a", "a"]),
    ],
)
def test_invalid_models_are_rejected(field: str, value: object) -> None:
    model = LogisticModel(("a",), (1,), (0,), (1,), 0)
    artifact = json.loads(model.to_json())
    artifact[field] = value
    with pytest.raises(ValueError):
        LogisticModel.from_json(json.dumps(artifact))


def test_corpus_has_required_support_and_hard_negatives() -> None:
    from agentsentinel.corpus import read_corpus

    rows = read_corpus(Path("src/agentsentinel/data/default_corpus.jsonl"))
    assert len(rows) >= 36
    for category in ("exfiltration", "destruction", "privilege_escalation"):
        assert sum(row.category == category for row in rows) >= 6
    assert sum(row.label == "benign" for row in rows) >= 12
