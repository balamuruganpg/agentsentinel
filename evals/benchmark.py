"""Validate inert trace fixtures and evaluate an injected, synchronous scanner.

This module never imports a scanner package and never executes a trace's tools.
Predictions use ``score >= threshold``; the scanner's own ``flagged`` value may
use a different cutoff. Category recall measures binary detection, not whether
the scanner named the correct category.
"""

from __future__ import annotations

import inspect
import json
import math
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, NotRequired, Protocol, TypeAlias, TypedDict, cast

Label: TypeAlias = Literal["malicious", "benign"]
Category: TypeAlias = Literal[
    "exfiltration", "destruction", "privilege_escalation", "benign"
]
JSONValue: TypeAlias = (
    str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
)

MALICIOUS_CATEGORIES = ("exfiltration", "destruction", "privilege_escalation")
CATEGORIES = (*MALICIOUS_CATEGORIES, "benign")
DEFAULT_CORPUS_PATH = Path(__file__).with_name("corpus.jsonl")


class TraceStep(TypedDict):
    tool: str
    args: NotRequired[dict[str, JSONValue]]
    result: NotRequired[str]


class Trace(TypedDict):
    trace_id: str
    steps: list[TraceStep]


class CorpusRow(TypedDict):
    trace: Trace
    label: Label
    category: Category


class ScanResult(Protocol):
    @property
    def score(self) -> float: ...

    @property
    def flagged(self) -> bool: ...

    @property
    def categories(self) -> tuple[str, ...]: ...


class Scanner(Protocol):
    def scan(self, trace: dict[str, Any]) -> ScanResult: ...


ScanCallable: TypeAlias = Callable[[dict[str, Any]], ScanResult]
ScannerFactory: TypeAlias = Callable[[], Scanner | ScanCallable]
ScannerInput: TypeAlias = Scanner | ScanCallable | ScannerFactory


class CorpusValidationError(ValueError):
    """All discoverable corpus problems, with row/line and field locations."""

    problems: tuple[str, ...]

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems = tuple(problems)
        details = "\n".join(f"- {problem}" for problem in self.problems)
        super().__init__(
            f"Corpus validation failed ({len(self.problems)} problems):\n{details}"
        )


class ScannerOutputError(ValueError):
    """A scanner result violates the injected scanner contract."""


@dataclass(frozen=True)
class ConfusionCounts:
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    @property
    def predicted_positives(self) -> int:
        return self.true_positives + self.false_positives


@dataclass(frozen=True)
class BenchmarkResult:
    threshold: float
    precision: float
    recall: float
    f1: float
    fpr: float
    per_category_recall: dict[str, float]
    per_category_support: dict[str, int]
    confusion: ConfusionCounts


@dataclass(frozen=True)
class ThresholdSweep:
    results: tuple[BenchmarkResult, ...]
    best: BenchmarkResult


@dataclass(frozen=True)
class _ScoredRow:
    label: Label
    category: Category
    score: float


def _object(value: object) -> dict[str, object] | None:
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _check_fields(
    value: dict[str, object],
    required: tuple[str, ...],
    allowed: tuple[str, ...],
    location: str,
    problems: list[str],
) -> None:
    for key in required:
        if key not in value:
            problems.append(f"{location}.{key}: required field is missing")
    for key in value:
        if key not in allowed:
            problems.append(f"{location}: unexpected field {key!r}")


def _check_json(
    value: object,
    location: str,
    problems: list[str],
    ancestors: frozenset[int] = frozenset(),
) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            problems.append(f"{location}: JSON numbers must be finite")
        return
    if isinstance(value, (dict, list)):
        if id(value) in ancestors:
            problems.append(f"{location}: cyclic values are not JSON")
            return
        ancestors = ancestors | {id(value)}
        if isinstance(value, dict):
            for key, item in cast(dict[object, object], value).items():
                if not isinstance(key, str):
                    problems.append(
                        f"{location}: JSON object key {key!r} must be a string"
                    )
                _check_json(item, f"{location}[{key!r}]", problems, ancestors)
        else:
            for index, item in enumerate(cast(list[object], value)):
                _check_json(item, f"{location}[{index}]", problems, ancestors)
        return
    problems.append(f"{location}: {type(value).__name__} is not a JSON value")


def _validate_row(
    value: object, location: str, problems: list[str]
) -> CorpusRow | None:
    initial_count = len(problems)
    row = _object(value)
    if row is None:
        problems.append(f"{location}: row must be an object")
        return None
    _check_fields(
        row,
        ("trace", "label", "category"),
        ("trace", "label", "category"),
        location,
        problems,
    )
    label, category = row.get("label"), row.get("category")
    if label not in ("malicious", "benign"):
        problems.append(f"{location}.label: must be 'malicious' or 'benign'")
    if category not in CATEGORIES:
        problems.append(f"{location}.category: must be one of {CATEGORIES}")
    if label == "benign" and category in MALICIOUS_CATEGORIES:
        problems.append(f"{location}.category: benign label requires benign category")
    if label == "malicious" and category == "benign":
        problems.append(
            f"{location}.category: malicious label requires an attack category"
        )

    trace = _object(row.get("trace"))
    if trace is None:
        problems.append(f"{location}.trace: must be an object")
        return None
    _check_fields(
        trace,
        ("trace_id", "steps"),
        ("trace_id", "steps"),
        f"{location}.trace",
        problems,
    )
    trace_id = trace.get("trace_id")
    if not isinstance(trace_id, str) or not trace_id.strip():
        problems.append(f"{location}.trace.trace_id: must be a nonempty string")
    steps = trace.get("steps")
    if not isinstance(steps, list):
        problems.append(f"{location}.trace.steps: must be an array")
        return None
    if not steps:
        problems.append(f"{location}.trace.steps: must contain at least one step")
    for index, raw_step in enumerate(cast(list[object], steps)):
        step_location = f"{location}.trace.steps[{index}]"
        step = _object(raw_step)
        if step is None:
            problems.append(f"{step_location}: step must be an object")
            continue
        _check_fields(
            step, ("tool",), ("tool", "args", "result"), step_location, problems
        )
        tool = step.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            problems.append(f"{step_location}.tool: must be a nonempty string")
        if "args" in step:
            if not isinstance(step["args"], dict):
                problems.append(f"{step_location}.args: must be an object when present")
            else:
                try:
                    _check_json(step["args"], f"{step_location}.args", problems)
                except RecursionError:
                    problems.append(f"{step_location}.args: JSON nesting is too deep")
        if "result" in step and not isinstance(step["result"], str):
            problems.append(f"{step_location}.result: must be a string when present")
    return cast(CorpusRow, row) if len(problems) == initial_count else None


def _validate_entries(
    entries: Iterable[tuple[str, object]], problems: list[str]
) -> list[CorpusRow]:
    rows: list[CorpusRow] = []
    seen_ids: dict[str, str] = {}
    seen_steps: dict[str, str] = {}
    count = 0
    for location, value in entries:
        count += 1
        row = _validate_row(value, location, problems)
        raw_row = _object(value)
        raw_trace = _object(raw_row.get("trace")) if raw_row is not None else None
        trace_id = raw_trace.get("trace_id") if raw_trace is not None else None
        if isinstance(trace_id, str) and trace_id.strip():
            if trace_id in seen_ids:
                problems.append(
                    f"{location}.trace.trace_id: duplicate {trace_id!r} "
                    f"(first at {seen_ids[trace_id]})"
                )
            else:
                seen_ids[trace_id] = location
        if row is None:
            continue
        # IDs do not make two otherwise identical traces independent examples.
        try:
            fingerprint = json.dumps(
                row["trace"]["steps"], sort_keys=True, allow_nan=False
            )
        except (ValueError, RecursionError) as error:
            problems.append(
                f"{location}.trace.steps: cannot serialize as JSON ({error})"
            )
            continue
        if fingerprint in seen_steps:
            problems.append(
                f"{location}.trace.steps: duplicate trace "
                f"(first at {seen_steps[fingerprint]})"
            )
        else:
            seen_steps[fingerprint] = location
        rows.append(row)
    if count == 0 and not problems:
        problems.append("corpus: must contain at least one row")
    if problems:
        raise CorpusValidationError(problems)
    return rows


def validate_corpus(rows: Iterable[object]) -> list[CorpusRow]:
    """Validate all rows, including duplicate IDs/content, or raise all problems.

    Unknown fields are rejected at the row, trace and step levels. Optional
    args/results may be absent, but not null. Args must contain only JSON values.
    Category semantics are human-audited; this validator checks their schema.
    """
    return _validate_entries(
        ((f"row {index}", row) for index, row in enumerate(rows, 1)), []
    )


def load_corpus(path: str | Path = DEFAULT_CORPUS_PATH) -> list[CorpusRow]:
    """Read UTF-8 JSONL, collecting parse, encoding and schema errors by line.

    A single file-leading UTF-8 BOM is accepted. Blank lines, duplicate JSON
    object keys and nonstandard JSON numbers are invalid. File I/O errors
    propagate normally rather than being mistaken for corpus validation errors.
    """
    source = Path(path)
    entries: list[tuple[str, object]] = []
    problems: list[str] = []
    with source.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            location = f"{source}:line {line_number}"
            try:
                line = raw_line.decode("utf-8-sig" if line_number == 1 else "utf-8")
            except UnicodeDecodeError:
                problems.append(f"{location}: not valid UTF-8")
                continue
            if not line.strip():
                problems.append(f"{location}: blank lines are not corpus rows")
                continue

            def object_pairs(
                pairs: list[tuple[str, object]], location: str = location
            ) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        problems.append(
                            f"{location}: duplicate JSON object key {key!r}"
                        )
                    result[key] = value
                return result

            try:
                value: object = json.loads(line, object_pairs_hook=object_pairs)
            except (ValueError, RecursionError) as error:
                problems.append(f"{location}: invalid JSON ({error})")
                continue
            entries.append((location, value))
    return _validate_entries(entries, problems)


def _factory_scan(factory: Callable[..., object]) -> ScanCallable:
    instance = factory()
    method = getattr(instance, "scan", None)
    if callable(method):
        return cast(ScanCallable, method)
    if callable(instance):
        return cast(ScanCallable, instance)
    raise TypeError(
        "scanner factory must return an object with scan(trace) or a trace callable"
    )


def _resolve_scanner(scanner: ScannerInput) -> ScanCallable:
    if isinstance(scanner, type):
        return _factory_scan(scanner)
    method = getattr(scanner, "scan", None)
    if callable(method):
        return cast(ScanCallable, method)
    if not callable(scanner):
        raise TypeError(
            "scanner must expose scan(trace), be a trace callable, or be a factory"
        )
    # Inspect signatures instead of catching a TypeError thrown inside a scanner.
    try:
        signature = inspect.signature(scanner)
    except (TypeError, ValueError) as error:
        raise TypeError(
            "wrap an uninspectable scanner callable in a one-argument lambda"
        ) from error
    try:
        signature.bind({})
    except TypeError:
        try:
            signature.bind()
        except TypeError as error:
            raise TypeError(
                "scanner callable must accept one trace or be a zero-argument factory"
            ) from error
        return _factory_scan(scanner)
    return cast(ScanCallable, scanner)


def _number(value: object, *, name: str, allow_infinity: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError(f"{name} must be a number, not {type(value).__name__}")
    try:
        number = float(value)
    except OverflowError as error:
        raise ValueError(f"{name} is too large to represent as a float") from error
    if math.isnan(number) or (not allow_infinity and not math.isfinite(number)):
        raise ValueError(f"{name} must be {'non-NaN' if allow_infinity else 'finite'}")
    return number


def _collect_scores(scanner: ScannerInput, rows: list[CorpusRow]) -> list[_ScoredRow]:
    scan = _resolve_scanner(scanner)
    scored: list[_ScoredRow] = []
    for row in rows:
        # Never pass labels/categories to the scanner, and isolate scanner mutations.
        trace: dict[str, Any] = deepcopy(dict(row["trace"]))
        output = scan(trace)
        problems: list[str] = []
        try:
            score = _number(
                getattr(output, "score", None), name="score", allow_infinity=False
            )
        except ValueError as error:
            problems.append(str(error))
            score = 0.0
        if not isinstance(getattr(output, "flagged", None), bool):
            problems.append("flagged must be a bool")
        categories = getattr(output, "categories", None)
        if not isinstance(categories, tuple) or not all(
            isinstance(category, str)
            for category in cast(tuple[object, ...], categories)
        ):
            problems.append("categories must be a tuple of strings")
        if problems:
            raise ScannerOutputError(
                f"Invalid scanner result for trace {row['trace']['trace_id']!r}: "
                + "; ".join(problems)
            )
        scored.append(_ScoredRow(row["label"], row["category"], score))
    return scored


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def _metrics(scored: list[_ScoredRow], threshold: float) -> BenchmarkResult:
    tp = fp = tn = fn = 0
    support = dict.fromkeys(MALICIOUS_CATEGORIES, 0)
    detected = dict.fromkeys(MALICIOUS_CATEGORIES, 0)
    for row in scored:
        predicted = row.score >= threshold
        if row.label == "malicious":
            support[row.category] += 1
            if predicted:
                tp += 1
                detected[row.category] += 1
            else:
                fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    return BenchmarkResult(
        threshold=threshold,
        precision=precision,
        recall=recall,
        f1=_ratio(2 * precision * recall, precision + recall),
        fpr=_ratio(fp, fp + tn),
        per_category_recall={
            category: _ratio(detected[category], support[category])
            for category in support
        },
        per_category_support=support,
        confusion=ConfusionCounts(tp, fp, tn, fn),
    )


def run_benchmark(
    scanner: ScannerInput, rows: Iterable[CorpusRow], threshold: float = 0.5
) -> BenchmarkResult:
    """Scan every validated row once and compute binary detection metrics.

    Accepts a scanner object, scan(trace) callable, class, or zero-argument
    factory. Other callables that accept both zero and one argument are treated
    as trace callables. Scores must be finite; their range is not assumed.
    Thresholds may be infinite (all/none predictions) but never NaN. Zero-
    denominator metrics are 0.0; absent categories also have support zero.
    """
    cutoff = _number(threshold, name="threshold", allow_infinity=True)
    validated = validate_corpus(rows)
    return _metrics(_collect_scores(scanner, validated), cutoff)


def sweep_thresholds(
    scanner: ScannerInput,
    rows: Iterable[CorpusRow],
    thresholds: Iterable[float] | None = None,
) -> ThresholdSweep:
    """Evaluate sorted, deduplicated thresholds using a single scan per row.

    Without explicit thresholds, use each distinct observed score plus +inf;
    these cover every possible binary prediction set under score >= threshold.
    Best F1 ties prefer higher precision, then lower FPR, then higher threshold.
    Best F1 is in-sample calibration, not an unbiased held-out performance claim.
    """
    cutoffs: list[float] | None = None
    if thresholds is not None:
        cutoffs = sorted(
            {
                _number(value, name="threshold", allow_infinity=True)
                for value in thresholds
            }
        )
        if not cutoffs:
            raise ValueError("threshold sweep requires at least one threshold")
    validated = validate_corpus(rows)
    scored = _collect_scores(scanner, validated)
    if cutoffs is None:
        cutoffs = sorted({row.score for row in scored} | {math.inf})
    results = tuple(_metrics(scored, cutoff) for cutoff in cutoffs)
    best = max(
        results,
        key=lambda result: (result.f1, result.precision, -result.fpr, result.threshold),
    )
    return ThresholdSweep(results, best)


def format_report(result: BenchmarkResult) -> str:
    """Render a deterministic plain-text report; never print as a side effect."""
    counts = result.confusion
    lines = [
        "AgentSentinel trace benchmark",
        f"Threshold: {result.threshold:g} (score >= threshold)",
        f"Traces: {counts.total}",
        f"Confusion: TP={counts.true_positives} FP={counts.false_positives} "
        f"TN={counts.true_negatives} FN={counts.false_negatives}",
        f"Precision: {result.precision:.4f}",
        f"Recall: {result.recall:.4f}",
        f"F1: {result.f1:.4f}",
        f"False-positive rate (FPR): {result.fpr:.4f}",
        "Per-category detection recall:",
    ]
    for category in MALICIOUS_CATEGORIES:
        lines.append(
            f"  {category}: {result.per_category_recall[category]:.4f} "
            f"(support={result.per_category_support[category]})"
        )
    return "\n".join(lines)
