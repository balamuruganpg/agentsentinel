"""Command-line scan, training, and evaluation, all offline."""

import argparse
import json
import math
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from agentsentinel.classifier import train
from agentsentinel.core import Sentinel
from agentsentinel.corpus import read_corpus
from agentsentinel.metrics import evaluate, format_metrics
from agentsentinel.trace import normalize_trace


class _Arguments(argparse.Namespace):
    command: str
    path: Path
    threshold: float
    as_json: bool
    model: Path | None
    out: Path


def _threshold(value: str) -> float:
    try:
        threshold = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "threshold must be a number in [0, 1]"
        ) from exc
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise argparse.ArgumentTypeError("threshold must be in [0, 1]")
    return threshold


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentsentinel", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("scan", "eval"):
        sub = subparsers.add_parser(command, help=f"{command} a trace or JSONL corpus")
        sub.add_argument("path", type=Path)
        sub.add_argument("--threshold", type=_threshold, default=0.5)
        sub.add_argument("--model", type=Path, help="use a locally trained model JSON")
        if command == "scan":
            sub.add_argument("--json", action="store_true", dest="as_json")
    training = subparsers.add_parser("train", help="train a deterministic classifier")
    training.add_argument("path", type=Path)
    training.add_argument("--out", type=Path, default=Path("model.json"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv, namespace=_Arguments())
    try:
        if args.command == "train":
            rows = read_corpus(args.path)
            model = train(rows)
            model.save(args.out)
            metrics = evaluate(
                rows,
                lambda trace: (
                    model.predict_probability(normalize_trace(trace)) >= model.threshold
                ),
            )
            print(f"Model written: {args.out}")
            print("Training-set classifier metrics (not held-out):")
            print(format_metrics(metrics))
            return 0
        scanner = (
            Sentinel(args.threshold)
            if args.model is None
            else Sentinel.from_model(args.model, args.threshold)
        )
        if args.command == "eval":
            rows = read_corpus(args.path)
            print(f"Pipeline evaluation (threshold={args.threshold:g}):")
            print(
                format_metrics(
                    evaluate(rows, lambda trace: scanner.scan(trace).flagged)
                )
            )
            return 0
        trace: object = json.loads(args.path.read_text(encoding="utf-8-sig"))
        if not isinstance(trace, dict):
            raise ValueError("trace must be a JSON object")
        report = scanner.scan(trace)
        if args.as_json:
            print(json.dumps(asdict(report), sort_keys=True, indent=2, allow_nan=False))
        else:
            print(f"Score: {report.score:.4f}")
            print(f"Flagged: {str(report.flagged).lower()}")
            print("Categories: " + (", ".join(report.categories) or "none"))
            print("Signals: " + (", ".join(report.signals) or "none"))
        return int(report.flagged)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        print(f"agentsentinel: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
