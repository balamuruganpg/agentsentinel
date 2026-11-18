"""Strict JSONL training/evaluation rows, separate from tolerant trace scanning."""

import json
from dataclasses import dataclass
from pathlib import Path

CATEGORIES = ("exfiltration", "destruction", "privilege_escalation")


@dataclass(frozen=True)
class CorpusRow:
    trace: dict[str, object]
    label: str
    category: str


def read_corpus(path: str | Path) -> tuple[CorpusRow, ...]:
    rows: list[CorpusRow] = []
    with Path(path).open(encoding="utf-8-sig") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                value: object = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict) or not isinstance(value.get("trace"), dict):
                raise ValueError(f"{path}:{number}: row must contain a trace object")
            label = value.get("label")
            category = value.get("category")
            if label not in ("malicious", "benign") or not isinstance(category, str):
                raise ValueError(f"{path}:{number}: invalid label/category")
            if (label == "benign" and category != "benign") or (
                label == "malicious" and category not in CATEGORIES
            ):
                raise ValueError(f"{path}:{number}: label/category mismatch")
            # Explicitly narrow label for the type checker, too.
            assert isinstance(label, str)
            rows.append(CorpusRow(value["trace"], label, category))
    if not rows:
        raise ValueError(f"{path}: corpus contains no rows")
    return tuple(rows)
