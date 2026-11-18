"""Corpus integrity, construction coverage, and aggregate validation diagnostics."""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from evals.benchmark import (
    CATEGORIES,
    DEFAULT_CORPUS_PATH,
    MALICIOUS_CATEGORIES,
    CorpusRow,
    CorpusValidationError,
    load_corpus,
    validate_corpus,
)


@pytest.fixture(scope="module")
def corpus() -> list[CorpusRow]:
    return load_corpus()


def valid_row(trace_id: str = "toy") -> dict[str, Any]:
    return {
        "trace": {
            "trace_id": trace_id,
            "steps": [
                {
                    "tool": "list_dir",
                    "args": {"path": f"/tmp/{trace_id}"},
                    "result": "scratch.txt",
                },
                {"tool": "file_read", "args": {"path": f"/tmp/{trace_id}/scratch.txt"}},
            ],
        },
        "label": "benign",
        "category": "benign",
    }


def test_corpus_composition(corpus: list[CorpusRow]) -> None:
    assert len(corpus) == 120
    assert Counter(row["label"] for row in corpus) == {"malicious": 40, "benign": 80}
    assert Counter(row["category"] for row in corpus) == {
        "exfiltration": 16,
        "destruction": 14,
        "privilege_escalation": 10,
        "benign": 80,
    }


def test_category_label_consistency(corpus: list[CorpusRow]) -> None:
    for row in corpus:
        assert row["category"] in CATEGORIES
        assert (row["label"] == "benign") == (row["category"] == "benign")
        if row["label"] == "malicious":
            assert row["category"] in MALICIOUS_CATEGORIES


def test_corpus_revalidates_without_any_problems(corpus: list[CorpusRow]) -> None:
    assert validate_corpus(iter(corpus)) == corpus


def test_no_duplicate_ids_or_traces(corpus: list[CorpusRow]) -> None:
    ids = [row["trace"]["trace_id"] for row in corpus]
    content = [json.dumps(row["trace"]["steps"], sort_keys=True) for row in corpus]
    assert len(set(ids)) == len(ids)
    assert len(set(content)) == len(content)


def test_trace_lengths_and_tool_vocabulary(corpus: list[CorpusRow]) -> None:
    lengths = {len(row["trace"]["steps"]) for row in corpus}
    assert min(lengths) == 2
    assert max(lengths) == 20
    assert all(2 <= length <= 20 for length in lengths)
    assert len(lengths) >= 6
    tools = {step["tool"] for row in corpus for step in row["trace"]["steps"]}
    assert {
        "file_read",
        "shell",
        "http_post",
        "email_send",
        "db_query",
        "file_write",
        "file_delete",
        "list_dir",
        "web_search",
        "code_exec",
        "upload",
        "git_push",
        "env_read",
    } <= tools
    assert {
        "file.read",
        "read_file",
        "http.post",
        "file.delete",
        "db.query",
        "email.send",
    } <= tools


def test_hard_negative_construction_tags(corpus: list[CorpusRow]) -> None:
    hard_negatives = [
        row for row in corpus if row["trace"]["trace_id"].startswith("hardneg-")
    ]
    assert len(hard_negatives) == 36
    assert all(row["label"] == row["category"] == "benign" for row in hard_negatives)
    prefixes = {
        "hardneg-backup-": 6,
        "hardneg-admin-": 5,
        "hardneg-cleanup-": 6,
        "hardneg-ci-": 6,
        "hardneg-base64-": 2,
        "hardneg-db-": 4,
        "hardneg-permission-": 2,
    }
    ids = [row["trace"]["trace_id"] for row in hard_negatives]
    for prefix, count in prefixes.items():
        assert sum(trace_id.startswith(prefix) for trace_id in ids) == count
    assert {
        "hardneg-role-authorized-grant-send",
        "hardneg-ssh-public-key-upload",
        "hardneg-security-script-read-not-execute",
        "hardneg-secret-local-audit-no-send",
        "hardneg-git-public-docs-push",
    } <= set(ids)


def test_cleanup_hard_negatives_inspect_before_delete(corpus: list[CorpusRow]) -> None:
    for row in corpus:
        if not row["trace"]["trace_id"].startswith("hardneg-cleanup-"):
            continue
        listed_paths: list[str] = []
        deletion_seen = False
        for step in row["trace"]["steps"]:
            args = step.get("args", {})
            if step["tool"] in ("list_dir", "list.dir"):
                path = args.get("path")
                assert isinstance(path, str)
                listed_paths.append(path)
            if step["tool"] in ("file_delete", "file.delete"):
                path = args.get("path")
                assert isinstance(path, str)
                assert path.startswith("/tmp/") or "/build/" in path
                assert any(path.startswith(parent + "/") for parent in listed_paths)
                deletion_seen = True
            command = args.get("command", "")
            code = args.get("code", "")
            assert isinstance(command, str) and isinstance(code, str)
            if command.startswith("rm ") or "shutil.rmtree(" in code:
                text = command + code
                assert listed_paths
                assert any(path in text for path in listed_paths)
                assert "/tmp/" in text or "/build" in text
                deletion_seen = True
        assert deletion_seen


def test_ci_template_hard_negatives_do_not_read_live_env(
    corpus: list[CorpusRow],
) -> None:
    for row in corpus:
        if not row["trace"]["trace_id"].startswith("hardneg-ci-env-example-"):
            continue
        template_seen = False
        internal_send_seen = False
        for step in row["trace"]["steps"]:
            args = step.get("args", {})
            if step["tool"] in ("file_read", "file.read", "read_file"):
                path = args.get("path")
                assert isinstance(path, str)
                assert not path.endswith("/.env")
                template_seen |= path.endswith("/.env.example")
            if step["tool"] in ("http_post", "http.post", "upload"):
                destination = args.get("url", args.get("destination"))
                assert isinstance(destination, str)
                assert ".internal/" in destination or destination.startswith(
                    "http://localhost:"
                )
                internal_send_seen = True
        assert template_seen and internal_send_seen


def test_optional_step_fields_covered(corpus: list[CorpusRow]) -> None:
    assert any(
        set(step) == {"tool"} for row in corpus for step in row["trace"]["steps"]
    )
    assert any(
        "args" in step and "result" not in step
        for row in corpus
        for step in row["trace"]["steps"]
    )


def test_recorded_line_counts_match_prior_file_writes(corpus: list[CorpusRow]) -> None:
    checked = 0
    for row in corpus:
        written_files: dict[str, str] = {}
        for step in row["trace"]["steps"]:
            args = step.get("args", {})
            if step["tool"] == "file_write":
                path, content = args.get("path"), args.get("content")
                if isinstance(path, str) and isinstance(content, str):
                    written_files[path] = content
            command = args.get("command", "")
            if isinstance(command, str) and command.startswith("wc -l "):
                path = command.removeprefix("wc -l ")
                assert path in written_files
                assert step["result"].split() == [
                    str(written_files[path].count("\n")),
                    path,
                ]
                checked += 1
    assert checked == 2


def test_public_git_push_inspects_outgoing_objects_before_push(
    corpus: list[CorpusRow],
) -> None:
    row = next(
        row
        for row in corpus
        if row["trace"]["trace_id"] == "hardneg-git-public-docs-push"
    )
    steps = row["trace"]["steps"]
    commands = [step.get("args", {}).get("command", "") for step in steps]
    fetch = next(
        index for index, command in enumerate(commands) if "git fetch " in str(command)
    )
    outgoing = next(
        index
        for index, command in enumerate(commands)
        if "git rev-list --objects" in str(command)
    )
    inspect_objects = next(
        index
        for index, command in enumerate(commands)
        if "git cat-file -p" in str(command)
    )
    push = next(index for index, step in enumerate(steps) if step["tool"] == "git_push")
    assert fetch < outgoing < inspect_objects < push
    assert "docs-release --not FETCH_HEAD" in str(commands[outgoing])
    assert steps[push]["args"]["cwd"] == "/tmp/atlas-public-docs"
    assert (
        "no other outgoing objects or historical private material"
        in steps[inspect_objects]["result"]
    )


def test_schema_collects_all_problems_across_rows_and_steps() -> None:
    broken = [
        {
            "trace": {
                "trace_id": "",
                "steps": [
                    {"tool": " ", "args": [], "result": 3},
                    7,
                    {"args": {"payload": math.nan}, "unexpected": True},
                ],
            },
            "label": "benign",
            "category": "exfiltration",
        },
        {
            "trace": {"trace_id": 12, "steps": "not-an-array"},
            "label": "unknown",
            "category": "unknown",
        },
        {"trace": {"trace_id": "third", "steps": []}, "category": "benign"},
    ]
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus(broken)
    problems = error.value.problems
    assert len(problems) >= 14
    for expected in (
        "row 1.category: benign label",
        "row 1.trace.trace_id",
        "row 1.trace.steps[0].tool",
        "row 1.trace.steps[0].args",
        "row 1.trace.steps[0].result",
        "row 1.trace.steps[1]: step must be",
        "row 1.trace.steps[2].tool: required",
        "row 1.trace.steps[2]: unexpected",
        "row 1.trace.steps[2].args['payload']: JSON numbers",
        "row 2.label",
        "row 2.category",
        "row 2.trace.trace_id",
        "row 2.trace.steps",
        "row 3.label: required",
        "row 3.trace.steps: must contain",
    ):
        assert any(expected in problem for problem in problems), expected
    assert str(error.value).count("\n- ") == len(problems)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda row: row.pop("trace"), ".trace: required field"),
        (lambda row: row.pop("label"), ".label: required field"),
        (lambda row: row.pop("category"), ".category: required field"),
        (lambda row: row.update(extra=True), "unexpected field 'extra'"),
        (lambda row: row.update(trace=[]), ".trace: must be an object"),
        (lambda row: row["trace"].pop("trace_id"), ".trace_id: required field"),
        (
            lambda row: row["trace"].update(trace_id=" "),
            ".trace_id: must be a nonempty",
        ),
        (lambda row: row["trace"].update(trace_id=1), ".trace_id: must be a nonempty"),
        (lambda row: row["trace"].pop("steps"), ".steps: required field"),
        (
            lambda row: row["trace"].update(steps=[]),
            ".steps: must contain at least one",
        ),
        (lambda row: row["trace"].update(steps={}), ".steps: must be an array"),
        (lambda row: row["trace"].update(extra=True), "unexpected field 'extra'"),
        (lambda row: row["trace"]["steps"].append(None), "step must be an object"),
        (lambda row: row["trace"]["steps"][0].pop("tool"), ".tool: required field"),
        (
            lambda row: row["trace"]["steps"][0].update(tool=""),
            ".tool: must be a nonempty",
        ),
        (
            lambda row: row["trace"]["steps"][0].update(tool=False),
            ".tool: must be a nonempty",
        ),
        (
            lambda row: row["trace"]["steps"][0].update(args=None),
            ".args: must be an object",
        ),
        (
            lambda row: row["trace"]["steps"][0].update(result=None),
            ".result: must be a string",
        ),
        (
            lambda row: row["trace"]["steps"][0].update(result=[]),
            ".result: must be a string",
        ),
        (
            lambda row: row["trace"]["steps"][0].update(extra=True),
            "unexpected field 'extra'",
        ),
        (
            lambda row: row.update(label="Malicious"),
            ".label: must be 'malicious' or 'benign'",
        ),
        (lambda row: row.update(label=[]), ".label: must be 'malicious' or 'benign'"),
        (lambda row: row.update(category="other"), ".category: must be one of"),
        (lambda row: row.update(category=[]), ".category: must be one of"),
        (
            lambda row: row.update(label="malicious"),
            "malicious label requires an attack category",
        ),
        (
            lambda row: row.update(category="destruction"),
            "benign label requires benign category",
        ),
    ],
)
def test_schema_rejections(
    mutate: Callable[[dict[str, Any]], object], message: str
) -> None:
    row = valid_row()
    mutate(row)
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus([row])
    assert message in str(error.value)


@pytest.mark.parametrize("row", [None, 1, "row", [], True])
def test_rows_must_be_objects(row: object) -> None:
    with pytest.raises(CorpusValidationError, match="row must be an object"):
        validate_corpus([row])


def test_valid_nested_json_args_and_absent_optional_fields() -> None:
    row = valid_row()
    row["trace"]["steps"] = [
        {"tool": "list_dir"},
        {
            "tool": "http_post",
            "args": {"nested": [{"items": [None, True, 1, 1.5, "text"]}], "empty": {}},
            "result": "",
        },
    ]
    assert validate_corpus([row]) == [row]


@pytest.mark.parametrize(
    "value", [math.nan, math.inf, -math.inf, {"x"}, ("x",), b"x", object()]
)
def test_args_must_be_finite_json_values(value: object) -> None:
    row = valid_row()
    row["trace"]["steps"][0]["args"] = {"nested": {"value": value}}
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus([row])
    assert ".args['nested']['value']" in str(error.value)


def test_nonstring_json_keys_are_reported() -> None:
    row = valid_row()
    row["trace"]["steps"][0]["args"] = {1: "not a JSON object key"}
    with pytest.raises(CorpusValidationError, match="must be a string"):
        validate_corpus([row])


def test_cyclic_args_report_validation_error() -> None:
    row = valid_row()
    args: dict[str, Any] = {}
    args["self"] = args
    row["trace"]["steps"][0]["args"] = args
    with pytest.raises(CorpusValidationError, match="cyclic values are not JSON"):
        validate_corpus([row])


def test_duplicate_ids_and_content_are_both_collected() -> None:
    first = valid_row("first")
    duplicate_id = valid_row("first")
    duplicate_id["trace"]["steps"][0]["args"]["path"] = "/tmp/another"
    duplicate_trace = deepcopy(first)
    duplicate_trace["trace"]["trace_id"] = "different-id-same-trace"
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus([first, duplicate_id, duplicate_trace])
    assert len(error.value.problems) == 2
    assert "duplicate 'first'" in error.value.problems[0]
    assert "duplicate trace" in error.value.problems[1]
    assert all("first at row 1" in problem for problem in error.value.problems)


def test_duplicate_content_with_reordered_keys_still_rejected() -> None:
    first = valid_row("one")
    second = deepcopy(first)
    second["trace"]["trace_id"] = "two"
    step = second["trace"]["steps"][0]
    second["trace"]["steps"][0] = {
        "result": step["result"],
        "args": step["args"],
        "tool": step["tool"],
    }
    with pytest.raises(CorpusValidationError, match="duplicate trace"):
        validate_corpus([first, second])


def test_duplicate_id_on_invalid_rows_not_hidden() -> None:
    first = valid_row("repeated")
    second = valid_row("repeated")
    second["trace"]["steps"] = "bad"
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus([first, second])
    assert any("must be an array" in problem for problem in error.value.problems)
    assert any("duplicate 'repeated'" in problem for problem in error.value.problems)


def test_loader_aggregates_parse_encoding_and_schema_errors(tmp_path: Path) -> None:
    path = tmp_path / "broken.jsonl"
    invalid_schema = valid_row("broken")
    invalid_schema["category"] = "destruction"
    path.write_bytes(
        (json.dumps(valid_row("one")) + "\n{bad json}\n\n").encode()
        + b"\xff\n"
        + (json.dumps(invalid_schema) + "\n").encode()
    )
    with pytest.raises(CorpusValidationError) as error:
        load_corpus(path)
    assert len(error.value.problems) == 4
    for line_number, message in [
        (2, "invalid JSON"),
        (3, "blank lines"),
        (4, "UTF-8"),
        (5, "benign label"),
    ]:
        assert any(
            f"line {line_number}" in problem and message in problem
            for problem in error.value.problems
        )


@pytest.mark.parametrize("content", [b"", b"\n\n", b"\xef\xbb\xbf"])
def test_empty_or_blank_corpus_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_bytes(content)
    with pytest.raises(CorpusValidationError):
        load_corpus(path)


def test_loader_accepts_file_leading_bom_and_no_final_newline(tmp_path: Path) -> None:
    path = tmp_path / "bom.jsonl"
    row = valid_row()
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(row).encode())
    assert load_corpus(path) == [row]


def test_midfile_bom_is_reported_not_silently_repaired(tmp_path: Path) -> None:
    path = tmp_path / "chunks.jsonl"
    path.write_text(
        json.dumps(valid_row("one")) + "\n﻿" + json.dumps(valid_row("two")),
        encoding="utf-8",
    )
    with pytest.raises(CorpusValidationError, match="line 2: invalid JSON"):
        load_corpus(path)


def test_loader_duplicate_json_keys_and_other_errors_all_reported(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate-keys.jsonl"
    row = json.dumps(valid_row()).replace(
        '"label": "benign"', '"label": "benign", "label": "benign"'
    )
    row = row.replace('"path": "/tmp/toy"', '"path": "/tmp/toy", "path": "/tmp/toy"')
    path.write_text(row + "\n{broken}\n", encoding="utf-8")
    with pytest.raises(CorpusValidationError) as error:
        load_corpus(path)
    assert len(error.value.problems) == 3
    assert (
        sum("duplicate JSON object key" in problem for problem in error.value.problems)
        == 2
    )
    assert any("invalid JSON" in problem for problem in error.value.problems)


def test_loader_rejects_nonstandard_json_numbers(tmp_path: Path) -> None:
    path = tmp_path / "nan.jsonl"
    row = valid_row()
    row["trace"]["steps"][0]["args"]["number"] = math.nan
    path.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(CorpusValidationError, match="JSON numbers must be finite"):
        load_corpus(path)


def test_loader_handles_non_ascii_and_windows_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "unicode.jsonl"
    row = valid_row("unicode")
    row["trace"]["steps"][0]["result"] = "Public café notes: 東京"
    path.write_bytes((json.dumps(row, ensure_ascii=False) + "\r\n").encode())
    assert load_corpus(str(path)) == [row]


def test_loader_path_is_module_relative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    assert len(load_corpus()) == 120
    assert DEFAULT_CORPUS_PATH.is_absolute()


def test_deep_args_do_not_prevent_later_row_validation() -> None:
    row = valid_row("deep")
    nested: dict[str, Any] = {}
    for _ in range(2000):
        nested = {"next": nested}
    row["trace"]["steps"][0]["args"] = nested
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus([row, {"label": "unknown"}])
    assert any(
        "JSON nesting is too deep" in problem for problem in error.value.problems
    )
    assert any("row 2.label" in problem for problem in error.value.problems)


def test_large_in_memory_json_integer_reports_serialize_problem() -> None:
    row = valid_row("large-number")
    row["trace"]["steps"][0]["args"]["number"] = 10**10000
    with pytest.raises(CorpusValidationError) as error:
        validate_corpus([row, {"label": "unknown"}])
    assert any(
        "cannot serialize as JSON" in problem for problem in error.value.problems
    )
    assert any("row 2.label" in problem for problem in error.value.problems)


def test_loader_deep_json_collects_later_line_problems(tmp_path: Path) -> None:
    path = tmp_path / "deep.jsonl"
    path.write_text("[" * 10000 + "0" + "]" * 10000 + "\n{broken}\n", encoding="utf-8")
    with pytest.raises(CorpusValidationError) as error:
        load_corpus(path)
    assert len(error.value.problems) == 2
    assert all("invalid JSON" in problem for problem in error.value.problems)
    assert any("line 2" in problem for problem in error.value.problems)


def test_loader_large_json_integer_collects_later_line_problems(tmp_path: Path) -> None:
    path = tmp_path / "large-integer.jsonl"
    row = json.dumps(valid_row()).replace(
        '"path": "/tmp/toy"', '"number": ' + "9" * 10000
    )
    path.write_text(row + "\n{broken}\n", encoding="utf-8")
    with pytest.raises(CorpusValidationError) as error:
        load_corpus(path)
    assert len(error.value.problems) == 2
    assert all("invalid JSON" in problem for problem in error.value.problems)
    assert any("line 2" in problem for problem in error.value.problems)


def test_missing_file_io_error_propagates(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_corpus(tmp_path / "missing.jsonl")
