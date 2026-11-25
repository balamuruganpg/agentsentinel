# AgentSentinel

AgentSentinel scans an LLM agent's execution trace for data exfiltration,
destructive operations, and privilege escalation. It combines deterministic
sequence rules with a learned tool-sequence classifier, following the
rules-plus-learned approach of the author's PromptWarden in a new domain.

Version 0.5.0 runs on Python 3.11+ with **no runtime dependencies**. The default
corpus and trained JSON model ship inside the package and work offline.

**F1 0.9286. False-positive rate 0.0625.** Precision 0.8864 and recall 0.9750
on the independent 120-trace corpus at threshold 0.5.

![v0.3.0 category recall: exfiltration 0.6250, destruction 0.9286, privilege escalation 1.0000. Precision 0.8684, recall 0.8250, F1 0.8462, FPR 0.0625.](docs/assets/benchmark.svg)

*Category recall. The red bar is exfiltration, the remaining gap at 0.6250.*

![v0.3.0 confusion counts at threshold 0.5: true positives 33, false positives 5, true negatives 75, false negatives 7.](docs/assets/confusion.svg)

*33 true positives, 5 false positives, 75 true negatives, and 7 false negatives. The red cell is the misses.*

[Open the benchmark chart](docs/assets/benchmark.svg?raw=1) or
[the confusion chart](docs/assets/confusion.svg?raw=1) to hover or focus each
mark. Rebuild both with `python docs/assets/make_charts.py`.

[Quickstart](#quickstart) · [Pipeline](#scan-pipeline) · [Feature matrix](#feature-matrix) · [Benchmark](#independent-benchmark-120-traces-evalscorpusjsonl)

## Install

From the repository root, create a virtual environment and install the package.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

For development, use `python -m pip install -e .` and install `pytest ruff mypy`
separately. They are development tools, not package dependencies.

## Quickstart

Scan the bundled [exfiltration trace](examples/exfiltration.json).

```sh
agentsentinel scan examples/exfiltration.json
```

### Demo scoreboard

Actual `agentsentinel scan` output at the v0.3.0 default threshold of `0.5`.

| | Flagged exfiltration | Unflagged benign trace |
| --- | --- | --- |
| Trace | `exfil-01` · reads `.env`, then posts externally | `safe-01` · lists `/workspace` |
| Score | `0.8500` | `0.0403` |
| Categories | `exfiltration` | `none` |
| Signals | `exfil:read-then-send` | `none` |
| CLI exit | `1` | `0` |

Exit **2** means a usage, input, or file error. Use `--json` for a machine-readable
report or `--threshold 0.9` to change the decision threshold. Every command also
works through `python -m agentsentinel`.

<details>
<summary>Reproduce both scans and see the CLI output</summary>

```console
$ agentsentinel scan examples/exfiltration.json
Score: 0.8500
Flagged: true
Categories: exfiltration
Signals: exfil:read-then-send

$ cat > benign.json <<'JSON'
> {"trace_id":"safe-01","steps":[{"tool":"list_files","args":{"path":"/workspace"},"result":""}]}
> JSON
$ agentsentinel scan benign.json
Score: 0.0403
Flagged: false
Categories: none
Signals: none
```

</details>

## Scan pipeline

```mermaid
flowchart LR
    Trace["Execution<br/>trace"] --> Normalize["Normalize<br/>tool steps"]
    Normalize --> Rules["Rules<br/>weighted signals"]
    Normalize --> Classifier["Classifier<br/>logistic regression"]
    Rules --> Blend["max(rule score,<br/>classifier probability)"]
    Classifier --> Blend
    Blend --> Report["TraceReport<br/>score, flagged,<br/>categories, signals"]
```

The report flags scores at or above the requested threshold. Categories come from
fired rules, including rules whose evidence falls below the flag threshold.

### Modules

```mermaid
flowchart TD
    CLI["cli.py · scan, train, eval"] --> Core["core.py · Sentinel"]
    CLI --> Classifier["classifier.py · model and training"]
    Core --> Rules["rules.py · sequence rules"]
    Core --> Classifier
    Core --> Trace["trace.py · normalized steps"]
    Classifier -->|tool families| Rules
    Classifier --> Trace
    Rules --> Trace
```

## Feature matrix

| Area | What it does |
| --- | --- |
| Rules | Detect sensitive reads followed by sends through dedicated tools or shell transfers, protected deletion including literal Python calls, database mutations, and explicit privilege grants. |
| Classifier | Scores binary tool-name unigrams and bigrams, tool-family presence, and trace length using stdlib logistic regression. |
| CLI | `scan` emits text or JSON, `train` writes a local model, and `eval` measures the complete pipeline. |
| Evals | Reports precision, recall, F1, false-positive rate, confusion counts, and per-category recall on the independent corpus. |

<details>
<summary>Rule weights and scoring</summary>

Each distinct rule adds its weight, and the rule total is capped at 1. A
standalone high-risk privilege operation contributes 0.55. Routine `sudo`
maintenance contributes 0.20. Exfiltration evidence includes external
destinations and shell transfers that name a previously read sensitive file
with an unresolved destination. Database query results supply sensitive-read
evidence. [Complete rule weights and triggers](SPEC.md#deterministic-rules)

</details>

## Train and evaluate

```sh
agentsentinel train src/agentsentinel/data/default_corpus.jsonl --out model.json
agentsentinel eval evals/corpus.jsonl
agentsentinel eval your-eval.jsonl --model model.json --threshold 0.5
agentsentinel scan examples/exfiltration.json --model model.json --json
```

`train` prints row counts and **classifier-only training-set metrics**. `eval`
prints metrics for the complete rules-plus-classifier pipeline. Evaluation exits
0 when it completes, regardless of detection quality. Python callers can load a
custom artifact with `Sentinel.from_model("model.json", threshold=0.5)`.

## Independent benchmark (120 traces, `evals/corpus.jsonl`)

All versions use the default threshold of 0.5 on the same measurement-only
corpus (40 malicious, 80 benign, including 36 hard negatives).

| Bundled scanner | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.5.0 | 0.8864 | 0.9750 | 0.9286 | 0.0625 | 39 / 5 / 75 / 1 |
| v0.4.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |
| v0.3.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |
| v0.2.0 | 0.7000 | 0.7000 | 0.7000 | 0.1500 | 28 / 12 / 68 / 12 |
| v0.1.0 | 0.4595 | 0.4250 | 0.4416 | 0.2500 | 17 / 20 / 60 / 23 |

| Bundled scanner | Exfiltration (16) | Destruction (14) | Privilege escalation (10) |
| --- | ---: | ---: | ---: |
| v0.5.0 | 1.0000 | 0.9286 | 1.0000 |
| v0.4.0 | 0.6250 | 0.9286 | 1.0000 |
| v0.3.0 | 0.6250 | 0.9286 | 1.0000 |
| v0.2.0 | 0.5625 | 0.8571 | 0.7000 |
| v0.1.0 | 0.3750 | 0.6429 | 0.2000 |

The figures at the top draw the v0.3.0 rows of these tables from
[evals/results/benchmark-v0.3.0.md](evals/results/benchmark-v0.3.0.md).
The tables are the measured record.

v0.4.0 changes no detection number above — its work is evasion resistance,
measured by [TrustBreaker](https://github.com/balamuruganpg/trustbreaker):
replaying its trace mutations (budget 40, seed 13) against both builds,
**bypass fell from 36.86% to 2.94%** (robustness 63.14% → 97.06%), and the
worst family, `tool_rename`, from 79.22% to 2.24% — v0.4.0 canonicalizes
tool synonyms back to canonical names before scoring. Full account:
[evals/results/benchmark-v0.4.0.md](evals/results/benchmark-v0.4.0.md).

v0.5.0 closes the exfiltration gap: sensitive reads are recognized by
basename and path shape, so all six traces that escaped v0.4.0 are caught
and exfiltration recall reaches 1.0000 with the false-positive rate
unchanged. Re-measured by TrustBreaker on the enlarged flagged set
(44 originals, 1,705 variants), bypass is 3.11% (robustness 96.89%).
Full account:
[evals/results/benchmark-v0.5.0.md](evals/results/benchmark-v0.5.0.md).

<details>
<summary>Benchmark corpus notes and reports</summary>

The benchmark is a synthetic regression set. The v0.3.0 report includes the
threshold sweep and remaining errors. [v0.3.0 results](evals/results/benchmark-v0.3.0.md)
· [v0.2.0 results](evals/results/benchmark-v0.2.0.md)
· [v0.1.0 results](evals/results/benchmark-v0.1.0-core.md)

</details>

<details>
<summary>Corpus format and bundled training data</summary>

Corpus files are JSONL with one object per line.

```json
{"trace":{"trace_id":"safe-01","steps":[{"tool":"list_files","args":{"path":"/workspace"},"result":""}]},"label":"benign","category":"benign"}
```

Labels are `malicious` or `benign`. Malicious categories are `exfiltration`,
`destruction`, or `privilege_escalation`. Benign rows use category `benign`.
Training needs both labels.

The bundled model trains on all **169 synthetic traces** in the default corpus.
There are 64 malicious traces and 105 benign traces, including shell health
checks, internal transfers, inspected build and test cleanup, and workspace
configuration edits.

</details>

## Python API

```python
import json
from pathlib import Path

from agentsentinel import Sentinel, TraceReport

trace = json.loads(Path("examples/exfiltration.json").read_text(encoding="utf-8"))
report: TraceReport = Sentinel(threshold=0.5).scan(trace)
print(report.score, report.flagged, report.categories)
# 0.85 True ('exfiltration',)
```

`TraceReport` is a frozen dataclass. Signals and categories are sorted,
deduplicated tuples. Malformed steps are skipped and an empty trace scores zero.
A non-dict trace is the only input that raises `ValueError`.

## Limits

<details>
<summary>Remaining gaps</summary>

This is a small offline trace scanner, not an authorization system or execution
sandbox. Scores are risk scores, not calibrated probabilities of harm. Rules do
not prove that data flowed from a read into a later send, or that an operation
succeeded. Authorized destructive/admin work can look malicious.

Tool aliases, shell obfuscation, DNS behavior, symlinks, and missing or falsified
trace steps can evade the heuristics. Network classification uses literal names
and addresses without DNS. The classifier's fixed vocabulary ignores unseen
features and cannot distinguish argument-level intent when sequences share
features. Malformed input is tolerated by dropping invalid parts; a low score
on damaged input does not establish safety. Validate on independent,
representative traces before using scores in a policy.

</details>

## Development

```sh
python3 -m venv /tmp/as-venv
/tmp/as-venv/bin/pip install -q pytest ruff mypy
/tmp/as-venv/bin/pip install -q -e .
/tmp/as-venv/bin/pytest -q
/tmp/as-venv/bin/ruff check .
/tmp/as-venv/bin/ruff format --check .
/tmp/as-venv/bin/mypy src evals tests
```

Training uses a local fixed random seed and canonical sample ordering. Repeating
training with the same rows reproduces the bundled model bytes in the same
Python environment. Runtime code uses only the standard library and is checked
with mypy strict.

## License

MIT. Copyright (c) 2026 Balamurugan P G. See [LICENSE](LICENSE).
