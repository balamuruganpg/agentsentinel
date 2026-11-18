# AgentSentinel v0.2.0 independent benchmark

The bundled rules and classifier were evaluated with Python 3.12.3 on the
unchanged `evals/corpus.jsonl`. It contains 120 synthetic traces, including 40
malicious traces, 80 benign traces, and 36 hard negatives within the benign set.
The benchmark supplied no training rows and did not select the cutoff. The
v0.1.0 miss analysis informed the coverage changes. [v0.1.0 report](benchmark-v0.1.0-core.md)

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.1.0 | 0.4595 | 0.4250 | 0.4416 | 0.2500 | 17 / 20 / 60 / 23 |
| v0.2.0 | 0.7000 | 0.7000 | 0.7000 | 0.1500 | 28 / 12 / 68 / 12 |

| Category | Support | v0.1.0 recall | v0.2.0 recall |
| --- | ---: | ---: | ---: |
| Exfiltration | 16 | 0.3750 (6/16) | 0.5625 (9/16) |
| Destruction | 14 | 0.6429 (9/14) | 0.8571 (12/14) |
| Privilege escalation | 10 | 0.2000 (2/10) | 0.7000 (7/10) |

Category recall counts flagged traces within each ground-truth category. At
0.5 the revised scanner catches 11 additional malicious traces and flags 8
fewer benign traces overall.

## Threshold sweep

| Threshold | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| ---: | ---: | ---: | ---: | ---: | --- |
| 0.3 | 0.5833 | 0.7000 | 0.6364 | 0.2500 | 28 / 20 / 60 / 12 |
| 0.4 | 0.6364 | 0.7000 | 0.6667 | 0.2000 | 28 / 16 / 64 / 12 |
| **0.5** | **0.7000** | **0.7000** | **0.7000** | **0.1500** | **28 / 12 / 68 / 12** |
| 0.6 | 0.6970 | 0.5750 | 0.6301 | 0.1250 | 23 / 10 / 70 / 17 |
| 0.7 | 0.7667 | 0.5750 | 0.6571 | 0.0875 | 23 / 7 / 73 / 17 |
| 0.8 | 0.7667 | 0.5750 | 0.6571 | 0.0875 | 23 / 7 / 73 / 17 |
| 0.9 | 0.7778 | 0.3500 | 0.4828 | 0.0500 | 14 / 4 / 76 / 26 |

The full sweep covered 68 cutoffs, including the all-clear operating point.
The harness ranked 0.55 first under its tie-break rules. At 0.55 the scanner
flags the same traces as at 0.5, which remains the default.

## Remaining errors at 0.5

- Seven exfiltration traces still miss. They include shell transfers, sensitive
  sources outside the identifier patterns, and send tools outside the recognized
  family.
- Two destruction traces miss. They involve a recursive deletion expressed as
  Python code and overwriting an active configuration file.
- Three privilege escalation traces miss. The IAM owner change and one sudo
  group change fire no rule. A sudo-policy change receives the routine admin
  weight of 0.20.
- Twelve benign traces flag, including nine hard negatives. Five cross the cutoff
  on rule evidence. Three are benign database mutations, including a transaction
  preview, and two are absolute build cleanups outside known scratch roots with
  no `cwd` on the deletion step. Seven cross the cutoff on classifier evidence
  alone, including internal backups and additional inspected cleanups.

## Reproduction

From the repository root with the editable package installed

```sh
agentsentinel eval evals/corpus.jsonl
python - <<'PY'
from agentsentinel import Sentinel
from evals.benchmark import format_report, load_corpus, sweep_thresholds

rows = load_corpus()
scanner = Sentinel()
grid = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)
for result in sweep_thresholds(scanner, rows, grid).results:
    print(format_report(result))
print(format_report(sweep_thresholds(scanner, rows).best))
PY
```

| Input | SHA-256 |
| --- | --- |
| `evals/corpus.jsonl` | `f916a47af4104661b83ed1fc82add1b6c7ce289e201d5770ec93230963784a2e` |
| `src/agentsentinel/data/default_corpus.jsonl` | `6834e4838f73110dfae43ca10c0f5120489fe5e5563a34e85da2882de820ada0` |
| `src/agentsentinel/data/default_model.json` | `a3cccfb3c34199e153a6ebef70e223092accf6216659ba09052f641680e96f9a` |
