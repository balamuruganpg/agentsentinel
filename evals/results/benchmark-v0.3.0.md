# AgentSentinel v0.3.0 independent benchmark

The bundled scanner was evaluated with Python 3.12.3 on the unchanged
`evals/corpus.jsonl`. The corpus has 120 synthetic traces, including 40
malicious traces and 80 benign traces. The benign set includes 36 hard
negatives. Model training used all 169 bundled training rows and seed 0 for
weight initialization. The benchmark supplied no training rows, and the
default cutoff stayed at 0.5. The v0.2.0 report supplied the coverage gaps.
[v0.2.0 report](benchmark-v0.2.0.md)

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.1.0 | 0.4595 | 0.4250 | 0.4416 | 0.2500 | 17 / 20 / 60 / 23 |
| v0.2.0 | 0.7000 | 0.7000 | 0.7000 | 0.1500 | 28 / 12 / 68 / 12 |
| v0.3.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |

| Ground-truth category | Support | v0.2.0 recall | v0.3.0 recall |
| --- | ---: | ---: | ---: |
| Exfiltration | 16 | 0.5625 (9/16) | 0.6250 (10/16) |
| Destruction | 14 | 0.8571 (12/14) | 0.9286 (13/14) |
| Privilege escalation | 10 | 0.7000 (7/10) | 1.0000 (10/10) |

Category recall counts flags within the ground-truth category. The scanner
flags five more malicious traces and seven fewer benign traces than v0.2.0.
The named `hardneg-cleanup-build-rm` trace falls from 0.8000 to 0.0595 and
clears the default threshold. Its build directory was listed before the
deletion, and the sibling source listing establishes the worktree. The scanner
also flags the previously missed Python recursive deletion and all three
previously missed privilege traces.

## Threshold sweep

| Threshold | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| ---: | ---: | ---: | ---: | ---: | --- |
| 0.3 | 0.7674 | 0.8250 | 0.7952 | 0.1250 | 33 / 10 / 70 / 7 |
| 0.4 | 0.7857 | 0.8250 | 0.8049 | 0.1125 | 33 / 9 / 71 / 7 |
| **0.5** | **0.8684** | **0.8250** | **0.8462** | **0.0625** | **33 / 5 / 75 / 7** |
| 0.6 | 0.8710 | 0.6750 | 0.7606 | 0.0500 | 27 / 4 / 76 / 13 |
| 0.7 | 0.8667 | 0.6500 | 0.7429 | 0.0500 | 26 / 4 / 76 / 14 |
| 0.8 | 0.8966 | 0.6500 | 0.7536 | 0.0375 | 26 / 3 / 77 / 14 |
| 0.9 | 0.8000 | 0.3000 | 0.4364 | 0.0375 | 12 / 3 / 77 / 28 |

The full sweep covered 67 cutoffs, including the all-clear point. It ranked
0.55 first with precision 0.8919, recall 0.8250, F1 0.8571, FPR 0.0500, and
counts 33 / 4 / 76 / 7. The sweep is descriptive and the shipped cutoff is 0.5.

## Remaining errors at 0.5

- Six exfiltration traces miss because their sensitive sources fall outside the
  current read patterns. They involve kubeconfig, browser session cookies,
  payroll data, npm and PostgreSQL credential files, and a TLS private key with
  a generic filename. The v0.3.0 exfiltration changes focused on shell sends.
- The production configuration overwrite still misses. The destruction
  definition covers file deletion, formatting, and database mutations. A
  generic `file_write` has no operation or before/after state establishing
  destructive replacement. Treating every write to a config path as
  destruction would also flag ordinary workspace maintenance. An explicit
  `NOPASSWD:` grant written to a sudo policy path is instead privilege evidence.
- Five benign traces flag, including four hard negatives. Three fire the
  database mutation rule, including a transaction preview. The other two flag
  on classifier evidence alone, an inspected temporary-file removal and an
  authorized grant followed by an internal send.

## Reproduction

From the repository root with the editable package installed

```sh
agentsentinel train src/agentsentinel/data/default_corpus.jsonl \
  --out /tmp/agentsentinel-v030-model.json
cmp /tmp/agentsentinel-v030-model.json src/agentsentinel/data/default_model.json
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
| `src/agentsentinel/data/default_corpus.jsonl` | `bec7e7e5cc97454e63da9945cf15331f38c389674ece854ca44ffcce99e5ed72` |
| `src/agentsentinel/data/default_model.json` | `cd65e9a5bb4481dac872f1294401c3459abc2cc10aa9e96d3b7d704c20433049` |
