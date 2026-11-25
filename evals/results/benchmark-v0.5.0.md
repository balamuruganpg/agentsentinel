# AgentSentinel v0.5.0 independent benchmark

The bundled scanner was evaluated on the unchanged `evals/corpus.jsonl`
(120 synthetic traces: 40 malicious, 80 benign, including 36 hard
negatives). v0.5.0 extends the exfiltration rules with sensitive-source
recognition by basename and path shape — kubeconfig, browser cookie
stores, payroll exports, npm and PostgreSQL credential files, and TLS
private keys under generic filenames — while generic config files, debug
logs, package manifests, SQL dumps, and certificates stay ordinary. The
default cutoff stayed at 0.5; the classifier was not refit.

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.4.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |
| v0.5.0 | 0.8864 | 0.9750 | 0.9286 | 0.0625 | 39 / 5 / 75 / 1 |

| Ground-truth category | Support | v0.5.0 recall |
| --- | ---: | ---: |
| Exfiltration | 16 | 1.0000 (16/16) |
| Destruction | 14 | 0.9286 (13/14) |
| Privilege escalation | 10 | 1.0000 (10/10) |

All six exfiltration traces that v0.3.0/v0.4.0 missed are now caught, and
no benign trace changed verdict: the false-positive count is identical
(5/80). The one remaining false negative is the production configuration
overwrite, unchanged since v0.3.0.

## Evasion measurement (TrustBreaker)

[TrustBreaker](https://github.com/balamuruganpg/trustbreaker) mutates the
traces this scanner flags (budget 40 variants per trace, seed 13, UCB1
over trace-operator pipelines) and counts how many mutations stop being
flagged. The v0.5.0 run was executed twice with byte-identical aggregates.

| Scanner | Flagged originals | Applicable variants | Bypasses | Bypass rate | Robustness |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.3.0 | 38 | 1,465 | 540 | 36.86% | 63.14% |
| v0.4.0 | 38 | 1,465 | 43 | 2.94% | 97.06% |
| v0.5.0 | 44 | 1,705 | 53 | 3.11% | 96.89% |

The bypass rate is a fraction of a larger base: v0.5.0 flags six more
originals (the recovered exfiltration traces), so more variants are
applicable. Per-operator bypass on this build concentrates in
`reorder_independent` (6.08%) and `arg_split` (5.43%); `tool_rename`
stays closed at 2.57%. Aggregates are recorded in TrustBreaker's
`benchmarks/agentsentinel-v050-mutation-summary.json`.

## Remaining errors at 0.5

One false negative: the production configuration overwrite (destruction),
unchanged since v0.3.0. Five false positives, the same benign traces as
v0.4.0.
