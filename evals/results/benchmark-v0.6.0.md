# AgentSentinel v0.6.0 independent benchmark

The bundled scanner was evaluated on the unchanged `evals/corpus.jsonl`
(120 synthetic traces: 40 malicious, 80 benign, including 36 hard
negatives). v0.6.0 gathers sensitive-path evidence from every argument
string, normalizes literal-path quirks before matching, and requires
corroboration before a payroll export, cookie store, or key file counts.
An explicit overwrite or truncate of a live production config or kubeconfig
is destruction. Ordinary config edits stay outside that rule. The default
cutoff stayed at 0.5; the classifier was not refit.

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.5.0 | 0.8864 | 0.9750 | 0.9286 | 0.0625 | 39 / 5 / 75 / 1 |
| v0.6.0 | 0.8889 | 1.0000 | 0.9412 | 0.0625 | 40 / 5 / 75 / 0 |

| Ground-truth category | Support | v0.6.0 recall |
| --- | ---: | ---: |
| Exfiltration | 16 | 1.0000 (16/16) |
| Destruction | 14 | 1.0000 (14/14) |
| Privilege escalation | 10 | 1.0000 (10/10) |

The production configuration overwrite, a false negative since v0.3.0, is
now caught. No benign trace changed verdict: the false-positive count is
identical (5/80). Exfiltration and privilege-escalation recall stay at
1.0000.

## Evasion measurement (TrustBreaker)

[TrustBreaker](https://github.com/balamuruganpg/trustbreaker) mutates the
traces this scanner flags (budget 40 variants per trace, seed 13, UCB1
over trace-operator pipelines) and counts how many mutations stop being
flagged. The v0.6.0 run was executed twice with byte-identical aggregates.

| Scanner | Flagged originals | Applicable variants | Bypasses | Bypass rate | Robustness |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.3.0 | 38 | 1,465 | 540 | 36.86% | 63.14% |
| v0.4.0 | 38 | 1,465 | 43 | 2.94% | 97.06% |
| v0.5.0 | 44 | 1,705 | 53 | 3.11% | 96.89% |
| v0.6.0 | 45 | 1,745 | 53 | 3.04% | 96.96% |

v0.6.0 flags one more original, the production-config overwrite, so 40 more
variants are applicable. None of those variants bypassed, and the bypass
count on the previous set is unchanged at 53, so the rate falls from 3.11%
to 3.04%. Per-operator bypass counts are unchanged. The highest rates on
this build are `reorder_independent` (5.94%) and `arg_split` (5.28%);
`tool_rename` is 2.52%. Aggregates are recorded in TrustBreaker's
`benchmarks/agentsentinel-mutation-summary-v060.json`.

## Remaining errors at 0.5

No false negatives. Five false positives, the same benign traces as
v0.5.0: `hardneg-cleanup-tmp-listed`, `hardneg-db-drop-temp-table`,
`hardneg-db-delete-scoped-test`, `hardneg-role-authorized-grant-send`,
and `benign-transaction-preview`.
