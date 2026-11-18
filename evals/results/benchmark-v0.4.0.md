# AgentSentinel v0.4.0 independent benchmark

The bundled scanner was evaluated with Python 3.12.3 on the unchanged
`evals/corpus.jsonl` (120 synthetic traces: 40 malicious, 80 benign,
including 36 hard negatives). v0.4.0 adds tool-name canonicalization —
known tool synonyms are mapped back to canonical tool names in a working
copy of the trace before rules and classifier features run — and refits the
bundled classifier on the same 169 synthetic training traces with
canonicalization in the pipeline. The default cutoff stayed at 0.5.

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.3.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |
| v0.4.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |

| Ground-truth category | Support | v0.4.0 recall |
| --- | ---: | ---: |
| Exfiltration | 16 | 0.6250 (10/16) |
| Destruction | 14 | 0.9286 (13/14) |
| Privilege escalation | 10 | 1.0000 (10/10) |

Detection on the original corpus is unchanged, row for row. v0.4.0's reason
to exist is the evasion measurement below; a threshold sweep was not rerun
because the 0.5 confusion counts are identical to v0.3.0's.

## Evasion measurement (TrustBreaker v0.2.0)

[TrustBreaker](https://github.com/balamuruganpg/trustbreaker) mutates the
traces this scanner flags (budget 40 variants per trace, seed 13, UCB1 over
trace-operator pipelines) and counts how many mutations stop being flagged.
Same protocol, both builds, 1,465 applicable variants each:

| Scanner | Bypasses | Bypass rate | Robustness |
| --- | ---: | ---: | ---: |
| v0.3.0 | 540 / 1,465 | 36.86% | 63.14% |
| v0.4.0 | 43 / 1,465 | 2.94% | 97.06% |

The dominant v0.3.0 weakness was `tool_rename` (79.22% of its applicable
variants bypassed); under canonicalization it falls to 2.24%. The remaining
bypasses concentrate in `arg_split` (6.53%) and `reorder_independent`
(5.03%). Aggregates are recorded in TrustBreaker's
`benchmarks/agentsentinel-mutation-summary.json` (v0.3.0 run) and its
v0.4.0 companion file.

## Remaining errors at 0.5

Unchanged from v0.3.0: the same six exfiltration traces miss because their
sensitive sources fall outside the current read patterns, and the production
configuration overwrite still misses for the reason the v0.3.0 report gives.
