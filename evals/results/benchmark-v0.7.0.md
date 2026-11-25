# AgentSentinel v0.7.0 independent benchmark

The bundled scanner was evaluated on the unchanged `evals/corpus.jsonl`
(120 synthetic traces: 40 malicious, 80 benign, including 36 hard
negatives). v0.7.0 treats a shell read of a sensitive path as a sensitive
read, resolves tool families beyond the alias map, judges a send against
the sensitive reads that precede it in its own flow, joins path pieces only
when they are one path, and does not let result text grant or erase
payroll, cookie, or `.key` sensitivity. Ordinary project config edits are
not destruction. Empty writes and protected locations still are. Path
decoding runs to a fixed point before `normpath`. The default cutoff stayed
at 0.5. The classifier was not refit.

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.5.0 | 0.8864 | 0.9750 | 0.9286 | 0.0625 | 39 / 5 / 75 / 1 |
| v0.6.0 | 0.8889 | 1.0000 | 0.9412 | 0.0625 | 40 / 5 / 75 / 0 |
| v0.7.0 | 0.8889 | 1.0000 | 0.9412 | 0.0625 | 40 / 5 / 75 / 0 |

| Ground-truth category | Support | v0.7.0 recall |
| --- | ---: | ---: |
| Exfiltration | 16 | 1.0000 (16/16) |
| Destruction | 14 | 1.0000 (14/14) |
| Privilege escalation | 10 | 1.0000 (10/10) |

No corpus verdict moved. The five false positives are the same benign
traces as v0.6.0, and every malicious row stays flagged.

## Evasion measurement (TrustBreaker)

[TrustBreaker](https://github.com/balamuruganpg/trustbreaker) mutates the
traces this scanner flags (budget 40 variants per trace, seed 13, UCB1
over trace-operator pipelines) and counts how many mutations stop being
flagged. The v0.7.0 run was executed twice with byte-identical aggregates.
The search adapts to which mutations bypass, so per-operator applicable
counts are not a frozen replay of the v0.6.0 variant list. The protocol is
the same.

| Scanner | Flagged originals | Applicable variants | Bypasses | Bypass rate | Robustness |
| --- | ---: | ---: | ---: | ---: | ---: |
| v0.3.0 | 38 | 1,465 | 540 | 36.86% | 63.14% |
| v0.4.0 | 38 | 1,465 | 43 | 2.94% | 97.06% |
| v0.5.0 | 44 | 1,705 | 53 | 3.11% | 96.89% |
| v0.6.0 | 45 | 1,745 | 53 | 3.04% | 96.96% |
| v0.7.0 | 45 | 1,745 | 67 | 3.84% | 96.16% |

v0.7.0 flags the same 45 originals. Fourteen more of the 1,745 applicable
variants bypass, so the rate rises from 3.04% to 3.84% (robustness 96.96%
to 96.16%). The increase sits in the operators the tighter rules change:

| Operator | v0.6.0 applicable / bypasses | v0.7.0 applicable / bypasses | v0.7.0 rate |
| --- | ---: | ---: | ---: |
| `reorder_independent` | 673 / 40 | 675 / 52 | 7.70% |
| `arg_split` | 568 / 30 | 568 / 39 | 6.87% |
| `path_obscure` | 622 / 16 | 625 / 22 | 3.52% |
| `tool_rename` | 635 / 16 | 635 / 20 | 3.15% |
| `result_pad` | 767 / 17 | 768 / 22 | 2.86% |
| `noise_insert` | 924 / 10 | 921 / 12 | 1.30% |

`reorder_independent` and `arg_split` account for most of the new bypasses.
Per-flow ordering no longer keeps a `git_push` tainted across ordinary repo
work, and path evidence no longer joins unrelated argument strings, so
mutations that relied on the old latch or the old cross-argument join can
clear. Aggregates are recorded in TrustBreaker's
`benchmarks/agentsentinel-mutation-summary-v070.json`.

## Remaining errors at 0.5

No false negatives. Five false positives, the same benign traces as
v0.6.0: `hardneg-cleanup-tmp-listed`, `hardneg-db-drop-temp-table`,
`hardneg-db-delete-scoped-test`, `hardneg-role-authorized-grant-send`,
and `benign-transaction-preview`.

## What this release does not close

One-step transfers the shell parser does not treat as sends
(`urllib.request.urlopen`, `mail`, `openssl s_client`) stay clear.
An explicit public-key or certificate block can still classify an
ambiguous `.pem` as a certificate; an empty or redacted `.pem` stays
sensitive. `%2f..` still collapses the way `normpath` collapses `../`.
A trailing `/..` names the parent. Kubeconfig suffixes outside
`yml`, `yaml`, `json`, `bak`, and `old` do not match. Taint does not
cross `scan()` calls. A dedicated send that precedes every sensitive
read stays clear of the exfiltration rule. The classifier was not refit,
so `exec` followed by `http_post` can still score above 0.5 on an
innocent command. A path whose basename is `license.key` still matches
the `.key` rule. A non-empty edit of a project path that normalizes out
of a sample tree is an ordinary edit; an empty write of that path still
flags.
