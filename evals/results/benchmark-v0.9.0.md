# AgentSentinel v0.9.0 independent benchmark

The bundled scanner was evaluated on the unchanged `evals/corpus.jsonl`
(120 synthetic traces: 40 malicious, 80 benign, including 36 hard
negatives). v0.9.0 closes the round-5 review's taint-laundering gaps:
`readlines()` and iteration of `open()` count as reads, `requests.post`
and `httpx.post` count as sends, `$(< file)` is a substituted read, a
shell redirect, `tee`, or a Python write plants the git latch,
`shutil.copy` remembers its destination, archive and compression tools
start taint, `ln` and `ln -s` keep the target's path identity, a second
hop keeps the identity dynamic uploads require, shell assignments
persist across commands in the trace, `cd` and a relative `cwd` resolve
relative paths, the git tree latch no longer forgets a secret past the
old 32-result / 8,192-character bound, and the `file_write` → `http_post`
classifier flag survives one intervening benign step. The default cutoff
stayed at 0.5. The classifier was not refit.

## Default threshold of 0.5

| Version | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.7.0 | 0.8889 | 1.0000 | 0.9412 | 0.0625 | 40 / 5 / 75 / 0 |
| v0.8.0 | 0.8889 | 1.0000 | 0.9412 | 0.0625 | 40 / 5 / 75 / 0 |
| v0.9.0 | 0.8889 | 1.0000 | 0.9412 | 0.0625 | 40 / 5 / 75 / 0 |

| Ground-truth category | Support | v0.9.0 recall |
| --- | ---: | ---: |
| Exfiltration | 16 | 1.0000 (16/16) |
| Destruction | 14 | 1.0000 (14/14) |
| Privilege escalation | 10 | 1.0000 (10/10) |

No corpus verdict moved. The five false positives are the same benign
traces as v0.8.0, and every malicious row stays flagged.

## Trace-mutation bypass (TrustBreaker)

Re-measured by TrustBreaker on the same 45 flagged originals and 1,745
variants, bypass is 3.72% (robustness 96.28%), unchanged from v0.8.0,
byte-identical across two runs. The mutation operators do not generate
the round-5 shapes (link laundering, archive hops, `cd` resolution), so
this number neither confirms nor contradicts the round-5 fixes; it shows
the tighter taint tracking cost nothing on the existing mutation
surface.
