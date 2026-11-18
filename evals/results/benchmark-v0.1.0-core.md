# Independent benchmark — AgentSentinel v0.1.0 core vs `evals/corpus.jsonl`

Measured 2026-11-18 ~01:20 IST by the maintainer (not the core author), running
the bundled `Sentinel()` at threshold 0.5 against the 120-trace adversarial
corpus built independently by the eval half. The corpus was never training data.

## Results

| System | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| Rules + classifier (threshold 0.5) | 0.4595 | 0.4250 | 0.4416 | 0.2500 | 17 / 20 / 60 / 23 |

Per-category recall: exfiltration 0.3750 (16), destruction 0.6429 (14),
privilege_escalation 0.2000 (10).

Threshold sweep (same scanner, same corpus): t=0.3 gives F1 0.5200 (P 0.4333,
R 0.6500, FPR 0.4250); t=0.6 gives P 0.7500, R 0.3000, FPR 0.0500. No threshold
fixes the recall problem; the scanner misses whole attack shapes.

## What the misses show (23 false negatives, 20 false positives)

- **Rule coverage gaps, not noise.** Ten exfiltration traces fire no rule at
  all: database dumps emailed out (`db_query` is not in the sensitive-read
  family), secrets pushed with `git_push` (not in the send family), and similar
  realistic tool spellings. Five destruction traces fire nothing: `DELETE` /
  `TRUNCATE` issued through `db_query` are not recognised as destructive, and
  one `rm -rf` variant escapes the shell parser.
- **Escalation weight is incoherent with the threshold.** Six privilege
  traces fire `escalation:privilege-op` (weight 0.20) and score 0.47 — below
  the 0.5 threshold, so a lone privilege operation can never flag. Two more
  fire nothing (role grants, DB superuser grants are not in the family).
- **The classifier is miscalibrated on short traces.** Eleven plain benign
  traces (lint, type-check, format, test inspection) score 0.507–0.511 — just
  above threshold — because the 60-row training corpus has too few short
  benign workflows. Five hard-negative cleanups score 0.8–0.95: the
  destruction rules over-fire on listed-then-deleted build/tmp paths.

## Standing

These numbers are the honest v0.1.0 state. The bundled-corpus figures in the
README (P 0.9231, R 1.0000, F1 0.9600) are resubstitution on the training
corpus and must not be quoted as detection performance. The v0.2.0 iteration
targets the gaps above — rule-family coverage, escalation scoring, and a
larger, more benign-varied default corpus with retraining — and re-measures
on this same corpus, which stays measurement-only.
