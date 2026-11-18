# Changelog

## 0.4.0

- Canonicalize known tool synonyms in normalized trace steps before applying
  rules or extracting classifier features.
- Refit the bundled classifier on the same 169 synthetic training traces
  with tool-name canonicalization in the pipeline.

## 0.3.0

- Recognize outbound shell transfers after a sensitive read and literal Python
  file and directory removals.
- Recognize explicit cloud owner grants, privileged group changes, and sudo
  policy writes. Keep ordinary configuration writes outside destruction rules.
- Use working directory and source-tree evidence to distinguish inspected
  build and temp cleanup from protected deletion.
- Expand bundled training to 169 synthetic traces and rebuild the default
  model from the bundled corpus with seed 0.
- Raise independent benchmark F1 from 0.7000 to 0.8462 and lower FPR from 0.1500
  to 0.0625 at the unchanged 0.5 threshold.

## 0.2.0

- Recognize sensitive database reads and query results, external Git pushes,
  destructive SQL statements, and role, permission, and database superuser grants.
- Extend shell `rm` parsing and count directory listings as earlier inspection.
  Recognize workspace-relative build and temp paths as scratch targets.
- Give high-risk standalone privilege operations weight 0.55 and retain weight
  0.20 for routine admin operations. Keep the default threshold at 0.5.
- Expand bundled training to 110 synthetic traces and rebuild the default model.
- Raise F1 from 0.4416 to 0.7000 and lower FPR from 0.2500 to 0.1500 at the
  default threshold on the independent 120-trace corpus.

## 0.1.0 — 2026-11-17

- Add tolerant trace normalization and the frozen `TraceReport` public API.
- Detect sensitive-read/external-send, protected destruction, and privilege
  operation sequences with six stable weighted rule signals.
- Add deterministic stdlib logistic regression over tool sequence features,
  JSON model artifacts, and an offline bundled 60-trace corpus and trained model.
- Provide scan, train, and eval commands through the console script and module.
- Document measured training-corpus results, classifier limitations, and the
  fixed public contract; add rule, robustness, model, and CLI tests.
