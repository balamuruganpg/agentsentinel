# Changelog

## 0.8.0

- Share one shell lexer between the reader and the transfer parser. A
  backslash is a bash escape, not a blanket fold to `/`. Windows
  drive-letter paths are folded before the lexer. Literal `NAME=value`
  bindings, backticks, and process substitutions are read forms. One
  unmatched quote is repaired (at most eight drops, then the remaining
  quotes are stripped) so the rest of the script is still analyzed. A
  nested `bash -c` or `sh -c` is opened, at most eight levels.
- Count indirect Python reads: a name bound to `open` or `Path`,
  `getattr` of `read` / `read_text` / `read_bytes`, `io.open` and
  `FileIO`, `os.open` with `os.read`, string concatenation, a `python`
  heredoc, and `shutil.copy` / `copy2` / `copyfile` of a real file.
  `file://` `urlopen` is a read.
- Treat a local `cp`, `mv`, `install`, or `rsync` of a sensitive source
  as a read. The staged path is an identity in that same step, so a
  dynamic upload of it matches.
- Keep a tree latch when a sensitive result is written or copied outside
  `/tmp` and `/var/tmp`. The latch never clears. An external `git_push`,
  including a shell `git push` of a literal external URL, stays tainted
  after `git status`, a README read, or `pytest`. Ordinary repo work
  that never plants the secret still clears the git flow. A shell
  `git push` is not a content sink.
- Treat `urllib.request.urlopen`, `mail`, and `openssl s_client` as
  sends that honor a sensitive read already in the trace, including the
  same command. `openssl` counts only with subcommand `s_client`.
- Join path pieces in source order inside one field, and pair a
  directory-role field with a filename or a single-segment path only
  inside the same object. A whitespace or over-long sibling is skipped
  instead of cancelling the field. Sibling objects do not cross.
- Match a legacy secret word only as the whole field or as the last
  identifier of a path segment. `.env` filenames match except the
  template suffixes `example`, `sample`, `template`, and `dist`.
  `env pytest` is a wrapper, not a dump. `printenv` with no command is
  still a dump. The classifier read-family check is unchanged.
- Treat every non-location, non-metadata string as a write body, so a
  project edit under `contents` or `source` is not a truncate. An empty
  body, an absent body, and a protected location still are.
- At prediction time, score a benign stored tool `exec` as `shell`. A
  risky `exec` keeps `tool:exec`. The model was not refit.
- Decode a path to a fixed point, at most `min(len(value), 64)` passes,
  then run `normpath` once. Nine layers of `%25` before `2E` resolve.
- The classifier was not refit. The independent benchmark is unchanged:
  precision 0.8889, recall 1.0000, F1 0.9412, FPR 0.0625, TP=40 FP=5
  TN=75 FN=0. Every family stays at 1.0000.
- TrustBreaker trace evasion re-measured twice with byte-identical
  aggregates: bypass 3.72%, robustness 96.28% (v0.7.0: 3.84% / 96.16% on
  the same 45 flagged originals and 1,745 applicable variants; 65 bypasses
  instead of 67).

## 0.7.0

- Treat a shell command that reads a sensitive path as a sensitive read, with
  the same downstream taint as a read tool. Readers include `cat`, `head`,
  `tail`, `type`, `Get-Content`, `less`, `more`, `od`, `xxd`, `base64`,
  `dd if=`, `sed -n`, `awk`, `nl`, `strings`, `bat`, input redirects, command
  and process substitution, and literal Python `open().read()` /
  `Path.read_text()`. Wrappers (`sudo`, `command`, `env`, `busybox`, `nice`,
  `nohup`, `time`, `ionice`) are peeled. Command text is also read from
  `input` and `cmdline`. The read-family classifier feature is unchanged.
- Resolve tool families for names outside the alias map: camelCase, a
  trailing version segment, `__` and hyphen folding, and an evident action
  class (`readfile`, `open_file`, `http_put`, `fetch`, `send_email`,
  `run_terminal_cmd`, and the other names in `SPEC.md`). The stored tool
  string still changes only through the exact alias map. Bare
  `open_document`, `webhook_call`, and `terminal_run` stay map-only.
- Judge each send against the sensitive reads that precede it in its own
  flow. Content sinks stay tainted for the rest of the scan. `git_push`
  taint clears when ordinary repo work intervenes. A shell command that both
  reads and transfers is judged in that step.
- Join argument strings into a path only inside one field, or as a declared
  directory field plus a filename field. Legacy secret tokens match non-prose
  field names and values, not prose and not a cross-field product.
- Stop letting result text grant or erase corroboration. Payroll and cookie
  stores are path decisions. A `.key` file is not cleared by a public-key
  result. A `.pem` stays sensitive unless the result is an explicit public
  key or certificate and not a private key. Strong export directories
  (`hr`, `payroll`, `compensation`, `salaries`, `confidential`, `export`)
  beat a later sample segment. `private` alone does not.
- Decode paths to a fixed point (at most eight passes of percent-decode,
  backslash folding, and the NUL cut) before `normpath`, so a double encoding
  or `%5c` / `%00` cannot undo an earlier pass.
- Scope live-config overwrites. A non-empty project `file_write` is an
  ordinary edit. Empty or absent content, and any write at a protected
  location (kubeconfig, `/etc`, a `live` segment, `/workspace`,
  `/workspaces`), still flags. `/workspace` stays scratch for deletion.
  `cp` / `mv` / `install` / `rsync` / `tee` flag protected destinations.
  `&>` is a truncate. `s/^$//` is not a wipe. Top-level `open(..., 'w')`
  and `open(...).close()` count; a nested function body does not.
- The classifier was not refit. One existing assertion changed:
  `test_shell_transfer_after_sensitive_read_flags` now expects a shell
  transfer of a sensitive file to flag on its own, because that command is
  the sensitive read.
- Independent benchmark unchanged: precision 0.8889, recall 1.0000,
  F1 0.9412, FPR 0.0625, TP=40 FP=5 TN=75 FN=0. Every family stays at 1.0000.
- TrustBreaker trace evasion re-measured twice with byte-identical
  aggregates: bypass 3.84%, robustness 96.16% (v0.6.0: 3.04% / 96.96% on
  the same 45 flagged originals and 1,745 applicable variants).

## 0.6.0

- Gather sensitive-path evidence from every argument string and from joined
  directory and filename pieces, then normalize the path before matching.
  Trailing whitespace and control characters, a NUL, backslashes,
  percent-encoding, and `$VAR`/`..` no longer hide a kubeconfig, npmrc, or
  pgpass path. Those families match the concept spelling, not only the
  corpus names.
- Require corroboration for payroll exports, cookie stores, and key files.
  A payroll module or document, a public demo table, a fixture cookie file,
  and a public key are not sensitive reads. A `.pem` counts when its body
  is a private key. A non-literal working directory no longer forgets the
  last absolute directory.
- Treat an explicit overwrite or truncate of a live production config or
  kubeconfig as destruction, including shell `>`, `truncate -s 0`, a
  null-device copy, a wiping `sed -i`, and top-level Python writes. Ordinary
  config edits stay outside the rule.
- The classifier was not refit.
- Independent benchmark: destruction recall 0.9286 -> 1.0000 (14/14),
  F1 0.9286 -> 0.9412, recall 0.9750 -> 1.0000, precision 0.8864 -> 0.8889,
  FPR unchanged at 0.0625. Exfiltration and privilege escalation stay at
  1.0000.
- TrustBreaker trace evasion re-measured on this build: bypass 3.04%,
  robustness 96.96% (v0.5.0: 3.11% / 96.89% on fewer flagged originals).

## 0.5.0

- Recognize sensitive reads by basename and path shape (kubeconfig, browser
  cookie stores, payroll exports, npm and PostgreSQL credential files, TLS
  private keys under generic filenames), so a sensitive read followed by an
  outbound transfer is caught even when the filename alone carried the
  signal. Generic config files, debug logs, package manifests, SQL dumps,
  and certificates stay ordinary — the false-positive rate does not move.
- Independent benchmark: exfiltration recall 0.6250 -> 1.0000 (16/16),
  F1 0.8462 -> 0.9286, recall 0.8250 -> 0.9750, FPR unchanged at 0.0625.
- TrustBreaker trace evasion re-measured on this build: bypass 3.11%,
  robustness 96.89% (v0.4.0: 2.94% / 97.06% on fewer flagged originals).

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
