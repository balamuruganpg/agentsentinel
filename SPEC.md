# AgentSentinel specification

The contract below describes the 0.8.0 scanner. Historical measurements stay
in the benchmark reports.

## Public contract

Python >= 3.11; standard library only at runtime. Public imports:

```python
from agentsentinel import Sentinel, TraceReport
```

A trace is a dict `{"trace_id": str, "steps": [step, ...]}`. Each step has a
string `tool`, optional dict `args` (default `{}`), and optional `result`.
`db_query` results can be strings or contain nested strings in objects or
lists. Structured result fields are used only by the database sensitive-read
rule. A file-read `result` string is not argument text and is not scanned for
paths. It cannot grant or erase payroll, cookie, or `.key` sensitivity. A
private-key block in the result confirms a key file, including a basename
that would otherwise look public. An explicit `PUBLIC KEY` or `CERTIFICATE`
block, with no private-key block, classifies an ambiguous `.pem` as a
certificate. An empty or redacted `.pem` result does not clear the path.
Trace IDs are ignored.

`Sentinel(threshold: float = 0.5)` rejects thresholds outside [0, 1], including
NaN and infinities, with `ValueError`. `scan(trace: dict) -> TraceReport` returns
a frozen dataclass with:

| Field | Meaning |
| --- | --- |
| `score: float` | Risk score in [0, 1] |
| `flagged: bool` | Exactly `score >= threshold` |
| `categories: tuple[str, ...]` | Sorted distinct rule categories: `exfiltration`, `destruction`, `privilege_escalation` |
| `signals: tuple[str, ...]` | Sorted distinct fired rule IDs and positive active feature IDs |

The binary classifier always abstains on category attribution, so categories are
empty when no rule fires, even if learned evidence flags the trace. A category
may appear on an unflagged trace when its rule evidence is below the threshold.

`scan` raises `ValueError` only when the trace argument itself is not a dict.
Missing/non-list/empty `steps`, non-dict steps, non-string or blank tool names,
and steps with non-dict `args` are ignored without raising. Optional missing
args are valid. Other valid steps still contribute evidence. If no valid steps
remain, score is 0.0, categories/signals are empty, and threshold 0 still flags
the trace.
Argument traversal is iterative and tolerates deeply nested JSON and cyclic
built-in Python containers. This is tolerance, not an assertion that malformed
input is safe.

Tool names are stripped, camelCase boundaries become underscores, and the
name is lowercased. An exact alias map then rewrites the stored tool string
that classifier unigrams use (`open_document` to `file_read`, `webhook_call`
to `http_post`, `terminal_run` to `shell`, plus `file.read`, `file.write`,
`file.delete`, `http.post`, `db.query`, `email.send`, and `list.dir`). Names
outside that map keep their stored string. Rule families are a separate
lookup and do not rewrite the stored name. A recognized legacy family (the
last two dotted segments via the dotted alias map, otherwise the last
segment) is kept, so `chmod`, `list_files`, `git.push`, and `http.post` stay
themselves. Otherwise the name is folded (`__` to `.`, hyphens to
underscores, a trailing `vN` segment dropped) and matched against the alias
map, an evident action (`readfile`, `read_files`, `open_file`,
`webhook_callback`, `http_put`, `http_post_json`, `fetch`, `send_email`,
`file_upload`, `run_terminal_cmd`, `execute_command`, `shell_exec`,
`bash_command`, `terminal`, `powershell`), an `fs` / `filesystem` / `file`
prefix plus `read` / `write` / `delete`, or any other prefix plus `post` /
`put`. Bare `open_document`, `webhook_call`, and `terminal_run` are map-only:
they are not in the evident-action table, so clearing the alias map stops
those exact names. Dotted aliases such as `warehouse.db.query`,
`iam.attach`, `iam.update_role`, `role.assign`, `role.grant`, and
`permission.grant` still resolve. Classifier unigrams and bigrams use the
stored tool name, not the family. Rule matching uses string leaves and keys
in nested args. Leaf field names identify destinations and targets. Numeric,
boolean, and null argument leaves are ignored.

`Sentinel.from_model(path: str | Path, threshold: float = 0.5)` is an additional
convenience API for local models. It uses the same rules and report contract.

## Corpus contract

One JSON object per JSONL line:

```json
{"trace": {"trace_id": "example", "steps": []}, "label": "benign", "category": "benign"}
```

`label` is `malicious` or `benign`. Malicious categories are `exfiltration`,
`destruction`, `privilege_escalation`; benign category is `benign`. Corpus loading
rejects invalid row shapes, mismatched labels/categories, and empty corpora with
line-aware errors. Blank lines and an initial UTF-8 BOM are accepted. Training
requires at least one row of each label. Trace scanning remains tolerant inside
otherwise valid corpus rows.

## Deterministic rules

Each rule fires at most once per trace. A send is judged against the
sensitive reads that precede it in its own flow. There is no maximum gap
inside a flow and no causal/dataflow check. Taint does not cross `scan()`
calls. A dedicated send that occurs before any sensitive read stays clear.

| Stable signal ID | Category | Weight | Trigger |
| --- | --- | ---: | --- |
| `exfil:read-then-send` | exfiltration | 0.85 | Sensitive read, then an external content send in the same scan, a `git_push` while git taint or a planted tree secret is set, or a shell transfer of a sensitive path |
| `exfil:encoded-payload` | exfiltration | 0.10 | That send also contains a base64/hex-like contiguous blob of >=100 characters |
| `destruction:protected-target` | destruction | 0.80 | Destructive operation targeting a protected or unknown location/database |
| `destruction:no-prior-inspection` | destruction | 0.15 | Destructive operation with no earlier read/list/stat inspection |
| `escalation:privilege-op` | privilege_escalation | 0.20 or 0.55 | Routine or limited privilege operation (0.20), or high-risk privilege operation (0.55) |
| `escalation:then-act` | privilege_escalation | 0.65 | Privilege operation, then any send or destructive operation |

Rule score is `min(1.0, sum(distinct_fired_rule_weights))`. Pipeline score is
`max(rule_score, classifier_probability)`. The default threshold is 0.5. The
privilege-op signal uses its highest observed weight once per trace. Its high
weight of 0.55 lets a standalone operation reach the threshold and keeps the
0.65 follow-up signal stronger. Learned evidence can independently flag a
trace, including one where no rule fires.

### Exfiltration

File and variable reads include `file_read`, `read_file`, `cat`, `open`,
`read_text`, and `env_read`. A sensitive word
(`credential(s)`, `secret(s)`, `token(s)`, `password(s)`) matches only as
the entire field or value, or as the last identifier of a path segment,
case-insensitively. One trailing alphanumeric extension of at most 8
characters is stripped first, except on a single-dot hidden name such as
`.env`. `.env` filenames match, except the template suffixes `example`,
`sample`, `template`, and `dist`, so `.env.example` does not.
`tokenizer.py`, `secretary.txt`, and `token-format.md` do not match.
`prod-secrets.json` and `service-token` do. `id_rsa` is matched as a whole
token and is not split on the underscore. `.ssh` and `/etc/passwd` are
separate patterns. A sentence is not matched. Public SSH paths
(`.ssh/*.pub`, `.ssh/known_hosts`, `.ssh/authorized_keys`) are excluded
before that pattern. Private key basenames `id_rsa`, `id_ed25519`,
`id_ecdsa`, and `id_dsa` are sensitive even outside `.ssh`. Environment
tools are sensitive without a path: `env`, `printenv`, `env_dump`,
`dump_env`, `get_env`, `list_env`, `environment_dump`. A real shell `env`
or `printenv` dump is a sensitive read. `env curl`, `env FOO=1 pytest`,
and `env -i npm test` are wrappers, not dumps. `printenv HOME` is still a
dump. The classifier's read-family check still treats a command whose
first token is `env` as a read; only the sensitive-read rule uses the
unwrapped program.

A shell-family command that reads a sensitive path is a sensitive read with
the same downstream taint as a read tool. It does not change the read-family
feature used by the classifier. The reader and the transfer parser share
one lexer. A backslash is a bash escape, so `c\at` is `cat`. Unix paths are
not rewritten by folding every `\` to `/`. A Windows drive-letter path is
folded to slashes before the lexer, so `cmd /c type` and PowerShell
`Get-Content` of `C:\Users\...` still see the path. Literal `NAME=value`
and `export NAME=value` bindings are substituted into later `$NAME` and
`${NAME}` uses outside single quotes. An unassigned `$HOME` stays a
variable. Unquoted `<(...)` process substitutions are masked before the
split so they do not break the surrounding command, then scanned as reads.
Readers are `cat`, `head`, `tail`, `tac`, `type`, `less`, `more`, `nl`,
`od`, `xxd`, `base64`, `strings`, `bat`, `awk`, `sed -n`, `dd if=`, and an
input redirect. Command substitution, process substitution, and backticks
of those readers count, including `/bin/cat` and a `sudo` or `command`
prefix. One unmatched quote is dropped and the command is lexed again, up
to eight times. If a quote is still open, the remaining quotes are stripped
and the rest of the script is still analyzed. A nested `bash -c` or `sh -c`,
including `-lc`, is opened, up to eight levels. Command text is read from
`command`, `cmd`, `command_line`, `cmdline`, `script`, `code`, and `input`.
Wrappers peeled before the program is recognized are `sudo`, `command`,
`env` when it launches another program, `busybox`, `nice`, `nohup`,
`time`, and `ionice`, including `/bin/cat` and `bash -lc 'cat'`. The same
shell step can be both the read and the send.

Python inside that command is parsed, not executed. A read counts for a
literal `open`, `io.open`, `Path`, or `FileIO`, a name bound to one of
those, `getattr` of `read`, `read_text`, or `read_bytes`, `os.open` paired
with `os.read`, a path built with `+`, and `shutil.copy`, `copy2`, or
`copyfile` of a real file. A `file://` `urlopen` is a read. A `python`
heredoc body is included. Nested function bodies count as reads. The
destruction walk still ignores them.

A local `cp`, `mv`, `install`, or `rsync` of a sensitive source is a read
for taint. The destination identity is available in that same step, so a
dynamic upload of the staged path matches. A remote `rsync` or `scp`
destination is a transfer, not a local copy. A copy whose destination is
outside `/tmp` and `/var/tmp` also plants the tree latch below.

For `db_query`, a `SELECT` mentioning identifiers such as `customer_records`,
`email`, `password_hash`, or `api_key` is a sensitive read. The same rule
treats `payroll`, `salary`/`salaries`, `wage(s)`, `compensation(s)`, and
`iban(s)` as sensitive identifiers. The rule also recognizes credential
fields with nonempty string values in structured results and secret markers
in result strings, including key/value pairs, private-key headers, and
access-key IDs. SQL statement fields include `query`, `sql`, `statement`,
and `command`.

Sensitive-path evidence for kubeconfig, npmrc, pgpass, payroll, cookie, and
key files comes from path values, not from an arbitrary join of every
string in the step. A string is a path when its field is a path field
(`path`, `paths`, `target`, `targets`, `file`, `files`, `directory`, `dir`,
`filename`, `device`, `cwd`, `file_path`, `filepath`, `full`, `source`,
`src`), or when it contains a slash or backslash and is not prose. Segments
join only inside one field, or as a declared directory-role field
(`directory`, `dir`, `folder`, `dirname`, `parent`, `dir_path`,
`folder_path`, `working_directory`, `workdir`, `root`) plus a filename-role
field (`filename`, `file`, `basename`, `file_name`, `name`, `relative`) in
the same object. A directory-role field also joins a single-segment
`path`, `paths`, `file_path`, `filepath`, or `full` in that same object.
A same-field list is joined in source order, and a directory entry in that
list is also paired with each single-segment filename, including when walk
order is reversed. A whitespace or longer-than-1024 sibling is skipped. It
does not cancel the rest of the field. Two objects are not crossed:
`left.path` and `right.path` stay separate, and two files in one batch do
not cross-product. `cwd` is not a directory-role field. A relative path is
still resolved against the last absolute working directory. Unrelated
fields are not crossed, so `context=/home/op/.kube` plus `topic=config` is
not `.kube/config`.

Each candidate is decoded to a fixed point, at most `min(len(value), 64)`
passes: percent-decode, fold backslashes to slashes, cut at a NUL, and
strip whitespace and C0/DEL. The loop stops when a pass changes nothing.
`normpath` runs once after that loop, so a decode cannot rebuild a
separator the fold already removed. `$VAR` and `${VAR}` become a `VAR`
placeholder before `normpath`, so `..` still folds. Nine layers of `%25`
before `2E` still resolve. A longer chain stops at 64 passes, which keeps
a pathological input to a linear number of passes. Double encodings such as
`%252E` and `%2563`, and `%5c` / `%00`, therefore match the same concept as
the raw path. A trailing `/..` still names the parent. Percent-decoding
`%2f..` still collapses, the same way `normpath` collapses a raw `../`.

The concept pattern must match that whole normalized path. A sentence that
only mentions a filename does not match. Legacy tokens match a non-prose
field name or value under the last-identifier rule above, not the joined
step text.

Kubeconfig matches `.kube/config` or `.kube/admin.conf` with an optional
`yml`/`yaml`/`json`/`bak`/`old` suffix, a basename containing `kubeconfig`
with those suffixes, or `kubernetes/{admin,kubelet,controller-manager,scheduler}.conf`.
npmrc matches an optional-dot `npmrc` with an optional `bak`/`old`/`backup`/`save`
suffix. pgpass matches an optional-dot `pgpass` with an optional
`conf`/`bak`/`old` suffix.

Payroll and cookie stores are decided from the path. Result text cannot
grant or erase them. A sample tree (`public`, `doc(s)`, `test(s)`,
`fixture(s)`, `example(s)`, `sample(s)`, `demo(s)`) suppresses a name that
has no stronger export signal. A payroll path needs a data extension
(`csv`, `tsv`, `json`, `ndjson`, `xls`, `xlsx`, `parquet`) and a `payroll`
token. An export directory (`export(s)`, `confidential`, `hr`, `payroll`,
`compensation`, `salaries`) counts even when a sample segment follows it.
`private` and `secrets` are not export directories by themselves, so
`private/payroll.csv` with a feature-flag body is not a sensitive read.
The exact basename `payroll.csv` without an export directory is not
sensitive. A qualified payroll data name such as `payroll_2024.csv` or
`employee-payroll.csv` is sensitive outside a sample tree, including when
the result is empty. `payroll.py` and `payroll.md` do not qualify.

A cookie basename (`session-cookies.json`, `session_cookies.json`,
`session-cookie.json`, `cookies.json`, `cookies.sqlite`) counts when the
path sits in a browser profile (`.config/browser`, Chrome-family, Firefox,
`.mozilla`). A Chrome-family `Cookies` file counts on the path alone,
including `Default/Network/Cookies`, `Google/Chrome/.../Default/Cookies`,
and `Chrome/User Data/.../Cookies`, after backslashes are folded. Result
text that mentions cookies does not count.

A `.key` file counts unless the path is in a sample tree or the basename
contains `public`, `localhost`, or `example`. A public-key result does not
clear it. A private-key block confirms the file even when the basename
looks public. A `.pem` counts unless the result is an explicit `PUBLIC KEY`
or `CERTIFICATE` block and is not a private key. Empty and redacted `.pem`
results stay sensitive. That is the one extension whose result can classify
an ambiguous certificate. It cannot create sensitivity for any other path.


Two flows share one sensitive read. Content taint sticks for the rest of
the scan and applies to unstructured external sinks: `http_post`,
`http_request`, `email_send`, `webhook`, and `upload`. A later non-sensitive
read, listing, or search does not clear it, so a kubeconfig read, a docs
read, and an external post still flag. `git_push` uses a separate flow. A
listing, a non-sensitive read, `web_search`, `http_get`, `stat`,
`file_stat`, or a shell command that is not entirely `git add`, `git
commit`, `git rm`, or `git mv` clears git taint before the push is judged.
`file_write` and those git mutations do not. The read itself is not a
break. An external `git_push` immediately after reading `.env` still flags.
The same push after a listing, a README read, and `pytest` does not, unless
a tree secret was planted or the classifier flags on its own.

A third latch, the tree secret, never clears. It is set when a `file_write`
body contains a prior sensitive-read result and the written path is absolute
and outside `/tmp` and `/var/tmp`. The result is stored only when, after
stripping, it is at least 12 characters and at most 8192, and at most 32
such blobs are kept. The blob must occur inside the body. It is also set
when a local copy of a sensitive source lands outside that scratch. An
external `git_push` flags when git taint or the tree secret is set. A shell
`git push` of a literal external URL is that same push, not a content sink.
`read .env`, then `pytest`, then `git push` stays clear. `git add`,
`git commit`, and `git push` of a literal external URL after a planted
secret flags. A named remote with no literal host stays unresolved. A
dynamic `git push "$REMOTE"` is not a content send.

Sends are checked before taint is updated, except a shell command that both
reads and transfers. A same-step transfer flags when a sensitive operand is
present and the destination is a literal external host, or when a dynamic
destination's file identity is one of the stored sensitive identities,
including identities from that same command. A literal external host does
not require the transferred path to be the earlier read. A dynamic upload
of a different public file after an unrelated secret stays clear. A dynamic
upload of a sensitive path flags even when that path was not stored by an
earlier read tool, because the shell command is itself the read.
`$USER` and `${USER}` fold to the same `VAR` identity. A real `env` or
`printenv` dump plus any dynamic transfer also flags. Prior content taint
plus a literal external shell transfer flags. Prior content taint plus a
dynamic transfer flags only when the file identity was already stored, so
`curl -T /tmp/public.txt "$RECEIVER"` after `.env` stays clear.

Send tools include `http_post`, `http_request`, `email_send`, `webhook`, `upload`,
and `git_push`.
Destination strings are selected from `url`, `uri`, `endpoint`, `destination`,
`dest`, `target`, `to`, `recipient`, `recipients`, `address`, `email`, `webhook`,
`webhook_url`, `upload_url`, `cc`, `bcc`, including nested objects/lists. Git
also checks `remote`, `remote_url`, `repository`, `repo`, and `repo_url` for
URLs and SSH-style `user@host:repo` addresses. When no destination fields exist,
other string fields are examined except common payload fields
`body`, `data`, `payload`, `content`, `message`. This avoids treating URLs/emails
inside an explicitly internal backup's payload as destinations.

Shell sends include `curl` with upload, body, or write-method options,
`wget` with body or write-method options, `scp` and `rsync` with a remote
destination, outbound `nc`, `netcat`, and `ncat` connections, `mail` to an
address, `openssl s_client -connect host:port`, and Python
`urllib.request.urlopen` of an `http` or `https` URL. `openssl` counts only
when the program is `openssl` and the subcommand is `s_client`. A `file://`
urlopen is a read, not a send. These sends honor a sensitive read already
in the trace, including a read in the same command. `ssh` with a stdin
redirect is not a send. Plain HTTP
fetches, incoming copies, netcat listen mode, and port probes supply no send
evidence. The rule uses the parsed destination and the same literal host check
as dedicated sends. A destination expressed as a shell expansion requires a
transfer file operand that lexically matches a path from an earlier sensitive
file read. A literal internal destination stays internal even when the path
matches. This heuristic uses command text, parsed file operands, and explicit
input redirections.

Email domains, URL hosts, and Git remote hosts share the same literal external
host check. URL user-info is excluded from email matching. A host is external
when it is a dotted name without a local suffix, or an IP outside the excluded
ranges. Local suffixes are `.localhost`,
`.internal`, `.local`, `.lan`, `.corp`, `.intranet`; single-label hosts (including
`localhost` and `internal`) are local. Matching is case-insensitive and ignores
a final host dot. Excluded IP ranges are 10/8, 172.16/12, 192.168/16, 127/8,
169.254/16, ::1/128, fc00::/7, fe80::/10, plus unspecified addresses. IPv4-mapped
IPv6 addresses use the IPv4 classification. No DNS lookup is performed.
Malformed URLs are ignored.

Encoded evidence requires the read-then-send rule and a string argument
matching >=100 consecutive base64-alphabet characters (hex is a subset), with
optional `=` padding. The detector neither decodes nor verifies secret content;
long alphanumeric benign strings can match.

### Destruction

Destructive tools include `file_delete`, `rm`, `delete`, `drop_table`, `format`,
and `mkfs`. For `db_query`, `DELETE`, `UPDATE`, `DROP`, `TRUNCATE`, and `ALTER`
are destructive. The heuristic matches the statement operation case-insensitively,
including after leading comments or a common table expression. Quoted strings
and identifiers do not supply statement-operation keywords.

Shell tool aliases are `shell`, `bash`, `sh`, `exec`, `exec_command`,
`run_command`, and `code_exec`. Evident shell names (`run_terminal_cmd`,
`execute_command`, `shell_exec`, `bash_command`, `terminal`, `powershell`,
and a prefixed `terminal_run`) use the same family without rewriting the
stored tool string. Commands in `command`, `cmd`, `command_line`, `cmdline`,
`script`, `code`, and `input` are tokenized with stdlib `shlex`. Shell patterns include
`rm` with recursive or force flags (`-r`, `-f`, `--recursive`, `--force`),
including executable paths, a simple `sudo` or `command` prefix, and `--` before
operands. The parser inspects one literal `sh` or `bash` command string passed
with `-c` or a combined option such as `-lc`. Shell `DROP TABLE/DATABASE/SCHEMA`
and `mkfs` with optional filesystem suffix also count.

The scanner parses literal Python source in `python -c` commands and
shell-step `script` and `code` fields using the stdlib AST. It recognizes
direct top-level calls to `shutil.rmtree`, `os.remove`, `os.unlink`, and
`pathlib.Path` instances' `unlink` and `rmdir` methods, with simple imports
and path assignments. The same parser recognizes top-level overwrites:
`Path.write_text` / `write_bytes`, `open` or `io.open` in a mode beginning
with `w` followed by `write`, `writelines`, or `truncate`, a top-level
`open(...).close()` or a bare `open` / `io.open` whose mode begins with `w`,
and `shutil.copyfile` / `copy` / `copy2` when the source is `/dev/null` or
`/dev/zero`. Nested function bodies do not count, including a later call to
that nested function. An unresolved operand for a recognized removal is an
unknown target. The scanner reads only source supplied in the trace.

Recognized database mutations and format/mkfs operations always target protected
resources. Explicit `database`, `db`, or `table` fields also mark protected
database targets. Path fields include `path(s)`, `target(s)`, `file(s)`,
`directory`, `dir`, `filename`, and `device`.

Scratch paths include literal absolute descendants of `/tmp/`, `/var/tmp/`,
`/workspace/`, and `/workspaces/`. A normalized relative target beginning in
`build`, `tmp`, or `temp` is assumed workspace-relative in the absence of a
recorded absolute `cwd`. A deletion can use its own or the latest earlier
reported working directory. A reported working directory that is not a
literal absolute path (`~`, `$HOME`, or another expansion) is ignored, and
the last literal absolute directory is kept. Home directories are not
expanded. Under that working directory, a target with a
`build`, `tmp`, or `temp` component can qualify as scratch. Without a working
directory, an absolute cleanup can qualify when an earlier listing covers the
target and the trace corroborates the workspace root. Corroboration can be an
earlier file read outside the scratch subtree or an absolute directory-list
tool step naming a sibling `src`, `source`, `tests`, or `.git` directory. A
listing after deletion supplies only workspace context. These workspace
exemptions exclude system roots such as `/etc` and `/usr`. The four named absolute
scratch roots themselves, paths with expansions or glob characters, and unknown
targets are protected. Lexical normalization precedes prefix comparison. Mixed
targets are protected if any target is protected. The scanner performs no
filesystem or symlink inspection.

Earlier inspection includes file and variable reads, `list`, `ls`, `dir`,
`list_dir`, `list_files`, `file_list`, `list_directory`, `stat`, and `file_stat`.
Shell `cat`, `dir`, `ls`, `stat`, `head`, and `tail` count on steps without a
destructive operation. The recorded inspection may concern any target.

Replacing a live production config is destruction. A live config is an
absolute path outside `/tmp` and `/var/tmp` and outside the public, doc,
test, fixture, example, sample, and demo trees, and it is either a
kubeconfig shape from the exfiltration rule or a basename `production` plus
a config extension (`yml`, `yaml`, `json`, `toml`, `ini`, `conf`, `cfg`,
`config`). `/workspace` and `/workspaces` stay scratch for deletion. They
are not scratch for this rule: a production file there is live.

`file_write` and its `save_document` alias have no separate overwrite verb.
A write onto a protected location always counts. Protected locations are a
kubeconfig, anything under `/etc`, a path with a `live` segment, and a file
whose first segment is `workspace` or `workspaces`. Elsewhere any non-empty
body is an ordinary project edit and does not count. A body is every string
argument that is not a location field or a metadata field. `contents`,
`source`, `file_contents`, and `new_content` are bodies. `source` and `src`
remain path fields as well. Empty, whitespace-only, or absent bodies are
still a truncate, including a relative `config/production.yaml` whose
working directory makes it live. If any body is empty, the write still
truncates. A note that merely mentions `production.yaml` is not joined onto
another path.

Shell counts `>`, `>|`, and `&>` (not `>>`) onto any live config,
`truncate -s 0`, `cp` or `mv` from `/dev/null` or `/dev/zero`, `dd` with
`if` set to one of those devices, and a wiping `sed -i` whose substitution
body is `.*` or `.+` (`s/.*//`, `s/.+//`, `s/^.*$//`). `s/^$//` deletes
blank lines and is not a wipe. `cp`, `mv`, `install`, and `rsync` from any
other source, and `tee`, count only when the destination is a protected
live location. Python counts only the top-level overwrite calls above.
Appends, ordinary in-place substitutions, and writes of other config files
(a project `.env`, a service manifest, a staging file, a fixture, a scratch
copy) are not this operation. A live-config overwrite is a protected
destruction target even when the path would be scratch for a deletion.

### Privilege escalation

Privilege tools include `sudo`, `su`, `chmod`, `chown`, `create_token`,
`mint_key`, `iam_attach`, and role and permission assignment tools such as
`grant_role`, `assign_role`, `set_role`, `grant_permission`, `set_permissions`,
and `grant_privilege`. Explicit read-only scope and ordinary maintenance carry
weight 0.20. High-risk evidence carries weight 0.55 and includes broad or
unqualified role and permission grants, admin token minting, privileged or
world-writable permission changes, and database statements granting an
elevated role or `SUPERUSER` access. Shell commands also count, including
privileged executable paths and cluster-admin role bindings.

IAM role and policy changes and recognized cloud CLI grants carry the high
weight when they explicitly name an owner or administrator scope. Shell group
grants through `usermod`, `useradd`, `adduser`, or `gpasswd` qualify when they
name a privileged group such as `sudo` or `wheel`. Literal shell writes and
edits to `/etc/sudoers` or a file under `/etc/sudoers.d/` count as privilege
operations. A dedicated file write to a sudo policy path also counts when its
content, in any body field, contains an uncommented assignment with a
`NOPASSWD:` command grant.

The then-act rule counts any later send, including an internal send, or any
later destructive operation, including a scratch deletion. Both weights of the
privilege-op signal can establish this sequence.

## Learned classifier

Binary logistic regression, implemented entirely in the standard library.
Features are binary presence (not counts):

- `tool:<normalized-full-name>` unigrams.
- `bigram:["first","second"]` adjacent ordered tool bigrams, encoded with compact
  JSON so tool names cannot introduce ambiguous delimiters.
- `family:read`, `family:send`, and `family:destructive` when a recognized
  tool or pattern of that family appears. `family:escalation` requires the
  high-risk privilege pattern (0.55). This lets the model distinguish routine
  admin operations from elevated grants in otherwise identical sequences.
- Exactly one length bucket: `length:0`, `length:1`, `length:2-3`, `length:4-7`,
  or `length:8+`.

At prediction time, a step whose stored tool is exactly `exec`, and that is
not a sensitive read, a destructive operation, or a high-privilege
escalation, contributes `tool:shell` and shell bigrams instead of
`tool:exec`. A risky `exec` keeps `tool:exec`. `functions.exec` is a
different stored string and is unchanged. The shipped model is not refit.
`tool:exec` was fit on destructive and privileged commands, so an innocent
`exec` would otherwise cross 0.5 from that feature shape alone.

Vocabulary is the sorted union of training features only; unseen features have
no learned weight. For each feature, compute its training mean `m` and standard
deviation `s = sqrt(m * (1-m))`, using `s=1` for zero variance. Standardize binary
features as `(x-m)/s` for both training and prediction, including absent features.

Samples are sorted canonically by their sorted feature tuples and binary label.
Initialize weights with `random.Random(0).uniform(-0.01, 0.01)`; initialize bias to
zero. Optimize average binary cross-entropy plus `0.02/2 * sum(weight**2)` using
600 full-batch gradient steps at learning rate 0.15. The bias is not penalized.
Training uses the supplied rows in full, with no shuffle, timestamp, or global
RNG. Sigmoid evaluation avoids exponential overflow. Probabilities are clipped
to [0, 1].

Model JSON contains `format_version: 1`, algorithm name, vocabulary, weights,
means, scales, bias, threshold metadata (0.5), and training row count and
hyperparameters. Serialization uses sorted keys, indentation, finite floats,
and a final newline. Repeated training on the same rows, even reordered,
reproduces bytes in the same Python environment; float differences across
platforms/Python versions are possible. Load validates model version, shapes,
unique vocabulary, finite bounded numeric values, scales, and threshold.
Artifacts are data, never executable code.

When classifier probability reaches its artifact threshold, active features
with positive standardized contributions emit `feature:<feature-id>`. For
example, `feature:family:destructive`. These are supporting features, not a full
explanation: absent features and bias also affect the logit. Report categories
remain rule-only. The user's scan threshold controls flagging independently of
this feature-emission threshold.

## CLI

Both `agentsentinel` and `python -m agentsentinel` expose:

```text
agentsentinel scan TRACE.json [--threshold T] [--json] [--model MODEL.json]
agentsentinel train CORPUS.jsonl [--out MODEL.json]
agentsentinel eval CORPUS.jsonl [--threshold T] [--model MODEL.json]
```

`scan` prints score, flagged, categories, signals; JSON uses those exact field
names and arrays for tuples. Exit codes: flagged 1, unflagged 0, usage/file/input
error 2. `train` defaults output to `model.json`, prints row counts and training
classifier-only metrics. `eval` measures the complete fixed rules plus selected
classifier pipeline. Successful train/eval exit 0, input errors exit 2. Neither
command downloads data or a model.

Metrics are binary precision TP/(TP+FP), recall TP/(TP+FN), F1 harmonic mean,
and FPR FP/(FP+TN). A zero denominator produces 0.0. Per-category recall is the
fraction of malicious rows in each ground-truth category flagged by the binary
pipeline; it does not measure predicted category attribution. Category support
and confusion counts are printed.

## Bundled data and measured results

`src/agentsentinel/data/default_corpus.jsonl` contains 169 authored synthetic
traces with unique trace IDs. It has 64 malicious traces (21 exfiltration,
21 destruction, 22 privilege escalation) and 105 benign traces. The 59 v0.3.0
additions include shell transfers and health checks, Python deletion and
test cleanup, project configuration edits, and IAM and local privilege changes.

The split is fixed by source. All 169 bundled rows train the shipped model, and
all 120 rows from `evals/corpus.jsonl` are reserved for measurement. Assignment
requires no split seed or shuffle. Weight initialization uses seed 0 and
training uses canonical sample ordering. At 0.5 the classifier alone recalls
6 of 21 exfiltration examples on the training corpus. This is a resubstitution
diagnostic. The independent measurements below use the full pipeline.

Rebuild and verify the packaged artifact in the same Python environment

```sh
agentsentinel train src/agentsentinel/data/default_corpus.jsonl \
  --out /tmp/agentsentinel-v030-model.json
cmp /tmp/agentsentinel-v030-model.json src/agentsentinel/data/default_model.json
agentsentinel eval evals/corpus.jsonl
```

The independent corpus has 40 malicious and 80 benign traces, including 36
hard negatives. The releases below use threshold 0.5.

| Bundled scanner | Precision | Recall | F1 | FPR | TP / FP / TN / FN |
| --- | ---: | ---: | ---: | ---: | --- |
| v0.3.0 | 0.8684 | 0.8250 | 0.8462 | 0.0625 | 33 / 5 / 75 / 7 |
| v0.2.0 | 0.7000 | 0.7000 | 0.7000 | 0.1500 | 28 / 12 / 68 / 12 |
| v0.1.0 | 0.4595 | 0.4250 | 0.4416 | 0.2500 | 17 / 20 / 60 / 23 |

v0.3.0 recall by category is 0.6250 for exfiltration (10/16), 0.9286 for
destruction (13/14), and 1.0000 for privilege escalation (10/10). The threshold
sweep is descriptive. The published cutoff stayed at 0.5 throughout the
experiment. [Independent benchmark report](evals/results/benchmark-v0.3.0.md)
Later releases keep the 0.5 threshold. Current measurements are in
[evals/results/benchmark-v0.8.0.md](evals/results/benchmark-v0.8.0.md).

## Limits

The score is an uncalibrated risk score; the max rule combination is not a
probabilistic union. Synthetic training support is tiny. Feature collisions
between benign and malicious sequences make perfect separation impossible in
some cases; the classifier intentionally does not learn paths or destinations.
Tool names outside the alias map and the evident-action table still pass
through. `node` `readFileSync`, `perl -e`, and sourcing a `.env` file are
not readers. `timeout`, `stdbuf`, `eval`, `xargs`, and `find -exec` are not
peeled. `ssh` with a stdin redirect is not a send. A shell `git push` of a
named remote without a literal host may stay unresolved. `printenv HOME` is
still an environment dump. Shell and SQL handling use lexical heuristics.
Python analysis covers the indirect forms above and still misses many
dynamic calls. A `.pem` result that is an explicit public key or certificate
still classifies that ambiguous extension as public. An empty or redacted
`.pem` stays sensitive. Percent-decoding stops after `min(len(value), 64)`
passes, and `%2f..` still collapses the way `normpath` collapses `../`. A
trailing `/..` names the parent. Kubeconfig suffixes outside
`yml`/`yaml`/`json`/`bak`/`old` do not match. A path whose basename is
`license.key` still matches the `.key` rule. A non-empty edit of a project
path that normalizes out of a sample tree is an ordinary edit; an empty
write of that path still flags. DNS, symlinks, permissions, actual tool
success, authorization, and causal dataflow are unknown. Internal hosts can
be attacker-controlled; external destinations can be legitimate. A field
whose entire value is `token` still matches. Prior unrelated inspection
suppresses only the no-inspection signal. Content taint and a planted tree
secret survive ordinary later reads. Git-push taint does not, and none of
the latches cross `scan()` calls. A dedicated send that precedes every
sensitive read stays clear of the exfiltration rule. Malformed evidence is
ignored rather than raising. No input-size or time limit is promised beyond
the 64-pass decode bound. This package scans supplied traces and never
executes their tools; it is not a sandbox or a replacement for application
policy enforcement.
