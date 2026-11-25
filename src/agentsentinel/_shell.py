"""Extract literal command evidence without running a shell or Python code."""

import ast
import posixpath
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

from agentsentinel.trace import Step

SHELL_TOOLS = frozenset(
    {"shell", "bash", "sh", "exec", "exec_command", "run_command", "code_exec"}
)
COMMAND_FIELDS = frozenset(
    {"command", "cmd", "command_line", "cmdline", "script", "code", "input"}
)
_SEPARATORS = ";&|()\n"
_SHELL_COMMAND_OPTION = re.compile(r"-[a-z]*c[a-z]*")
_PYTHON = re.compile(r"python(?:3(?:\.\d+)?)?")
_REMOTE = re.compile(r"(?:[\w.-]+@)?(\[[0-9a-f:]+\]|[\w.-]+):[^\s]+", re.I)
_EXPANSION = re.compile(r"\$\{|\$\w|\x60")
_PATH_FUNCTIONS = frozenset({"shutil.rmtree", "os.remove", "os.unlink"})

_CURL_PAYLOAD = {
    "-d",
    "-F",
    "-T",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--json",
    "--upload-file",
}
_WGET_PAYLOAD = {"--post-data", "--post-file", "--body-data", "--body-file"}
_CURL_VALUES = _CURL_PAYLOAD | {
    "-A",
    "-b",
    "-c",
    "-e",
    "-H",
    "-m",
    "-o",
    "-u",
    "-w",
    "-x",
    "-X",
    "--connect-timeout",
    "--cookie",
    "--cookie-jar",
    "--header",
    "--max-time",
    "--output",
    "--output-dir",
    "--proxy",
    "--referer",
    "--request",
    "--url",
    "--user",
    "--user-agent",
    "--write-out",
}
_WGET_VALUES = _WGET_PAYLOAD | {
    "-O",
    "-o",
    "-P",
    "-U",
    "--directory-prefix",
    "--header",
    "--method",
    "--output-document",
    "--output-file",
    "--referer",
    "--user-agent",
}
_SCP_VALUES = {
    "-c",
    "-D",
    "-F",
    "-i",
    "-J",
    "-l",
    "-o",
    "-P",
    "-S",
    "-X",
}
_RSYNC_VALUES = {
    "-e",
    "--exclude",
    "--exclude-from",
    "--include",
    "--include-from",
    "--port",
    "--rsh",
}
_NC_VALUES = {"-i", "-p", "-s", "-w", "-m", "-q", "-W", "-X", "-x"}
_REDIRECTS = {"<", "<<", "<<<", ">", ">>", "<>", ">|", "&>"}
_READERS = frozenset(
    {
        "awk",
        "base64",
        "bat",
        "cat",
        "head",
        "less",
        "more",
        "nl",
        "od",
        "strings",
        "tac",
        "tail",
        "type",
        "xxd",
    }
)
_HEAD_VALUES = {"-n", "-c", "-q"}
_ENV_WRAPPERS = frozenset({"busybox", "nice", "nohup", "time", "ionice"})
_COPY_PROGRAMS = frozenset({"cp", "mv", "install", "rsync"})
_READ_NAMES = "cat|head|tail|type|base64|nl|od|xxd|strings|less|more|bat|tac"
# Backticks are command substitution. A path prefix (`/bin/cat`) and a
# `sudo`/`command` wrapper still name the reader.
_SUBSTITUTED_READ = re.compile(
    rf"(?:\$\(|<\(|`)\s*(?:(?:sudo|command|busybox)\s+)*(?:[\w./\\-]+/)?"
    rf"(?:{_READ_NAMES})\s+([^)`\n]*)",
    re.IGNORECASE,
)
# Drive-letter paths only. A Unix escape such as `c\at` or `conf\ig` is not
# one of these; shlex drops that backslash, which is what bash does.
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\/\s\"']+\\)*[^\\/\s\"']*")
_ASSIGNMENT = re.compile(r"(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=")
_SHELL_NAME = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_WORD_START = frozenset(" \t\n;|&")
_PYTHON_HEREDOC = re.compile(
    r"(?:^|[;&|\n])\s*(?:[\w./]+/)?python(?:3(?:\.\d+)?)?[ \t]+"
    r"<<-?[ \t]*(?P<q>['\"]?)(?P<word>[A-Za-z_]\w*)(?P=q)[ \t]*\n"
    r"(?P<body>.*?)\n(?P=word)[ \t]*(?:\n|$)",
    re.IGNORECASE | re.DOTALL,
)
_NESTED_SHELL_DEPTH = 8
_QUOTE_REPAIR_LIMIT = 8


def shell_commands(step: Step) -> Iterator[list[str]]:
    if step.family_name not in SHELL_TOOLS:
        return
    for field, value in step.fields:
        if field not in COMMAND_FIELDS:
            continue
        yield from _commands_nested(value, 0)


def _commands_nested(value: str, depth: int) -> Iterator[list[str]]:
    for command in _split_shell_commands(value):
        yield command
        if depth >= _NESTED_SHELL_DEPTH:
            continue
        invoked = unwrap_command(command)
        if (
            len(invoked) >= 3
            and posixpath.basename(invoked[0]).lower() in {"bash", "sh"}
            and _SHELL_COMMAND_OPTION.fullmatch(invoked[1])
        ):
            yield from _commands_nested(invoked[2], depth + 1)


def _fold_windows_paths(value: str) -> str:
    return _WINDOWS_PATH.sub(lambda match: match.group(0).replace("\\", "/"), value)


def _read_assign_value(value: str, index: int) -> tuple[str, int]:
    """A literal assignment value, or empty when it expands or is unclosed."""
    if index >= len(value):
        return "", index
    if value[index] in "\"'":
        quote = value[index]
        index += 1
        chars: list[str] = []
        while index < len(value) and value[index] != quote:
            if value[index] == "\\" and quote == '"' and index + 1 < len(value):
                chars.append(value[index + 1])
                index += 2
                continue
            chars.append(value[index])
            index += 1
        if index >= len(value):
            return "", index
        literal = "".join(chars)
        if "$" in literal or "`" in literal:
            return "", index + 1
        return literal, index + 1
    chars = []
    while index < len(value) and value[index] not in " \t\n;|&<>":
        chars.append(value[index])
        index += 1
    literal = "".join(chars)
    if not literal or "$" in literal or "`" in literal:
        return "", index
    return literal, index


def _extract_assignments(value: str) -> dict[str, str]:
    """Literal `NAME=` and `export NAME=` bindings. Expanding values stay."""
    found: dict[str, str] = {}
    index = 0
    length = len(value)
    single = False
    double = False
    while index < length:
        char = value[index]
        if single:
            if char == "'":
                single = False
            index += 1
            continue
        if char == "\\" and not double:
            index += 2
            continue
        if char == "'" and not double:
            single = True
            index += 1
            continue
        if char == '"':
            double = not double
            index += 1
            continue
        at_word = index == 0 or value[index - 1] in _WORD_START
        match = _ASSIGNMENT.match(value, index) if at_word and not double else None
        if match is None:
            index += 1
            continue
        literal, index = _read_assign_value(value, match.end())
        if literal:
            found[match.group(1)] = literal
    return found


def _substitute_assignments(value: str) -> str:
    """Replace `$NAME` / `${NAME}` outside single quotes when NAME was set."""
    assignments = _extract_assignments(value)
    if not assignments:
        return value
    parts: list[str] = []
    index = 0
    length = len(value)
    single = False
    double = False
    while index < length:
        char = value[index]
        if single:
            parts.append(char)
            if char == "'":
                single = False
            index += 1
            continue
        if char == "\\" and not double:
            parts.append(value[index : index + 2])
            index += 2
            continue
        if char == "'" and not double:
            single = True
            parts.append(char)
            index += 1
            continue
        if char == '"':
            double = not double
            parts.append(char)
            index += 1
            continue
        if char == "$":
            match = _SHELL_NAME.match(value, index)
            if match is not None:
                name = match.group(1) or match.group(2)
                if name in assignments:
                    parts.append(assignments[name])
                    index = match.end()
                    continue
        parts.append(char)
        index += 1
    return "".join(parts)


def _mask_process_substitutions(value: str) -> str:
    """Hide unquoted `<(...)` so the parenthesis does not detach the next word.

    Quoted `$(cat ...)` stays quoted, and unquoted `$(...)` stays unmasked:
    the parenthesis split is what exposes `$(/bin/cat)`.
    """
    parts: list[str] = []
    index = 0
    length = len(value)
    single = False
    double = False
    while index < length:
        char = value[index]
        if single:
            parts.append(char)
            if char == "'":
                single = False
            index += 1
            continue
        if char == "\\" and not double:
            parts.append(value[index : index + 2])
            index += 2
            continue
        if char == "'" and not double:
            single = True
            parts.append(char)
            index += 1
            continue
        if char == '"':
            double = not double
            parts.append(char)
            index += 1
            continue
        if not double and value.startswith("<(", index):
            depth = 0
            end = index
            while end < length:
                if value[end] == "(":
                    depth += 1
                elif value[end] == ")":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
            parts.append("__procsub__")
            index = end
            continue
        parts.append(char)
        index += 1
    return "".join(parts)


def _analysis_text(value: str) -> str:
    """Text the reader and the transfer parser both see before tokenization."""
    return _substitute_assignments(_fold_windows_paths(value))


def _prepare_shell(value: str) -> str:
    return _mask_process_substitutions(_analysis_text(value))


def _unmatched_quote(value: str) -> int | None:
    """Index of a quote shlex would leave open, if there is one."""
    index = 0
    length = len(value)
    single: int | None = None
    double: int | None = None
    while index < length:
        char = value[index]
        if single is not None:
            if char == "'":
                single = None
            index += 1
            continue
        if char == "\\" and double is None:
            index += 2
            continue
        if char == "\\" and double is not None:
            index += 2
            continue
        if char == "'" and double is None:
            single = index
            index += 1
            continue
        if char == '"':
            double = None if double is not None else index
            index += 1
            continue
        index += 1
    if single is not None:
        return single
    return double


def _lex_shell(value: str) -> list[str] | None:
    lexer = shlex.shlex(value, posix=True, punctuation_chars=_SEPARATORS + "<>")
    lexer.whitespace_split = True
    lexer.whitespace = " \t\r"
    try:
        return list(lexer)
    except ValueError:
        return None


def _split_shell_commands(value: str) -> Iterator[list[str]]:
    prepared = _prepare_shell(value)
    tokens = _lex_shell(prepared)
    if tokens is None:
        repaired = prepared
        for _ in range(_QUOTE_REPAIR_LIMIT):
            opened = _unmatched_quote(repaired)
            if opened is None:
                break
            repaired = repaired[:opened] + repaired[opened + 1 :]
            tokens = _lex_shell(repaired)
            if tokens is not None:
                break
        if tokens is None:
            tokens = _lex_shell(repaired.replace("'", "").replace('"', "")) or []
    command: list[str] = []
    for token in tokens:
        if token and all(char in _SEPARATORS for char in token):
            if command:
                yield command
            command = []
        else:
            command.append(token)
    if command:
        yield command


def _unwrap_env(words: list[str]) -> list[str] | None:
    """Return the command after ``env`` assignments, or None for a bare dump."""
    index = 0
    rest = words[1:]
    while index < len(rest):
        word = rest[index]
        if word == "--":
            index += 1
            break
        if word.startswith("-") or ("=" in word and not word.startswith("=")):
            index += 1
            continue
        break
    if index >= len(rest):
        return None
    return rest[index:]


def unwrap_command(command: list[str]) -> list[str]:
    """Drop sudo, command, env, and other wrappers that hide the real program."""
    words = command
    for _ in range(6):
        if not words:
            return []
        program = posixpath.basename(words[0]).lower()
        if program in {"sudo", "command"}:
            nxt = next(
                (
                    words[index:]
                    for index, word in enumerate(words[1:], 1)
                    if not word.startswith("-")
                ),
                [],
            )
            if not nxt:
                return words
            words = nxt
            continue
        if program == "env":
            unwrapped = _unwrap_env(words)
            if not unwrapped:
                return words
            words = unwrapped
            continue
        if program in _ENV_WRAPPERS:
            nxt = next(
                (
                    words[index:]
                    for index, word in enumerate(words[1:], 1)
                    if not word.startswith("-")
                ),
                [],
            )
            if not nxt:
                return words
            words = nxt
            continue
        return words
    return words


def _quoted_operand(token: str) -> str:
    return token.strip().strip("\"'").strip()


def _bash_unescape(token: str) -> str:
    """Drop a backslash that only quoted the next character. shlex already did."""
    return re.sub(r"\\(.)", r"\1", token)


def _substituted_reads(value: str) -> Iterator[str]:
    for match in _SUBSTITUTED_READ.finditer(value):
        for piece in match.group(1).split():
            operand = _bash_unescape(_quoted_operand(piece))
            if not operand or operand.startswith("-") or operand.isdigit():
                continue
            yield operand
            break


def _copy_value_options(program: str) -> set[str]:
    if program == "install":
        return {
            "-m",
            "-o",
            "-g",
            "-S",
            "-t",
            "--mode",
            "--owner",
            "--group",
            "--suffix",
            "--target-directory",
        }
    if program == "cp":
        return {"-S", "-t", "--suffix", "--target-directory"}
    if program == "rsync":
        return set(_RSYNC_VALUES)
    return set()


def _remote_destination(destination: str) -> bool:
    return destination.startswith(("rsync://", "scp://")) or (
        _REMOTE.fullmatch(destination) is not None
    )


def _copy_pairs(invoked: list[str]) -> Iterator[tuple[str, str]]:
    """Local `cp` / `mv` / `install` / `rsync` source and destination pairs."""
    if not invoked:
        return
    program = posixpath.basename(invoked[0]).lower()
    if program not in _COPY_PROGRAMS:
        return
    operands = [
        value
        for option, value in command_arguments(
            invoked[1:], _copy_value_options(program)
        )
        if not option and value
    ]
    if len(operands) < 2 or _remote_destination(operands[-1]):
        return
    destination = operands[-1]
    for source in operands[:-1]:
        yield source, destination


def shell_local_copies(step: Step) -> Iterator[tuple[str, str]]:
    """Local copies whose source the command reads."""
    if step.family_name not in SHELL_TOOLS:
        return
    for command in shell_commands(step):
        yield from _copy_pairs(unwrap_command(command))


def shell_git_push_remotes(step: Step) -> Iterator[str]:
    """Repository argument of a shell `git push`, when one was written."""
    if step.family_name not in SHELL_TOOLS:
        return
    value_options = {"-o", "--exec", "--receive-pack", "--repo", "-u"}
    for command in shell_commands(step):
        invoked = unwrap_command(command)
        if not invoked or posixpath.basename(invoked[0]).lower() != "git":
            continue
        words = invoked[1:]
        if "push" not in words:
            continue
        rest = words[words.index("push") + 1 :]
        operands = [
            value
            for option, value in command_arguments(rest, value_options)
            if not option and value
        ]
        if operands:
            yield operands[0]


def _reader_operands(command: list[str]) -> Iterator[str]:
    if not command:
        return
    invoked = unwrap_command(command)
    if not invoked:
        return
    program = posixpath.basename(invoked[0]).lower()
    if program in {"cmd", "cmd.exe"}:
        words = [word.lower() for word in invoked[1:]]
        if "type" in words:
            yield from _reader_operands(["type", *invoked[words.index("type") + 2 :]])
        return
    if program in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        words = invoked[1:]
        for index, word in enumerate(words):
            if word.lower() not in {"get-content", "gc", "type", "cat"}:
                continue
            for nxt in words[index + 1 :]:
                lowered = nxt.lower()
                if lowered in {"-path", "-literalpath"}:
                    continue
                if nxt.startswith("-"):
                    continue
                yield _quoted_operand(nxt)
                break
        return
    for option, value in command_arguments(invoked[1:], {"<", ">"}):
        if option == "<" and value:
            yield value
    if program == "dd":
        for option, value in command_arguments(invoked[1:], set()):
            token = value if not option else ""
            if token.startswith("if="):
                yield token[3:]
        return
    if program in _COPY_PROGRAMS:
        for source, _destination in _copy_pairs(invoked):
            yield source
        return
    if program not in _READERS and not (
        program == "sed"
        and any(word == "-n" or word.startswith("-n") for word in invoked[1:])
    ):
        return
    value_options = _HEAD_VALUES if program in {"head", "tail"} else set()
    for option, value in command_arguments(invoked[1:], value_options):
        if option or not value or value == "-" or value.startswith("-"):
            continue
        if program in {"awk", "sed"} and "/" not in value and "\\" not in value:
            continue
        yield value


def shell_read_operands(step: Step) -> Iterator[str]:
    """File paths a shell or Python command reads, without executing it."""
    if step.family_name not in SHELL_TOOLS:
        return
    seen: set[str] = set()

    def emit(operand: str) -> Iterator[str]:
        if operand and operand not in seen:
            seen.add(operand)
            yield operand

    for field, value in step.fields:
        if field not in COMMAND_FIELDS:
            continue
        # Substitutions are read from the shared prepared text. The lexer
        # below is the same one `shell_commands` uses, including nested bash.
        for operand in _substituted_reads(_analysis_text(value)):
            yield from emit(operand)
    for command in shell_commands(step):
        for operand in _reader_operands(command):
            yield from emit(operand)
    for source in _python_sources(step):
        for operand in _python_read_paths(source):
            yield from emit(operand)


def command_arguments(
    words: list[str], value_options: set[str]
) -> Iterator[tuple[str, str]]:
    """Yield option/value pairs, with an empty option for positionals."""
    args = iter(words)
    options = True
    for word in args:
        if word in _REDIRECTS:
            yield word, next(args, "")
        elif options and word == "--":
            options = False
        elif options and word.startswith("--"):
            name, equals, value = word.partition("=")
            yield (
                name,
                next(args, "") if not equals and name in value_options else value,
            )
        elif options and word.startswith("-") and word != "-":
            for index, char in enumerate(word[1:], 2):
                name = "-" + char
                if name in value_options:
                    yield name, word[index:] or next(args, "")
                    break
                yield name, ""
        else:
            yield "", word


@dataclass(frozen=True)
class ShellTransfer:
    host: str | None
    files: tuple[str, ...]
    dynamic_destination: bool


def _file_source(option: str, value: str) -> str:
    if option in {"-T", "--upload-file", "--post-file", "--body-file", "<"}:
        return value
    if option in {"-F", "--form"}:
        value = value.partition("=")[2].split(";", 1)[0]
        return value[1:] if value.startswith(("@", "<")) else ""
    if option == "--data-urlencode":
        return value.partition("@")[2] if "=" not in value else ""
    if option in {"-d", "--data", "--data-ascii", "--data-binary", "--json"}:
        return value.removeprefix("@") if value.startswith("@") else ""
    return ""


def _web_transfers(program: str, words: list[str]) -> Iterator[ShellTransfer]:
    curl = program == "curl"
    args = tuple(command_arguments(words, _CURL_VALUES if curl else _WGET_VALUES))
    payload = _CURL_PAYLOAD if curl else _WGET_PAYLOAD
    if not any(
        (option in payload and value)
        or (
            option in {"-X", "--request", "--method"}
            and value.upper() in {"POST", "PUT", "PATCH"}
        )
        for option, value in args
    ):
        return
    sources = tuple(
        source for key, value in args if (source := _file_source(key, value))
    )
    for option, destination in args:
        if option not in {"", "--url"} or not destination:
            continue
        authority = destination.split("://", 1)[-1].split("/", 1)[0]
        dynamic = bool(_EXPANSION.search(authority))
        try:
            host = urlsplit(
                destination if "://" in destination else "//" + destination
            ).hostname
        except ValueError:
            continue
        if host or dynamic:
            yield ShellTransfer(None if dynamic else host, sources, dynamic)


def shell_transfers(step: Step) -> Iterator[ShellTransfer]:
    for raw_command in shell_commands(step):
        command = unwrap_command(raw_command)
        if not command:
            continue
        program = posixpath.basename(command[0])
        if program in {"curl", "wget"}:
            yield from _web_transfers(program, command[1:])
        elif program in {"scp", "rsync"}:
            operands = [
                value
                for option, value in command_arguments(
                    command[1:], _SCP_VALUES if program == "scp" else _RSYNC_VALUES
                )
                if not option
            ]
            if len(operands) < 2:
                continue
            destination = operands[-1]
            remote = _REMOTE.fullmatch(destination)
            if destination.startswith(("rsync://", "scp://")):
                try:
                    host = urlsplit(destination).hostname
                except ValueError:
                    continue
                if host:
                    yield ShellTransfer(host, tuple(operands[:-1]), False)
            elif remote:
                yield ShellTransfer(remote[1].strip("[]"), tuple(operands[:-1]), False)
            elif _EXPANSION.match(destination):
                yield ShellTransfer(None, tuple(operands[:-1]), True)
        elif program in {"nc", "netcat", "ncat"}:
            args = tuple(command_arguments(command[1:], _NC_VALUES))
            operands = [value for option, value in args if not option]
            if len(operands) < 2 or any(
                option in {"-l", "-z", "-U", "--listen", "--zero", "--unixsock"}
                for option, _ in args
            ):
                continue
            destination = operands[0]
            sources = tuple(value for option, value in args if option == "<")
            if re.fullmatch(r"[\w.-]+|\[?[0-9a-f:]+\]?", destination, re.I):
                yield ShellTransfer(destination.strip("[]"), sources, False)
            elif _EXPANSION.match(destination):
                yield ShellTransfer(None, sources, True)
        elif program.lower() == "mail":
            yield from _mail_transfers(command[1:])
        elif program.lower() == "openssl":
            yield from _openssl_transfers(command[1:])
    yield from _python_transfers(step)


_MAIL_VALUES = {"-a", "-b", "-c", "-r", "-s", "-S", "--subject"}


def _mail_transfers(words: list[str]) -> Iterator[ShellTransfer]:
    args = tuple(command_arguments(words, _MAIL_VALUES))
    sources = tuple(value for option, value in args if option == "<" and value)
    for option, value in args:
        if option or "@" not in value:
            continue
        host = value.rsplit("@", 1)[1]
        if not host or host.startswith("-"):
            continue
        dynamic = bool(_EXPANSION.search(host))
        yield ShellTransfer(None if dynamic else host, sources, dynamic)


def _openssl_transfers(words: list[str]) -> Iterator[ShellTransfer]:
    """`openssl s_client -connect host:port`. Other subcommands are not sends."""
    if "s_client" not in words:
        return
    sources: list[str] = []
    host = ""
    dynamic = False
    index = 0
    while index < len(words):
        word = words[index]
        if word == "<" and index + 1 < len(words):
            sources.append(words[index + 1])
            index += 2
            continue
        target = ""
        if word == "-connect" and index + 1 < len(words):
            target = words[index + 1]
            index += 2
        elif word.startswith("-connect="):
            target = word.split("=", 1)[1]
            index += 1
        else:
            index += 1
            continue
        host = target.rsplit(":", 1)[0].strip("[]")
        dynamic = bool(_EXPANSION.search(host))
    if host or dynamic:
        yield ShellTransfer(None if dynamic else host, tuple(sources), dynamic)


def _python_sources(step: Step) -> Iterator[str]:
    if step.family_name not in SHELL_TOOLS:
        return
    for field, source in step.fields:
        if field in {"code", "script"}:
            yield source
        elif field in COMMAND_FIELDS:
            for match in _PYTHON_HEREDOC.finditer(source):
                yield match.group("body")
    for raw_command in shell_commands(step):
        command = unwrap_command(raw_command)
        if command and _PYTHON.fullmatch(posixpath.basename(command[0])):
            for option, value in command_arguments(
                command[1:], {"-c", "-m", "-W", "-X"}
            ):
                if option == "-c":
                    yield value
                    break
                if option in {"", "-m"}:
                    break


def shell_python_targets(step: Step) -> Iterator[str]:
    for source in _python_sources(step):
        deletions, _overwrites = _python_effects(source)
        yield from deletions


def shell_python_overwrites(step: Step) -> Iterator[str]:
    """Top-level Python calls that replace a file's contents."""
    for source in _python_sources(step):
        _deletions, overwrites = _python_effects(source)
        yield from overwrites


def _python_name(node: ast.expr, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, "")
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return imports.get(node.value.id, "") + "." + node.attr
    return ""


def _python_path(node: ast.expr | None, paths: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return paths.get(node.id, "")
    return ""


def _call_arg(call: ast.Call, name: str) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == name), None
    )


def _path_object(
    node: ast.expr,
    imports: dict[str, str],
    paths: dict[str, str],
    objects: dict[str, str],
) -> str | None:
    suffix: list[str] = []
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        suffix.append(_python_path(node.right, paths))
        node = node.left
    if isinstance(node, ast.Name):
        base = objects.get(node.id)
    elif (
        isinstance(node, ast.Call)
        and _python_name(node.func, imports) == "pathlib.Path"
    ):
        if not node.args and not node.keywords:
            base = "."
        else:
            parts = [_python_path(arg, paths) for arg in node.args]
            base = (
                posixpath.join(*parts)
                if parts and all(parts) and not node.keywords
                else ""
            )
    else:
        base = None
    if base is None or not suffix:
        return base
    return posixpath.join(base, *reversed(suffix)) if base and all(suffix) else ""


_NULL_DEVICE = {"/dev/null", "/dev/zero"}
_COPY_FUNCTIONS = {"shutil.copyfile", "shutil.copy", "shutil.copy2"}


def _callee(node: ast.expr, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name) and node.id == "open":
        return imports.get(node.id, "open")
    return _python_name(node, imports)


def _nth_arg(call: ast.Call, index: int, keyword: str) -> ast.expr | None:
    if len(call.args) > index:
        return call.args[index]
    return next((item.value for item in call.keywords if item.arg == keyword), None)


def _literal_text(node: ast.expr | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _open_write_target(
    call: ast.Call, imports: dict[str, str], paths: dict[str, str]
) -> str:
    """Path opened in a write mode. Opening with ``w`` truncates before close."""
    if _callee(call.func, imports) not in {"open", "io.open"}:
        return ""
    mode = "r"
    if len(call.args) >= 2:
        mode = _literal_text(call.args[1]) or mode
    else:
        for keyword in call.keywords:
            if keyword.arg == "mode":
                mode = _literal_text(keyword.value) or mode
    if mode[:1].lower() != "w":
        return ""
    target = call.args[0] if call.args else _nth_arg(call, 0, "file")
    return _python_path(target, paths)


_READ_ATTRS = frozenset({"read", "read_text", "read_bytes"})
_PY_OPENERS = frozenset({"open", "io.open", "pathlib.Path", "io.FileIO"})
_PY_COPIES = frozenset({"shutil.copy", "shutil.copy2", "shutil.copyfile"})


@dataclass
class _PyIo:
    imports: dict[str, str]
    strings: dict[str, str]
    handles: dict[str, str]
    openers: dict[str, str]
    fds: dict[str, str]
    reads: list[str]
    transfers: list[ShellTransfer]


def _py_resolve(node: ast.expr, state: _PyIo) -> str:
    if isinstance(node, ast.Name):
        if node.id in state.openers:
            return state.openers[node.id]
        if node.id in state.imports:
            return state.imports[node.id]
        return "open" if node.id == "open" else node.id
    if isinstance(node, ast.Attribute):
        parent = _py_resolve(node.value, state)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _const_str(node: ast.expr | None, strings: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return strings.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _const_str(node.left, strings)
        right = _const_str(node.right, strings)
        if left is None or right is None:
            return None
        return left + right
    return None


def _call_arg_expr(call: ast.Call, index: int, names: set[str]) -> ast.expr | None:
    if len(call.args) > index:
        return call.args[index]
    return next((item.value for item in call.keywords if item.arg in names), None)


def _opened_path(call: ast.Call, state: _PyIo) -> str | None:
    resolved = _py_resolve(call.func, state)
    if resolved not in _PY_OPENERS:
        return None
    if resolved == "pathlib.Path" and call.args and not call.keywords:
        raw = [_const_str(arg, state.strings) for arg in call.args]
        parts = [part for part in raw if part is not None]
        if raw and len(parts) == len(raw):
            return posixpath.join(*parts)
    return _const_str(_call_arg_expr(call, 0, {"file", "path"}), state.strings)


def _os_open_path(call: ast.Call, state: _PyIo) -> str | None:
    if _py_resolve(call.func, state) != "os.open":
        return None
    return _const_str(_call_arg_expr(call, 0, {"path"}), state.strings)


def _handle_path(node: ast.expr, state: _PyIo) -> str | None:
    if isinstance(node, ast.Call):
        return _opened_path(node, state)
    if isinstance(node, ast.Name):
        return state.handles.get(node.id)
    return None


def _getattr_read_path(call: ast.Call, state: _PyIo) -> str | None:
    if _py_resolve(call.func, state) not in {"getattr", "builtins.getattr"}:
        return None
    if len(call.args) < 2:
        return None
    attr = _const_str(call.args[1], state.strings)
    if attr not in _READ_ATTRS:
        return None
    return _handle_path(call.args[0], state)


def _note_urlopen(call: ast.Call, state: _PyIo) -> None:
    url = _const_str(_call_arg_expr(call, 0, {"url"}), state.strings)
    if not url:
        return
    if url.startswith("file:"):
        path = urlsplit(url).path
        if path:
            state.reads.append(path)
        return
    if not url.startswith(("http://", "https://")):
        return
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return
    dynamic = "$" in url or "`" in url
    if host or dynamic:
        state.transfers.append(ShellTransfer(None if dynamic else host, (), dynamic))


def _scan_expr(node: ast.expr, state: _PyIo) -> None:
    if isinstance(node, ast.Call):
        _scan_expr(node.func, state)
        for arg in node.args:
            _scan_expr(arg, state)
        for keyword in node.keywords:
            _scan_expr(keyword.value, state)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _READ_ATTRS:
            path = _handle_path(func.value, state)
            if path:
                state.reads.append(path)
        if isinstance(func, ast.Call):
            got = _getattr_read_path(func, state)
            if got:
                state.reads.append(got)
        resolved = _py_resolve(func, state)
        if resolved == "os.read" and node.args:
            descriptor = node.args[0]
            if isinstance(descriptor, ast.Name) and descriptor.id in state.fds:
                state.reads.append(state.fds[descriptor.id])
            elif isinstance(descriptor, ast.Call):
                opened = _os_open_path(descriptor, state)
                if opened:
                    state.reads.append(opened)
        if resolved in _PY_COPIES:
            source = _const_str(_call_arg_expr(node, 0, {"src"}), state.strings)
            if source and source not in _NULL_DEVICE:
                state.reads.append(source)
        if resolved == "urllib.request.urlopen":
            _note_urlopen(node, state)
        return
    if isinstance(node, ast.Attribute):
        _scan_expr(node.value, state)
    elif isinstance(node, ast.BinOp):
        _scan_expr(node.left, state)
        _scan_expr(node.right, state)
    elif isinstance(node, ast.BoolOp):
        for value in node.values:
            _scan_expr(value, state)
    elif isinstance(node, ast.UnaryOp):
        _scan_expr(node.operand, state)
    elif isinstance(node, ast.IfExp):
        _scan_expr(node.test, state)
        _scan_expr(node.body, state)
        _scan_expr(node.orelse, state)
    elif isinstance(node, ast.Compare):
        _scan_expr(node.left, state)
        for comparator in node.comparators:
            _scan_expr(comparator, state)
    elif isinstance(node, ast.Subscript):
        _scan_expr(node.value, state)
        _scan_expr(node.slice, state)
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for element in node.elts:
            _scan_expr(element, state)
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is not None:
                _scan_expr(key, state)
            _scan_expr(value, state)
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.expr):
                _scan_expr(value, state)
    elif isinstance(node, ast.FormattedValue):
        _scan_expr(node.value, state)


def _bind_python_name(target: ast.expr, value: ast.expr, state: _PyIo) -> None:
    if not isinstance(target, ast.Name):
        return
    name = target.id
    state.strings.pop(name, None)
    state.handles.pop(name, None)
    state.openers.pop(name, None)
    state.fds.pop(name, None)
    state.imports.pop(name, None)
    text = _const_str(value, state.strings)
    if text is not None:
        state.strings[name] = text
    if isinstance(value, ast.Name):
        resolved = _py_resolve(value, state)
        if resolved in _PY_OPENERS or resolved == "open":
            state.openers[name] = resolved
    if isinstance(value, ast.Call):
        opened = _opened_path(value, state)
        if opened:
            state.handles[name] = opened
        descriptor = _os_open_path(value, state)
        if descriptor:
            state.fds[name] = descriptor


def _bind_import(state: _PyIo, alias: ast.alias) -> None:
    if alias.asname:
        state.imports[alias.asname] = alias.name
        return
    head = alias.name.split(".", 1)[0]
    state.imports[head] = head


def _walk_python(body: list[ast.stmt], state: _PyIo) -> None:
    for statement in body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                _bind_import(state, alias)
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
            module = statement.module or ""
            for alias in statement.names:
                if alias.name == "*":
                    continue
                state.imports[alias.asname or alias.name] = (
                    f"{module}.{alias.name}" if module else alias.name
                )
        elif isinstance(statement, ast.Assign):
            _scan_expr(statement.value, state)
            for target in statement.targets:
                _bind_python_name(target, statement.value, state)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            _scan_expr(statement.value, state)
            _bind_python_name(statement.target, statement.value, state)
        elif isinstance(statement, ast.Expr):
            _scan_expr(statement.value, state)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nested = _PyIo(
                dict(state.imports),
                dict(state.strings),
                dict(state.handles),
                dict(state.openers),
                dict(state.fds),
                state.reads,
                state.transfers,
            )
            _walk_python(statement.body, nested)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            _scan_expr(statement.iter, state)
            _walk_python(statement.body, state)
            _walk_python(statement.orelse, state)
        elif isinstance(statement, (ast.While, ast.If)):
            _scan_expr(statement.test, state)
            _walk_python(statement.body, state)
            _walk_python(statement.orelse, state)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                _scan_expr(item.context_expr, state)
                if item.optional_vars is not None:
                    _bind_python_name(item.optional_vars, item.context_expr, state)
            _walk_python(statement.body, state)
        elif isinstance(statement, ast.Try):
            _walk_python(statement.body, state)
            for handler in statement.handlers:
                _walk_python(handler.body, state)
            _walk_python(statement.orelse, state)
            _walk_python(statement.finalbody, state)
        else:
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    _scan_expr(child, state)


def _python_io(source: str) -> tuple[list[str], list[ShellTransfer]]:
    try:
        program = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], []
    state = _PyIo({}, {}, {}, {}, {}, [], [])
    _walk_python(program.body, state)
    return state.reads, state.transfers


def _python_read_paths(source: str) -> Iterator[str]:
    """Paths a Python snippet reads without executing it.

    Counts a literal ``open`` / ``io.open`` / ``Path`` / ``FileIO`` call, a
    name bound to one of those, ``getattr(..., "read")``, ``os.open`` paired
    with ``os.read``, a string built with ``+``, and ``shutil.copy*`` of a
    real file. ``file://`` urlopen is a read. Nested function bodies count
    here; the destruction walk still ignores them.
    """
    reads, _transfers = _python_io(source)
    yield from reads


def _python_transfers(step: Step) -> Iterator[ShellTransfer]:
    for source in _python_sources(step):
        _reads, transfers = _python_io(source)
        yield from transfers


def _python_overwrite_path(
    call: ast.Call,
    imports: dict[str, str],
    paths: dict[str, str],
    objects: dict[str, str],
) -> str:
    """Path replaced by a top-level write, or empty when the call is not one."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in {"write_text", "write_bytes"}:
        return _path_object(func.value, imports, paths, objects) or ""
    if (
        isinstance(func, ast.Attribute)
        and func.attr in {"write", "writelines", "truncate"}
        and isinstance(func.value, ast.Call)
    ):
        written = _open_write_target(func.value, imports, paths)
        if written:
            return written
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "close"
        and isinstance(func.value, ast.Call)
    ):
        return _open_write_target(func.value, imports, paths)
    if _callee(func, imports) in {"open", "io.open"}:
        return _open_write_target(call, imports, paths)
    if _python_name(func, imports) in _COPY_FUNCTIONS:
        source = _python_path(_nth_arg(call, 0, "src"), paths)
        if source in _NULL_DEVICE:
            return _python_path(_nth_arg(call, 1, "dst"), paths)
    return ""


def _python_effects(source: str) -> tuple[list[str], list[str]]:
    try:
        program = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], []
    imports = {name: name for name in ("shutil", "os", "pathlib")}
    paths: dict[str, str] = {}
    objects: dict[str, str] = {}
    deletions: list[str] = []
    overwrites: list[str] = []
    for statement in program.body:
        if isinstance(statement, ast.Import):
            imports.update(
                (item.asname or item.name, item.name) for item in statement.names
            )
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
            imports.update(
                (item.asname or item.name, f"{statement.module}.{item.name}")
                for item in statement.names
            )
        elif isinstance(statement, ast.Assign):
            value = statement.value
            path = _python_path(value, paths)
            obj = _path_object(value, imports, paths, objects)
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    imports.pop(target.id, None)
                    paths[target.id] = obj if obj is not None else path
                    objects.pop(target.id, None)
                    if obj is not None:
                        objects[target.id] = obj
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if _python_name(call.func, imports) in _PATH_FUNCTIONS:
                arg = _call_arg(call, "path")
                obj = (
                    _path_object(arg, imports, paths, objects)
                    if arg is not None
                    else None
                )
                deletions.append(obj if obj is not None else _python_path(arg, paths))
            elif isinstance(call.func, ast.Attribute) and call.func.attr in {
                "unlink",
                "rmdir",
            }:
                obj = _path_object(call.func.value, imports, paths, objects)
                if obj is not None:
                    deletions.append(obj)
            written = _python_overwrite_path(call, imports, paths, objects)
            if written:
                overwrites.append(written)
    return deletions, overwrites
