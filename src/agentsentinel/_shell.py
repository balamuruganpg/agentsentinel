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
_SUBSTITUTED_READ = re.compile(
    r"(?:\$\(|<\()\s*(?:cat|head|tail|type|base64|nl)\s+([^)]*)",
    re.IGNORECASE,
)


def shell_commands(step: Step) -> Iterator[list[str]]:
    if step.family_name not in SHELL_TOOLS:
        return
    for field, value in step.fields:
        if field not in COMMAND_FIELDS:
            continue
        for command in _split_shell_commands(value):
            yield command
            invoked = unwrap_command(command)
            if (
                len(invoked) >= 3
                and posixpath.basename(invoked[0]) in {"bash", "sh"}
                and _SHELL_COMMAND_OPTION.fullmatch(invoked[1])
            ):
                yield from _split_shell_commands(invoked[2])


def _split_shell_commands(value: str) -> Iterator[list[str]]:
    lexer = shlex.shlex(value, posix=True, punctuation_chars=_SEPARATORS + "<>")
    lexer.whitespace_split = True
    lexer.whitespace = " \t\r"
    try:
        tokens = list(lexer)
    except ValueError:
        return
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


def _substituted_reads(value: str) -> Iterator[str]:
    for match in _SUBSTITUTED_READ.finditer(value):
        inner = match.group(1).strip()
        if not inner:
            continue
        operand = _quoted_operand(inner.split()[0])
        if operand:
            yield operand


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


def _commands_keeping_backslashes(value: str) -> Iterator[list[str]]:
    """Tokenize a copy where backslashes are path separators, not escapes."""
    for command in _split_shell_commands(value.replace("\\", "/")):
        yield command
        invoked = unwrap_command(command)
        if (
            len(invoked) >= 3
            and posixpath.basename(invoked[0]) in {"bash", "sh"}
            and _SHELL_COMMAND_OPTION.fullmatch(invoked[1])
        ):
            yield from _split_shell_commands(invoked[2].replace("\\", "/"))


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
        for operand in _substituted_reads(value):
            yield from emit(operand)
        for command in _commands_keeping_backslashes(value):
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


def _python_sources(step: Step) -> Iterator[str]:
    if step.family_name not in SHELL_TOOLS:
        return
    for field, source in step.fields:
        if field in {"code", "script"}:
            yield source
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


def _call_string_path(node: ast.expr) -> str:
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    name = func.id if isinstance(func, ast.Name) else ""
    if not name and isinstance(func, ast.Attribute):
        name = func.attr
    if name not in {"open", "Path"}:
        return ""
    if node.args:
        return _literal_text(node.args[0])
    for keyword in node.keywords:
        if keyword.arg in {"file", "path"}:
            return _literal_text(keyword.value)
    return ""


def _python_read_paths(source: str) -> Iterator[str]:
    """Literal paths passed to open().read or Path.read_text/read_bytes."""
    try:
        program = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return
    for node in ast.walk(program):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"read", "read_text", "read_bytes"}:
            continue
        path = _call_string_path(node.func.value)
        if path:
            yield path


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
