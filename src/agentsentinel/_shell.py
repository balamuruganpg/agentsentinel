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
COMMAND_FIELDS = frozenset({"command", "cmd", "command_line", "script", "code"})
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
_REDIRECTS = {"<", "<<", "<<<", ">", ">>", "<>", ">|"}


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


def unwrap_command(command: list[str]) -> list[str]:
    if posixpath.basename(command[0]) in {"sudo", "command"}:
        return next(
            (
                command[index:]
                for index, word in enumerate(command[1:], 1)
                if not word.startswith("-")
            ),
            [],
        )
    return command


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


def shell_python_targets(step: Step) -> Iterator[str]:
    if step.family_name not in SHELL_TOOLS:
        return
    for field, source in step.fields:
        if field in {"code", "script"}:
            yield from _python_targets(source)
    for raw_command in shell_commands(step):
        command = unwrap_command(raw_command)
        if command and _PYTHON.fullmatch(posixpath.basename(command[0])):
            for option, value in command_arguments(
                command[1:], {"-c", "-m", "-W", "-X"}
            ):
                if option == "-c":
                    yield from _python_targets(value)
                    break
                if option in {"", "-m"}:
                    break


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


def _python_targets(source: str) -> Iterator[str]:
    try:
        program = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return
    imports = {name: name for name in ("shutil", "os", "pathlib")}
    paths: dict[str, str] = {}
    objects: dict[str, str] = {}
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
                yield obj if obj is not None else _python_path(arg, paths)
            elif isinstance(call.func, ast.Attribute) and call.func.attr in {
                "unlink",
                "rmdir",
            }:
                obj = _path_object(call.func.value, imports, paths, objects)
                if obj is not None:
                    yield obj
