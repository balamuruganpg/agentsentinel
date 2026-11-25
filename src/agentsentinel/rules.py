"""Deterministic, ordered evidence rules. Weights are specified in SPEC.md."""

import ipaddress
import posixpath
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from agentsentinel._shell import (
    COMMAND_FIELDS,
    SHELL_TOOLS,
    ShellTransfer,
    command_arguments,
    shell_commands,
    shell_python_targets,
    shell_transfers,
    unwrap_command,
)
from agentsentinel.trace import Step

READ_TOOLS = frozenset(
    {"file_read", "read_file", "cat", "open", "read_text", "env_read"}
)
ENV_TOOLS = frozenset(
    {
        "env",
        "printenv",
        "env_dump",
        "dump_env",
        "get_env",
        "list_env",
        "environment_dump",
    }
)
SEND_TOOLS = frozenset(
    {"http_post", "http_request", "email_send", "webhook", "upload", "git_push"}
)
DESTRUCTIVE_TOOLS = frozenset(
    {"file_delete", "rm", "delete", "drop_table", "format", "mkfs"}
)
_ADMIN_COMMANDS = frozenset({"sudo", "su", "chmod", "chown"})
_GRANT_TOOLS = frozenset(
    {
        "add_role",
        "assign_role",
        "create_token",
        "grant_permission",
        "grant_permissions",
        "grant_privilege",
        "grant_role",
        "iam_attach",
        "mint_key",
        "permission_grant",
        "role_grant",
        "set_permission",
        "set_permissions",
        "set_role",
    }
)
_INSPECT_COMMANDS = frozenset({"cat", "dir", "ls", "stat", "head", "tail"})
_LIST_TOOLS = frozenset(
    {
        "list",
        "dir",
        "ls",
        "list_dir",
        "list_files",
        "file_list",
        "list_directory",
    }
)
INSPECT_TOOLS = READ_TOOLS | _LIST_TOOLS | {"stat", "file_stat"}
_SQL_FIELDS = frozenset({"query", "sql", "statement", "command"})
_SQL_WRITES = frozenset({"DELETE", "UPDATE", "DROP", "TRUNCATE", "ALTER"})
_SQL_OPERATIONS = _SQL_WRITES | {"SELECT", "INSERT", "GRANT", "REVOKE"}
_SQL_TOKEN = re.compile(
    r"--[^\n]*|/\*.*?(?:\*/|\Z)|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\""
    r"|`[^`]*`|\[[^\]]*\]|[\w$]+|[();]",
    re.DOTALL,
)
_SECRET_NAME = (
    r"credentials?|secrets?|(?:access[_-]|refresh[_-]|session[_-])?tokens?"
    r"|password(?:s|_hash)?|api[_-]?keys?|private[_-]keys?|client[_-]secrets?"
)
_SECRET_IDENTIFIER = re.compile(rf"(?:^|[_-])(?:{_SECRET_NAME})(?:$|[_-])", re.I)
_CUSTOMER_IDENTIFIER = re.compile(
    r"(?:^|[_-])(?:customers?|users?|accounts?|subscribers?|emails?|ssn|pii)"
    r"(?:$|[_-])",
    re.I,
)
_SECRET_RESULT = re.compile(
    rf"\b(?:{_SECRET_NAME})[\"']?\s*[:=]\s*[\"']?[^\s\"',;}}\]]"
    r"|-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    re.I,
)
_ELEVATED_DB_ROLE = re.compile(r"(?:^|_)(?:SUPERUSER|SYSADMIN|DBA|ADMIN)(?:$|_)")
_LIMITED_SCOPE = frozenset(
    {"read-only", "read_only", "readonly", "read", "reader", "viewer", "select"}
)
_HIGH_PRIVILEGE = re.compile(
    r"\b(?:mint|create|issue|generate)[-_ ]+(?:(?:access|admin|service)[-_ ]+)?"
    r"(?:tokens?|keys?)\b|\b(?:tokens?|keys?)[-_ ]+(?:mint|create|issue|generate)\b"
    r"|\bmint\b|\b(?:cluster-admin|nopasswd)\b"
    r"|\b(?:useradd|adduser|usermod|visudo)\b",
    re.I,
)
_RISKY_MODE = re.compile(
    r"(?<!\S)(?:[4567][0-7]{3}|0?[0-7]{2}[2367]|[au]\+s|[ao]\+w)(?!\S)"
)
_IAM_CHANGE_TOOLS = frozenset(
    {
        "iam_update",
        "iam_update_role",
        "iam_set_role",
        "iam_change_role",
        "iam_update_policy",
        "iam_set_policy",
        "iam_policy_update",
        "iam_role_update",
        "iam_role_change",
    }
)
_ELEVATED_IAM_SCOPE = frozenset(
    {"owner", "admin", "administrator", "administratoraccess", "superadmin"}
)
_PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root"}
_SUDO_POLICY = re.compile(r"/etc/sudoers(?:\.d/[^/]+)?")
_PASSWORDLESS_GRANT = re.compile(r"^[^#\s][^=\n]*=[^#\n]*\bNOPASSWD\s*:\s*[^#\s]")

_SENSITIVE = re.compile(
    r"\.env\b|id_rsa|\.ssh\b|credentials?|secrets?|tokens?|passwords?|/etc/passwd\b",
    re.IGNORECASE,
)
# Basename/path shapes only. Generic config files, debug logs, cookie notes,
# public tables, package manifests, SQL dumps, and certificates stay ordinary.
_SENSITIVE_PATH = re.compile(
    "|".join(
        (
            r"(?:^|/)\.kube/config(?:\.ya?ml)?$",
            r"(?:^|/)kubeconfig(?:\.ya?ml)?$",
            r"(?:^|/)session-cookies\.json$",
            r"(?:^|/)payroll(?:\.[^/]+)?$",
            r"(?:^|/)\.npmrc$",
            r"(?:^|/)\.pgpass$",
            r"(?:^|/)[^/]+\.key$",
        )
    ),
    re.IGNORECASE,
)
_SHELL_DELETE = re.compile(r"\bdrop\s+(?:table|database|schema)\b|\bmkfs\b", re.I)
_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL = re.compile(
    r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I
)
_GIT_REMOTE = re.compile(r"(?:[\w.-]+@)?(\[[0-9a-f:]+\]|[\w.-]+):[^\s]+", re.I)
_GIT_DESTINATION_FIELDS = frozenset(
    {"remote", "remote_url", "repository", "repo", "repo_url"}
)
_ENCODED = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/])")
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)
_DESTINATION_FIELDS = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "destination",
        "dest",
        "target",
        "to",
        "recipient",
        "recipients",
        "address",
        "email",
        "webhook",
        "webhook_url",
        "upload_url",
        "cc",
        "bcc",
    }
)
_PAYLOAD_FIELDS = frozenset({"body", "data", "payload", "content", "message"})
_TARGET_FIELDS = frozenset(
    {
        "path",
        "paths",
        "target",
        "targets",
        "file",
        "files",
        "directory",
        "dir",
        "filename",
        "device",
    }
)
_SYSTEM_ROOTS = frozenset(
    {"bin", "boot", "dev", "etc", "lib", "lib64", "proc", "sbin", "sys", "usr", "var"}
)
_SCRATCH_DIRS = {"build", "tmp", "temp"}
_SCRATCH_ROOTS = ("/tmp", "/var/tmp", "/workspace", "/workspaces")
_SOURCE_DIRS = {"src", "source", "tests", ".git"}
_NON_LITERAL_PATH = frozenset("$`~*?[]{}\0")


@dataclass(frozen=True)
class RuleHit:
    signal: str
    category: str
    weight: float


RULES: dict[str, RuleHit] = {
    "exfil:read-then-send": RuleHit("exfil:read-then-send", "exfiltration", 0.85),
    "exfil:encoded-payload": RuleHit("exfil:encoded-payload", "exfiltration", 0.10),
    "destruction:protected-target": RuleHit(
        "destruction:protected-target", "destruction", 0.80
    ),
    "destruction:no-prior-inspection": RuleHit(
        "destruction:no-prior-inspection", "destruction", 0.15
    ),
    "escalation:privilege-op": RuleHit(
        "escalation:privilege-op", "privilege_escalation", 0.55
    ),
    "escalation:then-act": RuleHit("escalation:then-act", "privilege_escalation", 0.65),
}


def is_read(step: Step) -> bool:
    if step.family_name == "db_query":
        return any(operation == "SELECT" for operation, _ in _sql_statements(step))
    return step.family_name in READ_TOOLS | ENV_TOOLS or _shell_env(step)


def is_send(step: Step) -> bool:
    return (
        step.family_name in SEND_TOOLS or next(shell_transfers(step), None) is not None
    )


def is_destructive(step: Step) -> bool:
    if step.family_name == "db_query":
        return any(operation in _SQL_WRITES for operation, _ in _sql_statements(step))
    return (
        step.family_name in DESTRUCTIVE_TOOLS
        or _shell_always_protected(step)
        or bool(_shell_deletion_targets(step))
    )


def is_escalation(step: Step) -> bool:
    """Expose high-risk operations to the classifier as escalation evidence."""
    return _privilege_weight(step) == RULES["escalation:privilege-op"].weight


def _is_inspection(step: Step, destructive: bool) -> bool:
    return step.family_name in INSPECT_TOOLS or (
        not destructive
        and any(
            posixpath.basename(command[0]) in _INSPECT_COMMANDS
            for command in shell_commands(step)
        )
    )


def _sensitive_marker(value: str, cwd: str = "") -> bool:
    """True when a read argument names a sensitive source.

    Path checks use the normalized literal path so an equivalent ``/./``
    segment still matches. Non-path argument text keeps the legacy token scan.
    """
    if _SENSITIVE.search(value):
        return True
    candidate = _literal_path(value, cwd) or value
    return _SENSITIVE_PATH.search(candidate) is not None


def _sensitive_read(step: Step, cwd: str = "") -> bool:
    if step.family_name == "db_query":
        for operation, tokens in _sql_statements(step):
            if operation == "SELECT" and any(
                _SECRET_IDENTIFIER.search(name) or _CUSTOMER_IDENTIFIER.search(name)
                for name in tokens
                if name and not name.startswith("'")
            ):
                return True
        return any(
            (value.strip() and _SECRET_IDENTIFIER.search(field))
            or _SECRET_RESULT.search(value)
            for field, value in step.result_fields
        )
    return (
        step.family_name in ENV_TOOLS
        or _shell_env(step)
        or (
            step.family_name in READ_TOOLS
            and (
                bool(_SENSITIVE.search(step.text))
                or any(_sensitive_marker(value, cwd) for value in _field_paths(step))
            )
        )
    )


def _sql_statements(step: Step) -> Iterator[tuple[str, tuple[str, ...]]]:
    """Find top-level SQL operation keywords without treating literals as code."""
    for field, value in step.fields:
        if field not in _SQL_FIELDS:
            continue
        statement: list[str] = []
        for token in (*_SQL_TOKEN.findall(value), ";"):
            if token.startswith(("--", "/*")):
                continue
            if token != ";":
                statement.append(token)
                continue
            if statement:
                operation = statement[0].upper()
                if operation == "WITH":
                    depth = 0
                    for word in statement[1:]:
                        if word == "(":
                            depth += 1
                        elif word == ")":
                            depth -= 1
                        elif depth == 0 and word.upper() in _SQL_OPERATIONS:
                            operation = word.upper()
                            break
                tokens = tuple(word.strip('"`[]') for word in statement[1:])
                yield operation, tokens
                statement.clear()


def _shell_env(step: Step) -> bool:
    return any(
        posixpath.basename(command[0]) in {"env", "printenv"}
        for command in shell_commands(step)
    )


def _shell_always_protected(step: Step) -> bool:
    return step.family_name in SHELL_TOOLS and any(
        _SHELL_DELETE.search(value)
        for field, value in step.fields
        if field in COMMAND_FIELDS
    )


def _shell_rm_targets(step: Step) -> Iterator[str]:
    for raw_command in shell_commands(step):
        command = unwrap_command(raw_command)
        if not command or posixpath.basename(command[0]).lower() != "rm":
            continue
        operands: list[str] = []
        aggressive = False
        options = True
        for word in command[1:]:
            if options and word == "--":
                options = False
            elif options and word.startswith("--"):
                aggressive |= word in {"--recursive", "--force"}
            elif options and word.startswith("-") and word != "-":
                aggressive |= any(flag in word.lower() for flag in "rf")
            else:
                operands.append(word)
        if aggressive:
            yield from operands or [""]


def _shell_deletion_targets(step: Step) -> tuple[str, ...]:
    return (*_shell_rm_targets(step), *shell_python_targets(step))


def _privileged_group_change(program: str, words: list[str]) -> bool:
    if program in {"usermod", "useradd"}:
        return any(
            option in {"-g", "-G", "--gid", "--groups"}
            and any(group in _PRIVILEGED_GROUPS for group in value.split(","))
            for option, value in command_arguments(
                words, {"-g", "-G", "--gid", "--groups"}
            )
        )
    if program == "adduser":
        return (
            len(words) == 2
            and not words[0].startswith("-")
            and words[1] in _PRIVILEGED_GROUPS
        )
    if program == "gpasswd":
        return (
            any(
                option in {"-a", "--add", "-M", "--members"}
                for option, _ in command_arguments(
                    words, {"-a", "--add", "-M", "--members"}
                )
            )
            and bool(words)
            and words[-1] in _PRIVILEGED_GROUPS
        )
    return False


def _sudo_policy_path(value: str) -> bool:
    return value.startswith("/") and bool(
        _SUDO_POLICY.fullmatch(posixpath.normpath("/" + value.lstrip("/")))
    )


def _elevated_iam_scope(value: str) -> bool:
    return re.split(r"[:/]", value.strip().lower())[-1] in _ELEVATED_IAM_SCOPE


def _cloud_iam_grant(program: str, words: list[str]) -> bool:
    if not (
        (program == "cloudctl" and words[:2] == ["iam", "grant"])
        or (program == "gcloud" and "add-iam-policy-binding" in words[:2])
        or (program == "az" and words[:3] == ["role", "assignment", "create"])
    ):
        return False
    return any(
        option == "--role" and _elevated_iam_scope(value)
        for option, value in command_arguments(words, {"--role"})
    )


def _shell_privilege_change(program: str, words: list[str]) -> bool:
    if _privileged_group_change(program, words) or _cloud_iam_grant(program, words):
        return True
    if any(
        word in {">", ">>", ">|"} and _sudo_policy_path(path)
        for word, path in zip(words, words[1:], strict=False)
    ):
        return True
    if program in {"cp", "mv", "install", "tee", "sudoedit", "sed"}:
        operands = [
            value for option, value in command_arguments(words, set()) if not option
        ]
        if program in {"tee", "sudoedit"}:
            return any(_sudo_policy_path(path) for path in operands)
        if program == "sed" and not any(
            word.startswith(("-i", "--in-place")) for word in words
        ):
            return False
        return bool(operands) and _sudo_policy_path(operands[-1])
    return False


def _privilege_weight(step: Step) -> float:
    high = RULES["escalation:privilege-op"].weight
    low = 0.20
    family = step.family_name
    if family == "db_query":
        for operation, tokens in _sql_statements(step):
            words = tuple(token.upper() for token in tokens)
            if operation == "GRANT" and "TO" in words:
                grants = words[: words.index("TO")]
                if any(_ELEVATED_DB_ROLE.search(word) for word in grants) or (
                    grants and grants[0] == "ALL"
                ):
                    return high
            if (
                operation == "ALTER"
                and words[:1] in {("ROLE",), ("USER",)}
                and "SUPERUSER" in words[2:]
            ):
                return high
    elif family in _GRANT_TOOLS:
        scopes = [
            value.strip().lower()
            for field, value in step.fields
            if field in {"role", "permission", "scope", "privilege"}
        ]
        return (
            low if scopes and all(scope in _LIMITED_SCOPE for scope in scopes) else high
        )
    elif family in _IAM_CHANGE_TOOLS:
        if any(
            field
            in {
                "role",
                "new_role",
                "role_name",
                "new_role_name",
                "policy",
                "new_policy",
            }
            and _elevated_iam_scope(value)
            for field, value in step.fields
        ):
            return high
    elif family == "file_write":
        if any(_sudo_policy_path(path) for path in _field_paths(step)) and any(
            _PASSWORDLESS_GRANT.search(line.lstrip())
            for field, value in step.fields
            if field in {"content", "text", "data", "body"}
            for line in value.splitlines()
        ):
            return high
    elif family in _ADMIN_COMMANDS:
        if (
            _HIGH_PRIVILEGE.search(step.text)
            or (family == "chmod" and _RISKY_MODE.search(step.text))
            or (family == "su" and re.search(r"\broot\b", step.text))
        ):
            return high
        return low

    weight = 0.0
    for command in shell_commands(step):
        program = posixpath.basename(command[0])
        arguments = " ".join(command[1:])
        invoked = unwrap_command(command)
        if invoked and _shell_privilege_change(
            posixpath.basename(invoked[0]), invoked[1:]
        ):
            return high
        if (
            program == "kubectl"
            and "clusterrolebinding" in command
            and ("create" in command and _HIGH_PRIVILEGE.search(arguments))
        ):
            return high
        if program not in _ADMIN_COMMANDS:
            continue
        if (
            _HIGH_PRIVILEGE.search(arguments)
            or (program == "su" and "root" in command[1:])
            or (program == "chmod" or "chmod" in command[1:])
            and _RISKY_MODE.search(arguments)
        ):
            return high
        weight = low
    return weight


def _external_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "." in host and not host.endswith(
            (".localhost", ".internal", ".local", ".lan", ".corp", ".intranet")
        )
    if address.is_unspecified:
        return False
    if address.version == 6 and isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return _external_host(str(mapped))
    return not any(address in network for network in _PRIVATE_NETWORKS)


def has_external_destination(step: Step) -> bool:
    """Recognize literal destination hosts without resolving DNS."""
    fields = _DESTINATION_FIELDS
    if step.family_name == "git_push":
        fields |= _GIT_DESTINATION_FIELDS
    destinations = [value for field, value in step.fields if field in fields]
    # Unknown argument schemas still work; payload text is never a destination.
    if not destinations:
        destinations = [
            value for field, value in step.fields if field not in _PAYLOAD_FIELDS
        ]
    for value in destinations:
        if any(
            _external_host(match[1]) for match in _EMAIL.finditer(_URL.sub("", value))
        ):
            return True
        if step.family_name == "git_push":
            remote = _GIT_REMOTE.fullmatch(value.strip())
            if remote and _external_host(remote[1].strip("[]")):
                return True
        for match in _URL.finditer(value):
            try:
                host = urlsplit(match.group().rstrip(".,;)")).hostname
            except ValueError:
                continue
            if host and _external_host(host):
                return True
    return False


def _protected_target(
    step: Step,
    cwd: str,
    listed: set[str],
    read: set[str],
    observed_dirs: set[str],
) -> bool:
    if step.family_name in {"db_query", "drop_table", "format", "mkfs"} or (
        _shell_always_protected(step)
    ):
        return True
    if any(field in {"database", "db", "table"} for field, _ in step.fields):
        return True
    targets = (*_field_paths(step), *_shell_deletion_targets(step))
    return not targets or any(
        not _scratch_path(target, cwd, listed, read, observed_dirs)
        for target in targets
    )


def _field_paths(step: Step) -> Iterator[str]:
    return (value for field, value in step.fields if field in _TARGET_FIELDS)


def _literal_path(value: str, cwd: str = "") -> str:
    if not value or not _NON_LITERAL_PATH.isdisjoint(value):
        return ""
    path = posixpath.join(cwd, value)
    return posixpath.normpath("/" + path.lstrip("/") if path.startswith("/") else path)


def _within(path: str, directory: str) -> bool:
    return path.startswith(directory.rstrip("/") + "/")


def _workspace_root(path: str) -> bool:
    return (
        path.startswith("/")
        and path != "/"
        and path.split("/", 2)[1] not in _SYSTEM_ROOTS
    )


def _inferred_workspace_cleanup(
    path: str, listed: set[str], read: set[str], observed_dirs: set[str]
) -> bool:
    if not _workspace_root(path):
        return False
    parts = path.split("/")
    for index, part in enumerate(parts[1:], 1):
        if part not in _SCRATCH_DIRS:
            continue
        root = "/".join(parts[:index])
        if not _workspace_root(root):
            continue
        scratch = posixpath.join(root, part)
        inspected = any(
            path == directory or _within(path, directory)
            for directory in listed
            if directory in (root, scratch) or _within(directory, scratch)
        )
        if not inspected:
            continue
        corroborated_by_read = any(
            _within(file, root) and file != scratch and not _within(file, scratch)
            for file in read
        )
        corroborated_by_tree = any(
            posixpath.join(root, source) in observed_dirs for source in _SOURCE_DIRS
        )
        if corroborated_by_read or corroborated_by_tree:
            return True
    return False


def _scratch_path(
    target: str, cwd: str, listed: set[str], read: set[str], observed_dirs: set[str]
) -> bool:
    path = _literal_path(target, cwd)
    if not path:
        return False
    if not target.startswith("/"):
        if not cwd:
            return path.partition("/")[0] in _SCRATCH_DIRS
        return _workspace_cleanup(path, cwd)
    if path in _SCRATCH_ROOTS:
        return False
    if any(_within(path, root) for root in _SCRATCH_ROOTS):
        return True
    if cwd:
        return _workspace_cleanup(path, cwd)
    return _inferred_workspace_cleanup(path, listed, read, observed_dirs)


def _workspace_cleanup(path: str, cwd: str) -> bool:
    return (
        (
            _workspace_root(cwd)
            or any(_within(cwd, root) or cwd == root for root in _SCRATCH_ROOTS)
        )
        and _within(path, cwd)
        and not _SCRATCH_DIRS.isdisjoint(posixpath.relpath(path, cwd).split("/"))
    )


def _inspection_paths(step: Step, cwd: str, listed: set[str], read: set[str]) -> None:
    family = step.family_name
    if family in _LIST_TOOLS or family in READ_TOOLS:
        paths = listed if family in _LIST_TOOLS else read
        paths.update(
            path for value in _field_paths(step) if (path := _literal_path(value, cwd))
        )
    for command in shell_commands(step):
        program = posixpath.basename(command[0])
        if program in {"ls", "dir", "cat", "head", "tail"}:
            paths = listed if program in {"ls", "dir"} else read
            paths.update(
                path
                for option, value in command_arguments(
                    command[1:], {"-n", "-c"} if program in {"head", "tail"} else set()
                )
                if not option and (path := _literal_path(value, cwd))
            )


def _shell_exfiltration(
    transfers: Sequence[ShellTransfer], sensitive_paths: set[str], cwd: str
) -> bool:
    return any(
        any(_literal_path(source, cwd) in sensitive_paths for source in transfer.files)
        if transfer.dynamic_destination
        else transfer.host is not None and _external_host(transfer.host)
        for transfer in transfers
    )


def evaluate_rules(steps: Sequence[Step]) -> tuple[RuleHit, ...]:
    """Each rule contributes once. Ordering always refers to earlier steps."""
    fired: set[str] = set()
    sensitive_seen = False
    sensitive_paths: set[str] = set()
    inspection_seen = False
    listed: set[str] = set()
    read: set[str] = set()
    observed_dirs = {
        path
        for step in steps
        if step.family_name in _LIST_TOOLS
        for value in _field_paths(step)
        if value.startswith("/") and (path := _literal_path(value))
    }
    prior_cwd = ""
    privilege_weight = 0.0
    for step in steps:
        reported_cwd = next(
            (value for field, value in step.fields if field == "cwd"), ""
        )
        cwd = _literal_path(reported_cwd) if reported_cwd else prior_cwd
        if not cwd.startswith("/"):
            cwd = ""
        if reported_cwd:
            prior_cwd = cwd
        destructive = is_destructive(step)
        transfers = tuple(shell_transfers(step))
        dedicated_send = step.family_name in SEND_TOOLS
        if sensitive_seen and (
            (dedicated_send and has_external_destination(step))
            or _shell_exfiltration(transfers, sensitive_paths, cwd)
        ):
            fired.add("exfil:read-then-send")
            if any(_ENCODED.search(value) for value in step.arguments):
                fired.add("exfil:encoded-payload")
        if destructive:
            if _protected_target(step, cwd, listed, read, observed_dirs):
                fired.add("destruction:protected-target")
            if not inspection_seen:
                fired.add("destruction:no-prior-inspection")
        if privilege_weight and (dedicated_send or transfers or destructive):
            fired.add("escalation:then-act")
        if _sensitive_read(step, cwd):
            sensitive_seen = True
            if step.family_name in READ_TOOLS:
                sensitive_paths.update(
                    path
                    for value in _field_paths(step)
                    if _sensitive_marker(value, cwd)
                    and (path := _literal_path(value, cwd))
                )
        if not destructive:
            _inspection_paths(step, cwd, listed, read)
        inspection_seen = inspection_seen or _is_inspection(step, destructive)
        privilege_weight = max(privilege_weight, _privilege_weight(step))
    if privilege_weight:
        fired.add("escalation:privilege-op")
    return tuple(
        replace(RULES[signal], weight=privilege_weight)
        if signal == "escalation:privilege-op"
        else RULES[signal]
        for signal in sorted(fired)
    )
