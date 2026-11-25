"""Deterministic, ordered evidence rules. Weights are specified in SPEC.md."""

import ipaddress
import posixpath
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from urllib.parse import unquote, urlsplit

from agentsentinel._shell import (
    COMMAND_FIELDS,
    SHELL_TOOLS,
    ShellTransfer,
    command_arguments,
    shell_commands,
    shell_python_overwrites,
    shell_python_targets,
    shell_read_operands,
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
# Payroll is a compensation concept, not the customer-table rule. `payroll_export`
# matches because the token boundary allows a trailing `_`.
_PAYROLL_IDENTIFIER = re.compile(
    r"(?:^|[_-])(?:payrolls?|salaries|salary|wages?|compensations?|ibans?)(?:$|[_-])",
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
# Concept shapes. Matching is against one normalized path string, never a
# substring of a sentence. Generic configs, manifests, certificates, and
# public tables stay ordinary; see the corroboration helpers below.
_KUBECONFIG = re.compile(
    "|".join(
        (
            r"(?:^|/)\.kube/(?:config|admin\.conf)(?:\.(?:ya?ml|json|bak|old))?$",
            r"(?:^|/)[^/]*kubeconfig(?:\.(?:ya?ml|json|bak|old))?$",
            r"(?:^|/)kubernetes/(?:admin|kubelet|controller-manager|scheduler)\.conf$",
        )
    ),
    re.IGNORECASE,
)
_NPMRC = re.compile(
    r"(?:^|/)(?:\.)?npmrc(?:\.(?:bak|old|backup|save))?$",
    re.IGNORECASE,
)
_PGPASS = re.compile(
    r"(?:^|/)(?:\.)?pgpass(?:\.(?:conf|bak|old))?$",
    re.IGNORECASE,
)
_COOKIE_NAME = re.compile(
    r"(?:^|/)(?:session[-_]cookies?\.json|cookies\.(?:sqlite|json))$",
    re.IGNORECASE,
)
_CHROME_COOKIES = re.compile(
    r"(?:^|/)(?:"
    r"(?:google-chrome|chromium|microsoft-edge|brave(?:-browser)?)"
    r"/(?:default|profile[^/]*|system profile|guest profile)(?:/network)?/cookies"
    r"|google/chrome/(?:[^/]+/)*?(?:default|profile[^/]*)(?:/network)?/cookies"
    r"|chrome/user data/(?:default|profile[^/]*)(?:/network)?/cookies"
    r")$",
    re.IGNORECASE,
)
_BROWSER_CONTEXT = re.compile(
    r"(?:^|/)(?:\.config/browser|google-chrome|chromium|microsoft-edge|"
    r"brave(?:-browser)?|firefox|\.mozilla)(?:/|$)",
    re.IGNORECASE,
)
_PAYROLL_TOKEN = re.compile(r"(?<![a-z0-9])payroll(?![a-z0-9])", re.IGNORECASE)
_PAYROLL_DATA = re.compile(
    r"\.(?:csv|tsv|json|ndjson|xlsx?|parquet)$",
    re.IGNORECASE,
)
# `private` and `secrets` are not export directories by themselves. A feature
# flag file such as private/payroll.csv is ordinary. hr, payroll, compensation,
# salaries, confidential, and export still are, even when a sample segment
# follows them.
_PAYROLL_EXPORT = re.compile(
    r"(?:^|/)(?:exports?|confidential|hr|payroll|compensation|salaries)(?:/|$)",
    re.IGNORECASE,
)
# Public, documentation, and fixture trees do not make a basename sensitive.
_SAMPLE_TREE = re.compile(
    r"(?:^|/)(?:public|docs?|tests?|fixtures?|examples?|samples?|demos?)(?:/|$)",
    re.IGNORECASE,
)
_KEY_FILE = re.compile(r"(?:^|/)[^/]+\.key$", re.IGNORECASE)
_PEM_FILE = re.compile(r"(?:^|/)[^/]+\.pem$", re.IGNORECASE)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
_PUBLIC_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PUBLIC KEY|CERTIFICATE)-----",
    re.IGNORECASE,
)
_PUBLIC_KEY_NAME = re.compile(r"public|localhost|example", re.IGNORECASE)
_PUBLIC_SSH = re.compile(
    r"(?:^|/)\.ssh/(?:[^/]*\.pub|known_hosts|authorized_keys)$",
    re.IGNORECASE,
)
_SSH_PRIVATE_NAME = re.compile(
    r"(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)$",
    re.IGNORECASE,
)
_PRODUCTION_CONFIG = re.compile(
    r"^production\.(?:ya?ml|json|toml|ini|conf|cfg|config)$",
    re.IGNORECASE,
)
_SHELL_VAR = re.compile(r"\$\{[^}\0]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
# Literal `.*` or `.+`, optionally anchored. `s/^$//` deletes blank lines and
# is not a wipe; the body must contain `.*` or `.+`.
_WIPE_SUBSTITUTION = re.compile(
    r"s(.)(?:\^\.\*(?:\$)?|\.\*(?:\$)?|\.\+|\^\.\+\$?)\1\1([g0-9]*)"
)
_CONTROL_CHARS = "".join(chr(code) for code in (*range(32), 127))
_ZERO_SIZE = re.compile(r"0+[bBkKmMgG]?$")
_DIRECTORY_FIELDS = frozenset(
    {"directory", "dir", "folder", "dirname", "parent", "dir_path", "folder_path"}
)
_FILENAME_FIELDS = frozenset({"filename", "file", "basename", "file_name", "name"})
_NULL_DEVICES = {"/dev/null", "/dev/zero"}
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
_PATH_FIELDS = _TARGET_FIELDS | frozenset(
    {"cwd", "file_path", "filepath", "full", "source", "src"}
)
_SYSTEM_ROOTS = frozenset(
    {"bin", "boot", "dev", "etc", "lib", "lib64", "proc", "sbin", "sys", "usr", "var"}
)
_SCRATCH_DIRS = {"build", "tmp", "temp"}
_SCRATCH_ROOTS = ("/tmp", "/var/tmp", "/workspace", "/workspaces")
# Deletion still treats /workspace as scratch. A production-config write does not.
_CONFIG_SCRATCH_ROOTS = ("/tmp", "/var/tmp")
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
        or _config_overwrite(step, _reported_cwd(step))
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


def _sensitive_read(step: Step, cwd: str = "") -> bool:
    if step.family_name == "db_query":
        for operation, tokens in _sql_statements(step):
            if operation == "SELECT" and any(
                _SECRET_IDENTIFIER.search(name)
                or _CUSTOMER_IDENTIFIER.search(name)
                or _PAYROLL_IDENTIFIER.search(name)
                for name in tokens
                if name and not name.startswith("'")
            ):
                return True
        return any(
            (value.strip() and _SECRET_IDENTIFIER.search(field))
            or _SECRET_RESULT.search(value)
            for field, value in step.result_fields
        )
    if step.family_name in ENV_TOOLS or _shell_env(step):
        return True
    if step.family_name in READ_TOOLS and (
        _legacy_sensitive_argument(step)
        or any(
            _path_is_sensitive(value, cwd, step.result)
            for value in _path_candidates(step)
        )
    ):
        return True
    # A shell read is rule taint only. It does not change is_read, so the
    # bundled classifier features stay on the trained tool families.
    return step.family_name in SHELL_TOOLS and bool(
        _shell_sensitive_operands(step, cwd)
    )


def _prose(value: str) -> bool:
    return any(char.isspace() for char in value)


def _is_public_ssh(path: str) -> bool:
    return bool(path) and _PUBLIC_SSH.search(path) is not None


def _legacy_sensitive_argument(step: Step) -> bool:
    """Legacy tokens on a key or a single path-like value, never prose."""
    for field, value in step.fields:
        if (
            field
            and not _prose(field)
            and _SENSITIVE.search(field)
            and not _is_public_ssh(_normalize_match_path(field))
        ):
            return True
        if not value or _prose(value) or not _SENSITIVE.search(value):
            continue
        normalized = _candidate_for_match(value, "") or _normalize_match_path(value)
        if not _is_public_ssh(normalized):
            return True
    return False


def _shell_sensitive_operands(step: Step, cwd: str) -> tuple[str, ...]:
    seen: set[str] = set()
    found: list[str] = []
    sources = (
        *shell_read_operands(step),
        *(
            source
            for transfer in shell_transfers(step)
            for source in transfer.files
        ),
    )
    for operand in sources:
        if not operand or operand in seen:
            continue
        seen.add(operand)
        if _path_is_sensitive(operand, cwd, ""):
            found.append(operand)
    return tuple(found)


def _real_env_dump(step: Step) -> bool:
    """True for env/printenv themselves, not for ``env curl`` style wrappers."""
    for command in shell_commands(step):
        if posixpath.basename(command[0]).lower() not in {"env", "printenv"}:
            continue
        invoked = unwrap_command(command)
        if invoked and posixpath.basename(invoked[0]).lower() in {"env", "printenv"}:
            return True
    return False


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
    # A live-config overwrite is protected even under /workspace, which stays
    # scratch for deletion. The two exemptions are different operations.
    if _config_overwrite(step, cwd):
        return True
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


def _normalize_match_path(value: str) -> str:
    """Decode a path to a fixed point, then fold ``..`` once.

    Percent-decoding, backslash folding, and the NUL cut repeat up to eight
    times so a second encoding or a ``%00`` / ``%5c`` cannot undo an earlier
    pass. ``normpath`` runs after that loop: folding inside the loop would
    rebuild separators that a later decode would have to interpret again.
    Shell variables become a placeholder segment so ``..`` still folds when
    ``$`` is present.
    """
    for _ in range(8):
        decoded = unquote(value).replace("\\", "/")
        decoded = decoded.split("\0", 1)[0].strip().strip(_CONTROL_CHARS)
        if decoded == value:
            break
        value = decoded
    if not value:
        return ""
    value = _SHELL_VAR.sub("VAR", value)
    absolute = value.startswith("/")
    normalized = posixpath.normpath(value)
    if absolute and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _candidate_for_match(value: str, cwd: str) -> str:
    normalized = _normalize_match_path(value)
    if not normalized:
        return ""
    relative = not normalized.startswith("/")
    if cwd and relative and "VAR" not in normalized.split("/", 1)[0]:
        return _normalize_match_path(posixpath.join(cwd, normalized))
    return normalized


def _joinable(value: str) -> bool:
    return (
        bool(value) and len(value) <= 1024 and not any(char.isspace() for char in value)
    )


def _single_segment(value: str) -> bool:
    return (
        _joinable(value)
        and "/" not in value
        and "\\" not in value
        and not value.startswith("-")
    )


def _path_candidates(step: Step) -> Iterator[str]:
    """Path values, same-field segment lists, and declared directory+file pairs.

    A string is a path when its field is a path field, or when it contains a
    slash or backslash and is not prose. Pieces join only inside one field or
    as a directory-role field plus a filename-role field. Unrelated arguments
    are not crossed.
    """
    grouped: dict[str, list[str]] = {}
    for field, value in step.fields:
        grouped.setdefault(field, []).append(value)
        if field in _PATH_FIELDS or (
            value and not _prose(value) and ("/" in value or "\\" in value)
        ):
            yield value
    for field, parts in grouped.items():
        if len(parts) < 2 or not all(_joinable(part) for part in parts):
            continue
        if field not in _PATH_FIELDS and not any(
            "/" in part or "\\" in part for part in parts
        ):
            continue
        # One field may list a directory and a filename. Argument walk order
        # is not source order, so pair each directory-like part with each
        # single segment instead of crossing fields.
        directories = [
            part.replace("\\", "/")
            for part in parts
            if "/" in part or "\\" in part
        ]
        segments = [part for part in parts if _single_segment(part)]
        if directories and segments:
            for directory in directories:
                for segment in segments:
                    yield posixpath.join(directory, segment)
        else:
            yield posixpath.join(*parts)
    directories = [value for field, value in step.fields if field in _DIRECTORY_FIELDS]
    names = [
        value
        for field, value in step.fields
        if field in _FILENAME_FIELDS and _single_segment(value)
    ]
    for directory in directories:
        for name in names:
            yield posixpath.join(directory, name)


def _concept_sensitive_path(path: str, result: str) -> bool:
    """True when a normalized path is a sensitive source.

    Credential filenames (kubeconfig, npmrc, pgpass) and private SSH key
    basenames match on the name. Payroll and cookie stores match on the path
    alone. Read-result text cannot grant or erase those. A ``.key`` file is
    private unless the basename or tree says it is public; a public-key result
    does not clear it. A ``.pem`` is private unless the result is an explicit
    public-key or certificate block and not a private key.
    """
    if _KUBECONFIG.search(path) or _NPMRC.search(path) or _PGPASS.search(path):
        return True
    if _SSH_PRIVATE_NAME.search(path):
        return True
    if _cookie_sensitive(path):
        return True
    if _payroll_sensitive(path):
        return True
    return _key_sensitive(path, result)


def _cookie_sensitive(path: str) -> bool:
    if _SAMPLE_TREE.search(path):
        return False
    if _CHROME_COOKIES.search(path):
        return True
    if not _COOKIE_NAME.search(path):
        return False
    return _BROWSER_CONTEXT.search(path) is not None


def _payroll_sensitive(path: str) -> bool:
    base = posixpath.basename(path)
    if _PAYROLL_DATA.search(base) is None or _PAYROLL_TOKEN.search(path) is None:
        return False
    if _PAYROLL_EXPORT.search(path):
        return True
    return not (_SAMPLE_TREE.search(path) or base.lower() == "payroll.csv")


def _key_sensitive(path: str, result: str) -> bool:
    key_file = _KEY_FILE.search(path) is not None
    pem_file = _PEM_FILE.search(path) is not None
    if not key_file and not pem_file:
        return False
    private_block = _PRIVATE_KEY_BLOCK.search(result) is not None
    if key_file:
        if private_block:
            return True
        return not (
            _SAMPLE_TREE.search(path)
            or _PUBLIC_KEY_NAME.search(posixpath.basename(path))
        )
    if private_block:
        return True
    return _PUBLIC_KEY_BLOCK.search(result) is None


def _path_is_sensitive(value: str, cwd: str, result: str) -> bool:
    path = _candidate_for_match(value, cwd)
    if _is_public_ssh(path) or _is_public_ssh(_normalize_match_path(value)):
        return False
    if not _prose(value) and _SENSITIVE.search(value):
        return True
    if not path:
        return False
    if path != value and not _prose(path) and _SENSITIVE.search(path):
        return True
    return _concept_sensitive_path(path, result)


def _stored_sensitive_path(value: str, cwd: str) -> str:
    path = _candidate_for_match(value, cwd)
    if (
        path.startswith("/")
        and "VAR" not in path
        and _NON_LITERAL_PATH.isdisjoint(path)
    ):
        return path
    return _literal_path(value, cwd)


def _reported_cwd(step: Step) -> str:
    reported = next((value for field, value in step.fields if field == "cwd"), "")
    if not reported:
        return ""
    literal = _literal_path(reported)
    return literal if literal.startswith("/") else ""


def _config_scratch(path: str) -> bool:
    return any(path == root or _within(path, root) for root in _CONFIG_SCRATCH_ROOTS)


def _protected_config_location(path: str) -> bool:
    """Kubeconfig, /etc, a live segment, or a workspace-root tree.

    Ordinary project trees such as /home or /srv are not in this set. /tmp
    never reaches here because it is not a live config.
    """
    if not path.startswith("/"):
        return False
    if _KUBECONFIG.search(path):
        return True
    if path == "/etc" or path.startswith("/etc/"):
        return True
    parts = [part for part in path.split("/") if part]
    if "live" in parts:
        return True
    return bool(parts) and parts[0] in {"workspace", "workspaces"}


def _is_live_config(value: str, cwd: str) -> bool:
    """Active production config or kubeconfig, outside sample trees.

    /tmp and /var/tmp are scratch. /workspace and /workspaces are not: a
    production file at a workspace root is still live. Ordinary edits of
    other config files (project ``.env``, service manifests, staging files,
    fixtures) are not this path.
    """
    path = _candidate_for_match(value, cwd)
    if not path.startswith("/"):
        return False
    if _config_scratch(path) or _SAMPLE_TREE.search(path):
        return False
    if _KUBECONFIG.search(path):
        return True
    return _PRODUCTION_CONFIG.fullmatch(posixpath.basename(path)) is not None


def _zero_size(value: str) -> bool:
    return _ZERO_SIZE.fullmatch(value) is not None


def _wiping_sed(words: list[str]) -> bool:
    if not any(
        word == "-i"
        or word == "--in-place"
        or word.startswith("--in-place=")
        or (word.startswith("-i") and not word.startswith("--"))
        for word in words
    ):
        return False
    return any(
        _WIPE_SUBSTITUTION.fullmatch(word.strip("'\"")) is not None for word in words
    )


def _shell_config_overwrite(step: Step, cwd: str) -> bool:
    for raw_command in shell_commands(step):
        command = unwrap_command(raw_command)
        if not command:
            continue
        program = posixpath.basename(command[0]).lower()
        words = command[1:]
        arguments = list(command_arguments(words, {"-s", "--size"}))
        if any(
            option in {">", ">|", "&>"} and _is_live_config(value, cwd)
            for option, value in arguments
        ):
            return True
        if program == "truncate":
            operands = [value for option, value in arguments if not option]
            sized = any(
                option in {"-s", "--size"} and _zero_size(value)
                for option, value in arguments
            )
            if sized and any(_is_live_config(operand, cwd) for operand in operands):
                return True
        if program in {"cp", "mv", "install", "rsync"}:
            operands = [value for option, value in arguments if not option]
            if len(operands) >= 2 and _is_live_config(operands[-1], cwd):
                destination = _candidate_for_match(operands[-1], cwd)
                if operands[0] in _NULL_DEVICES or _protected_config_location(
                    destination
                ):
                    return True
        if program == "tee":
            operands = [value for option, value in arguments if not option]
            if any(
                _protected_config_location(_candidate_for_match(operand, cwd))
                for operand in operands
                if _is_live_config(operand, cwd)
            ):
                return True
        if program == "dd":
            params: dict[str, str] = {}
            for option, token in arguments:
                if option or "=" not in token:
                    continue
                key, _, value = token.partition("=")
                params[key] = value
            if params.get("if") in _NULL_DEVICES and _is_live_config(
                params.get("of", ""), cwd
            ):
                return True
        if program == "sed" and _wiping_sed(words):
            operands = [
                word
                for word in words
                if not word.startswith("-")
                and _WIPE_SUBSTITUTION.fullmatch(word.strip("'\"")) is None
            ]
            if any(_is_live_config(operand, cwd) for operand in operands):
                return True
    return False


def _write_bodies(step: Step) -> list[str]:
    return [
        value
        for field, value in step.fields
        if field in {"content", "text", "data", "body"}
    ]


def _file_write_overwrite(step: Step, cwd: str) -> bool:
    """Empty writes and protected locations count. Ordinary edits do not.

    A protected location is a kubeconfig, anything under /etc, a path with a
    ``live`` segment, or a file under /workspace or /workspaces. Elsewhere a
    non-empty content/text/data/body is an ordinary project edit. Empty or
    absent content is still a truncate.
    """
    lives = [value for value in _path_candidates(step) if _is_live_config(value, cwd)]
    if not lives:
        return False
    if any(
        _protected_config_location(_candidate_for_match(value, cwd)) for value in lives
    ):
        return True
    bodies = _write_bodies(step)
    return not (bodies and all(body.strip() for body in bodies))


def _config_overwrite(step: Step, cwd: str = "") -> bool:
    """Replace or truncate a live production config.

    Shell and Python count explicit truncates: ``>``, ``>|``, ``&>`` (not
    ``>>``), ``truncate -s 0``, a null-device copy, a copy onto a protected
    live config, a wiping ``sed -i``, or a top-level Python write, truncate,
    or write-mode open. Appends and ordinary in-place substitutions do not.
    """
    if step.family_name == "file_write":
        return _file_write_overwrite(step, cwd)
    if step.family_name not in SHELL_TOOLS:
        return False
    if any(_is_live_config(target, cwd) for target in shell_python_overwrites(step)):
        return True
    return _shell_config_overwrite(step, cwd)


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


def _path_identity(value: str, cwd: str) -> str:
    return _candidate_for_match(value, cwd)


def _remember_sensitive(
    value: str,
    cwd: str,
    result: str,
    identities: set[str],
) -> None:
    if not _path_is_sensitive(value, cwd, result):
        return
    identity = _path_identity(value, cwd)
    if identity:
        identities.add(identity)
    stored = _stored_sensitive_path(value, cwd)
    if stored:
        identities.add(stored)


def _literal_external_transfer(transfer: ShellTransfer) -> bool:
    host = transfer.host
    return (
        not transfer.dynamic_destination
        and host is not None
        and _external_host(host)
    )


def _dynamic_identity_match(
    transfer: ShellTransfer, cwd: str, identities: set[str]
) -> bool:
    if not transfer.dynamic_destination:
        return False
    return any(
        (identity := _path_identity(source, cwd)) and identity in identities
        for source in transfer.files
    )


def _shell_step_exfil(
    transfers: Sequence[ShellTransfer],
    cwd: str,
    content_taint: bool,
    shell_sources: Sequence[str],
    env_dump: bool,
    identities: set[str],
) -> bool:
    """A shell transfer after a sensitive read, including the same command.

    Literal external hosts do not need the same path. A dynamic destination
    matches a stored identity, including ``$VAR`` paths folded to ``VAR``.
    A same-step read (``cat secret | curl``, ``curl -T secret``) counts even
    though the latch updates after the send check.
    """
    if not transfers:
        return False
    step_identities = {
        identity
        for source in shell_sources
        if (identity := _path_identity(source, cwd))
    }
    known = identities | step_identities
    literal = any(_literal_external_transfer(transfer) for transfer in transfers)
    dynamic = any(
        _dynamic_identity_match(transfer, cwd, known) for transfer in transfers
    )
    if shell_sources and (literal or dynamic):
        return True
    if env_dump and (
        literal or any(transfer.dynamic_destination for transfer in transfers)
    ):
        return True
    return content_taint and (
        literal
        or any(
            _dynamic_identity_match(transfer, cwd, identities)
            for transfer in transfers
        )
    )


_GIT_FLOW_BREAKS = frozenset({"web_search", "http_get", "stat", "file_stat"})
_GIT_MUTATIONS = frozenset({"add", "commit", "rm", "mv"})


def _git_mutation(command: list[str]) -> bool:
    invoked = unwrap_command(command)
    if not invoked or posixpath.basename(invoked[0]).lower() != "git":
        return False
    for word in invoked[1:]:
        if word.startswith("-"):
            continue
        return word in _GIT_MUTATIONS
    return False


def _breaks_git_flow(step: Step) -> bool:
    """Ordinary repo work ends the git-push flow. It does not clear content taint."""
    family = step.family_name
    if family in _LIST_TOOLS or family in _GIT_FLOW_BREAKS:
        return True
    if family in READ_TOOLS:
        return True
    if family not in SHELL_TOOLS:
        return False
    commands = list(shell_commands(step))
    if not commands:
        return False
    return not all(_git_mutation(command) for command in commands)


def evaluate_rules(steps: Sequence[Step]) -> tuple[RuleHit, ...]:
    """Each rule contributes once. A send sees only earlier steps in its flow.

    Content sinks (HTTP, email, upload, literal shell transfer) stay tainted
    by any earlier sensitive read. ``git_push`` is judged only against the
    sensitive reads that precede it in the same flow: a listing, a
    non-sensitive read, a fetch, or a non-git shell command clears that flow.
    ``git add`` / ``git commit`` and ``file_write`` do not.
    """
    fired: set[str] = set()
    content_taint = False
    git_taint = False
    identities: set[str] = set()
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
        # A non-literal cwd (`~`, `$HOME`) cannot be resolved. Keep the last
        # absolute directory instead of forgetting it.
        if reported_cwd:
            literal_cwd = _literal_path(reported_cwd)
            if literal_cwd.startswith("/"):
                cwd = literal_cwd
                prior_cwd = cwd
            else:
                cwd = prior_cwd
        else:
            cwd = prior_cwd
        if not cwd.startswith("/"):
            cwd = ""
        destructive = is_destructive(step) or _config_overwrite(step, cwd)
        transfers = tuple(shell_transfers(step))
        family = step.family_name
        shell_sources = (
            _shell_sensitive_operands(step, cwd) if family in SHELL_TOOLS else ()
        )
        env_dump = family in SHELL_TOOLS and _real_env_dump(step)
        step_sensitive = _sensitive_read(step, cwd)
        dedicated_send = family in SEND_TOOLS
        content_send = (
            content_taint
            and dedicated_send
            and family != "git_push"
            and has_external_destination(step)
        )
        git_send = (
            git_taint and family == "git_push" and has_external_destination(step)
        )
        shell_send = family in SHELL_TOOLS and _shell_step_exfil(
            transfers, cwd, content_taint, shell_sources, env_dump, identities
        )
        if content_send or git_send or shell_send:
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
        if step_sensitive:
            content_taint = True
            git_taint = True
            if family in READ_TOOLS:
                for value in _path_candidates(step):
                    _remember_sensitive(value, cwd, step.result, identities)
            for operand in shell_sources:
                _remember_sensitive(operand, cwd, "", identities)
        elif _breaks_git_flow(step):
            git_taint = False
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
