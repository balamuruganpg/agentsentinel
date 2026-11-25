"""Defensive normalization of untrusted traces; results never become commands."""

import re
from dataclasses import dataclass

_SHARED_DOTTED_ALIASES = {
    "db.query": "db_query",
    "email.send": "email_send",
    "file.delete": "file_delete",
    "file.read": "file_read",
    "file.write": "file_write",
    "http.post": "http_post",
}

_RULE_DOTTED_ALIASES = {
    **_SHARED_DOTTED_ALIASES,
    "git.push": "git_push",
    "iam.attach": "iam_attach",
    "iam.update": "iam_update",
    "iam.update_role": "iam_update_role",
    "iam.update_policy": "iam_update_policy",
    "permission.grant": "permission_grant",
    "role.assign": "assign_role",
    "role.grant": "role_grant",
}

# Canonicalization matches the full name and feeds both rules and features.
# Bare open_document, webhook_call, and terminal_run stay map-only: clearing
# this dict must stop those exact names from acting as read, send, or shell.
_CANONICAL_TOOL_NAMES = {
    **_SHARED_DOTTED_ALIASES,
    "case_note": "ticket_comment",
    "case_read": "ticket_read",
    "database_lookup": "db_query",
    "list.dir": "list_dir",
    "open_document": "file_read",
    "save_document": "file_write",
    "terminal_run": "shell",
    "web_fetch": "http_get",
    "webhook_call": "http_post",
}

# Families the rules already understand. A legacy family in this set is kept
# so list_files, chmod, and the training tool names do not get rewritten.
_RECOGNIZED_FAMILIES = frozenset(
    {
        "add_role",
        "assign_role",
        "bash",
        "build",
        "cat",
        "chmod",
        "chown",
        "code_exec",
        "create_token",
        "db_query",
        "delete",
        "dir",
        "drop_table",
        "dump_env",
        "email_send",
        "env",
        "env_dump",
        "env_read",
        "environment_dump",
        "exec",
        "exec_command",
        "file_delete",
        "file_list",
        "file_read",
        "file_stat",
        "file_write",
        "format",
        "get_env",
        "git_push",
        "grant_permission",
        "grant_permissions",
        "grant_privilege",
        "grant_role",
        "http_get",
        "http_post",
        "http_request",
        "iam_attach",
        "iam_change_role",
        "iam_policy_update",
        "iam_role_change",
        "iam_role_update",
        "iam_set_policy",
        "iam_set_role",
        "iam_update",
        "iam_update_policy",
        "iam_update_role",
        "lint",
        "list",
        "list_dir",
        "list_directory",
        "list_env",
        "list_files",
        "ls",
        "mint_key",
        "mkfs",
        "open",
        "permission_grant",
        "printenv",
        "read_file",
        "read_text",
        "rm",
        "role_grant",
        "run_command",
        "run_tests",
        "search",
        "set_permission",
        "set_permissions",
        "set_role",
        "sh",
        "shell",
        "stat",
        "su",
        "sudo",
        "ticket_comment",
        "ticket_read",
        "type_check",
        "upload",
        "web_search",
        "webhook",
    }
)
# Evident actions for names the alias map does not list. The three map-only
# names above are intentionally absent.
_EVIDENT_ACTIONS = {
    "bash_command": "shell",
    "execute_command": "shell",
    "fetch": "http_post",
    "file_upload": "upload",
    "http_post_json": "http_post",
    "http_put": "http_post",
    "open_file": "file_read",
    "powershell": "shell",
    "read_files": "file_read",
    "readfile": "file_read",
    "run_terminal_cmd": "shell",
    "send_email": "email_send",
    "shell_exec": "shell",
    "terminal": "shell",
    "webhook_callback": "http_post",
}
_IO_PREFIXES = frozenset({"file", "filesystem", "fs"})
_IO_ACTIONS = {"delete": "file_delete", "read": "file_read", "write": "file_write"}
_VERSION_SEGMENT = re.compile(r"v\d+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _legacy_family(tool: str) -> str:
    parts = tool.rsplit(".", 2)
    return _RULE_DOTTED_ALIASES.get(".".join(parts[-2:]), parts[-1])


def _mapped_action(name: str) -> str:
    if name in _RULE_DOTTED_ALIASES:
        return _RULE_DOTTED_ALIASES[name]
    if name in _CANONICAL_TOOL_NAMES:
        return _CANONICAL_TOOL_NAMES[name]
    return _EVIDENT_ACTIONS.get(name, "")


def _structural_parts(tool: str) -> list[str]:
    folded = tool.replace("__", ".").replace("-", "_")
    parts = [part for part in folded.split(".") if part]
    if len(parts) >= 2 and _VERSION_SEGMENT.fullmatch(parts[-1]):
        parts = parts[:-1]
    return parts


def _family_name(tool: str) -> str:
    """Rule family for a tool name, without rewriting the stored tool string."""
    legacy = _legacy_family(tool)
    if legacy in _RECOGNIZED_FAMILIES:
        return legacy
    parts = _structural_parts(tool)
    if not parts:
        return legacy
    if len(parts) >= 2:
        mapped = _mapped_action(f"{parts[-2]}.{parts[-1]}")
        if mapped:
            return mapped
        if parts[-1] in _IO_ACTIONS and parts[-2] in _IO_PREFIXES:
            return _IO_ACTIONS[parts[-1]]
        if parts[-1] in {"post", "put"}:
            return "http_post"
    mapped = _mapped_action(parts[-1])
    if mapped:
        return mapped
    if parts[-1] in _RECOGNIZED_FAMILIES:
        return parts[-1]
    return legacy


def _camel_to_snake(tool: str) -> str:
    """Insert underscores at camelCase boundaries. Snake and dotted names stay."""
    return _CAMEL_BOUNDARY.sub("_", tool)


@dataclass(frozen=True)
class Step:
    """A valid tool name with flattened argument strings (including object keys)."""

    tool: str
    arguments: tuple[str, ...]
    fields: tuple[tuple[str, str], ...] = ()
    result_fields: tuple[tuple[str, str], ...] = ()
    # Read results corroborate path evidence. They are not argument text, so a
    # secret mentioned in a file body cannot become a path match by itself.
    result: str = ""

    @property
    def text(self) -> str:
        return " ".join(self.arguments)

    @property
    def family_name(self) -> str:
        """Allow namespaced tools, such as filesystem.read_file."""
        return _family_name(self.tool)


def _strings(
    value: object,
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    # Iteration and identity tracking also tolerate cyclic non-JSON Python inputs.
    pending: list[tuple[str, object]] = [("", value)]
    seen: set[int] = set()
    strings: list[str] = []
    fields: list[tuple[str, str]] = []
    while pending:
        field, item = pending.pop()
        if isinstance(item, str):
            strings.append(item)
            fields.append((field.lower(), item))
        elif isinstance(item, (dict, list)):
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, dict):
                for key, child in item.items():
                    if isinstance(key, str):
                        strings.append(key)
                    pending.append((key if isinstance(key, str) else field, child))
            else:
                pending.extend((field, child) for child in item)
    return tuple(strings), tuple(fields)


def normalize_trace(trace: dict[str, object]) -> tuple[Step, ...]:
    """Build fresh steps with canonical tool names for rules and features."""
    steps = trace.get("steps")
    if not isinstance(steps, list):
        return ()
    normalized: list[Step] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        tool = step.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            continue
        args = step.get("args", {})
        if not isinstance(args, dict):
            continue
        arguments, fields = _strings(args)
        tool = _camel_to_snake(tool.strip()).lower()
        tool = _CANONICAL_TOOL_NAMES.get(tool, tool)
        raw_result = step.get("result")
        result_text = raw_result if isinstance(raw_result, str) else ""
        result_fields: tuple[tuple[str, str], ...] = ()
        if _family_name(tool) == "db_query":
            _, result_fields = _strings(raw_result)
        normalized.append(Step(tool, arguments, fields, result_fields, result_text))
    return tuple(normalized)
