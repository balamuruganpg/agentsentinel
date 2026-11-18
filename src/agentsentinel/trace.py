"""Defensive normalization of untrusted traces; results never become commands."""

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


def _family_name(tool: str) -> str:
    parts = tool.rsplit(".", 2)
    return _RULE_DOTTED_ALIASES.get(".".join(parts[-2:]), parts[-1])


@dataclass(frozen=True)
class Step:
    """A valid tool name with flattened argument strings (including object keys)."""

    tool: str
    arguments: tuple[str, ...]
    fields: tuple[tuple[str, str], ...] = ()
    result_fields: tuple[tuple[str, str], ...] = ()

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
        tool = tool.strip().lower()
        tool = _CANONICAL_TOOL_NAMES.get(tool, tool)
        result_fields: tuple[tuple[str, str], ...] = ()
        if _family_name(tool) == "db_query":
            _, result_fields = _strings(step.get("result"))
        normalized.append(Step(tool, arguments, fields, result_fields))
    return tuple(normalized)
